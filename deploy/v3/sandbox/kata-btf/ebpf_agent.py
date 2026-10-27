#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""B1: минимальный in-guest eBPF-агент для наблюдения за инференсом (Kata + BTF-ядро).

Пишет реальные события из гостевой ВМ (без внешних зависимостей: только stdlib + ctypes):
  * хук 1 — raw tracepoint `sys_enter`, syscall `execve`  → событие process_exec (бинарник/путь);
  * хук 2 — raw tracepoint `sys_enter`, syscall `connect` → событие network (dst IP:port);
  * хук 3 — raw tracepoint `sys_enter`, syscall `openat`  → событие file (путь).

События складываются в JSONL-файл (`--out`, общий том пода) и/или отправляются в сервис
тестирования (`--post URL --key KEY --scan-id ID --nonce N`) на `/llm/events`, где маппятся
в findings `LLM-B-*` (deploy/v3/llm/tetragon.py).

Ограничения: x86_64-гость, чтение user-памяти ограничено 64 байтами, счётчики в ARRAY-мапе
(без ring-buffer) — этого достаточно для детекции факта и первого значения.

Запуск:
  python3 ebpf_agent.py --out /events/ebpf.jsonl --duration 30 \
      --post http://mlscan-testing.mlscan-testing.svc:8080 --key <api-key> --scan-id s1 --nonce abc
"""
from __future__ import annotations

import argparse
import ctypes as C
import json
import os
import struct
import subprocess
import sys
import time

# --- BPF syscall/типы -------------------------------------------------------
SYS_BPF = 321
BPF_MAP_CREATE = 0
BPF_MAP_LOOKUP_ELEM = 1
BPF_PROG_LOAD = 5
BPF_RAW_TRACEPOINT_OPEN = 17

BPF_MAP_TYPE_ARRAY = 2
BPF_PROG_TYPE_RAW_TRACEPOINT = 17

LOG_SIZE = 1 << 16
DUMP_NR = int(os.environ.get("EBPF_DUMP_NR", "-1"))
EXTRA = os.environ.get("EBPF_EXTRA", "1") == "1"   # хуки mmap/mprotect/module/openat (LLM-B-03/04/05)
# honeypot-подсказки — те же, что в правиле LLM-B-03 (deploy/v3/llm/tetragon.py); прочие openat не шлём
HONEYPOT_HINTS = ("/.aws/", "/.ssh/", "/.kube/", "/etc/shadow", "/etc/passwd")
# начала honeypot-путей для BPF-фильтра (сравнение первых 8 байт, выровнено по началу пути)
HONEYPOT_PREFIX_8 = (b"/etc/sha", b"/etc/pas", b"/root/.a", b"/home/.a", b"/root/.s", b"/root/.k")
if os.environ.get("EBPF_TEST_PREFIX") == "1":      # отладочный набор (проверка механизма фильтра)
    HONEYPOT_PREFIX_8 = (b"/proc/ne", b"/etc/sha")
# BPF-фильтр honeypot по префиксу (сравнение первых 8 байт пути) — включён по умолчанию:
# в кольцо попадают только значимые пути, шум файловой активности его не вымывает.
# EBPF_HONEYPOT_FILTER=0 — отключить (тогда в кольцо пишутся все пути, фильтр работает в агенте).
HONEYPOT_FILTER = os.environ.get("EBPF_HONEYPOT_FILTER", "1") == "1"
KEY_SIZE = 4
VALUE_SIZE = 96                      # {u64 count; u32 pid; u32 pad; u64 argptr; u64 rv; u8 buf[64]}

# Кодировки инструкций eBPF (см. include/uapi/linux/bpf.h)
OP = {
    "ld_map_fd": 0x18, "ld_imm64": 0x18, "ldx_dw": 0x79, "ldx_w": 0x61, "stx_w": 0x63,
    "stx_dw": 0x7B, "st_dw": 0x7A, "add_imm": 0x07, "mov_reg": 0xBF, "mov_imm": 0xB7,
    "jeq_imm": 0x15, "jne_imm": 0x55, "jgt_imm": 0x25, "call": 0x85, "exit": 0x95,
    "jsl_imm": 0xC5,   # BPF_JMP | BPF_JSLT | BPF_K
    "and_imm": 0x57,   # BPF_ALU64 | BPF_AND | BPF_K
    "jle_imm": 0xB5,   # BPF_JMP | BPF_JLE | BPF_K
    "jeq_reg": 0x1D,   # BPF_JMP | BPF_JEQ | BPF_X
    "ja": 0x05,        # BPF_JMP | BPF_JA
}
# Номера syscall (x86_64)
NR_EXECVE, NR_CONNECT, NR_OPENAT = 59, 42, 257
NR_MMAP, NR_MPROTECT = 9, 10
NR_INIT_MODULE, NR_FINIT_MODULE = 175, 313
# слоты ARRAY-карты: 0=execve, 1=connect, 2=mmap, 3=mprotect, 4=init_module, 5=finit_module
SLOT = {NR_EXECVE: 0, NR_CONNECT: 1, NR_MMAP: 2, NR_MPROTECT: 3, NR_INIT_MODULE: 4,
        NR_FINIT_MODULE: 5, NR_OPENAT: 6}
# offsets в struct pt_regs (x86_64): r15..r8, ax, cx, dx, si, di, orig_ax
#   index: 0..9 (r15..r8), 10=ax(80), 11=cx(88), 12=dx(96), 13=si(104), 14=di(112), 15=orig_ax(120)
OFF_ARG0, OFF_ARG1, OFF_ORIG_AX = 112, 104, 120
# args: 0=di(112), 1=si(104), 2=dx(96), 3=r10(56), 4=r8(72), 5=r9(64)
OFF_ARG_MMAP_PROT = 96        # mmap(addr, len, prot, flags, ...) -> prot = arg2 (dx)
OFF_ARG_MPROTECT_PROT = 96    # mprotect(addr, len, prot)      -> prot = arg2 (dx)


class MapCreate(C.Structure):
    _fields_ = [("map_type", C.c_uint32), ("key_size", C.c_uint32), ("value_size", C.c_uint32),
                ("max_entries", C.c_uint32), ("map_flags", C.c_uint32), ("inner_map_fd", C.c_uint32),
                ("numa_node", C.c_uint32), ("map_name", C.c_char * 16), ("map_ifindex", C.c_uint32),
                ("btf_fd", C.c_uint32), ("btf_key_type_id", C.c_uint32),
                ("btf_value_type_id", C.c_uint32), ("btf_vmlinux_value_type_id", C.c_uint32)]


class MapElem(C.Structure):
    _fields_ = [("map_fd", C.c_uint32), ("pad", C.c_uint32), ("key", C.c_uint64),
                ("value", C.c_uint64), ("flags", C.c_uint64)]


class ProgLoad(C.Structure):
    _fields_ = [("prog_type", C.c_uint32), ("insn_cnt", C.c_uint32), ("insns", C.c_uint64),
                ("license", C.c_uint64), ("log_level", C.c_uint32), ("log_size", C.c_uint32),
                ("log_buf", C.c_uint64), ("kern_version", C.c_uint32), ("prog_flags", C.c_uint32),
                ("prog_name", C.c_char * 16), ("prog_ifindex", C.c_uint32),
                ("expected_attach_type", C.c_uint32)]


class RawTpOpen(C.Structure):
    _fields_ = [("name", C.c_uint64), ("prog_fd", C.c_uint32), ("cookie", C.c_uint64)]


def _bpf(attr, cmd: int) -> tuple[int, int]:
    libc = C.CDLL(None, use_errno=True)
    ret = libc.syscall(SYS_BPF, cmd, C.byref(attr), C.sizeof(attr))
    return ret, C.get_errno()


class Asm:
    """Минимальный ассемблер: список 8-байтовых инструкций eBPF."""

    def __init__(self):
        self.ins: list[bytes] = []
        self._labels: dict = {}
        self._pending: list = []

    def _i(self, code, dst=0, src=0, off=0, imm=0):
        self.ins.append(struct.pack("<BBhI", code, ((src & 0xF) << 4) | (dst & 0xF),
                                    off, imm & 0xFFFFFFFF))

    def ld_map(self, dst, fd):
        self._i(OP["ld_map_fd"], dst=dst, src=1, imm=fd)   # BPF_PSEUDO_MAP_FD
        self._i(0, imm=0)

    def ldx_dw(self, dst, src, off):
        self._i(OP["ldx_dw"], dst=dst, src=src, off=off)

    def ldx_w(self, dst, src, off):
        self._i(OP["ldx_w"], dst=dst, src=src, off=off)

    def stx_dw(self, dst, src, off):
        self._i(OP["stx_dw"], dst=dst, src=src, off=off)

    def stx_w(self, dst, src, off):
        self._i(OP["stx_w"], dst=dst, src=src, off=off)

    def mov_reg(self, dst, src):
        self._i(OP["mov_reg"], dst=dst, src=src)

    def mov_imm(self, dst, imm):
        self._i(OP["mov_imm"], dst=dst, imm=imm)

    def add_imm(self, dst, imm):
        self._i(OP["add_imm"], dst=dst, imm=imm)

    def jne_imm(self, dst, imm, off):
        self._i(OP["jne_imm"], dst=dst, imm=imm, off=off)

    def jeq_imm(self, dst, imm, off):
        self._i(OP["jeq_imm"], dst=dst, imm=imm, off=off)

    def jgt_imm(self, dst, imm, off):
        self._i(OP["jgt_imm"], dst=dst, imm=imm, off=off)

    def jle_imm(self, dst, imm, off):
        self._i(OP["jle_imm"], dst=dst, imm=imm, off=off)

    def jsl_imm(self, dst, imm, off):
        self._i(OP["jsl_imm"], dst=dst, imm=imm, off=off)

    def and_imm(self, dst, imm):
        self._i(OP["and_imm"], dst=dst, imm=imm)

    def ld_imm64(self, dst, value):
        self._i(OP["ld_imm64"], dst=dst, imm=value & 0xFFFFFFFF)   # src=0 -> обычная 64-битная константа
        self._i(0, imm=(value >> 32) & 0xFFFFFFFF)

    def jeq_reg(self, dst, src, off):
        self._i(OP["jeq_reg"], dst=dst, src=src, off=off)

    def ja(self, off):
        self._i(OP["ja"], off=off)

    def call(self, helper):
        self._i(OP["call"], imm=helper)

    def exit(self):
        self._i(OP["exit"])

    def label(self, name: str) -> None:
        """Поставить метку (для переходов вперёд)."""
        self._labels[name] = len(self.ins)

    def jmp(self, code: int, label: str, dst: int = 0, src: int = 0, imm: int = 0) -> None:
        """Инструкция перехода на метку (смещение проставится в resolve())."""
        self._pending.append((len(self.ins), code, dst, src, imm, label))
        self._i(code, dst=dst, src=src, off=0, imm=imm)

    def resolve(self) -> None:
        """Проставить смещения для всех переходов по меткам."""
        for idx, code, dst, src, imm, label in self._pending:
            if label not in self._labels:
                raise RuntimeError(f"нет метки {label!r}")
            off = self._labels[label] - idx - 1
            self.ins[idx] = struct.pack("<BBhI", code, ((src & 0xF) << 4) | (dst & 0xF),
                                        off, imm & 0xFFFFFFFF)
        self._pending = []

    def bytes(self) -> bytes:
        return b"".join(self.ins)


def build_hook(nr: int, arg_off: int, map_fd: int, need_mask: int = 0, read_str: bool = False) -> bytes:
    """Программа raw-tracepoint: если syscall == nr — читает строку аргумента и пишет в map[nr%2]."""
    a = Asm()
    a.ldx_dw(6, 1, 0)            # r6 = ctx->args[0] = pt_regs* (для verifier — scalar)
    # номер syscall читаем из pt_regs через bpf_probe_read_kernel (прямое разыменование запрещено)
    a.mov_reg(1, 10)
    a.add_imm(1, -72)
    a.mov_imm(2, 8)
    a.mov_reg(3, 6)
    a.add_imm(3, OFF_ORIG_AX)
    a.call(113)                  # bpf_probe_read_kernel
    a.ldx_dw(7, 10, -72)         # r7 = номер syscall
    jump = len(a.ins)
    a.jne_imm(7, nr, 0)          # если не наш syscall — на выход (off пропатчим)
    # аргумент (filename / sockaddr) — user-указатель из pt_regs; строку читаем probe_read_user
    skip_neg = None
    # ЗНАЧЕНИЕ аргумента (prot/flags/fd): читаем 8 байт из pt_regs+arg_off через probe_read_kernel
    a.mov_reg(1, 10)
    a.add_imm(1, -88)
    a.mov_imm(2, 8)
    a.mov_reg(3, 6)
    a.add_imm(3, arg_off)
    a.call(113)                  # r10-88 = *(u64 *)(pt_regs + arg_off)
    if need_mask:
        a.ldx_dw(1, 10, -88)
        a.and_imm(1, need_mask & 0xFFFFFFFF)
        need_jump = len(a.ins)
        a.jne_imm(1, need_mask & 0xFFFFFFFF, 0)   # не наш случай (напр. не RWX) -> на выход
    # ВАЖНО: bpf_probe_read_user в этом госте стабильно даёт EFAULT (user-память недоступна
    # хелперу), поэтому атрибуцию процесса берём из ядра: bpf_get_current_comm (helper 35).
    # Сырой аргумент (r3) сохраняем для диагностики; окно pt_regs можно дампить (DUMP_NR).
    if nr == DUMP_NR:
        a.mov_reg(1, 10)
        a.add_imm(1, -64)
        a.mov_imm(2, 64)
        a.mov_reg(3, 6)
        a.add_imm(3, 80)
        a.call(113)              # bpf_probe_read_kernel: pt_regs[80..144]
        a.mov_reg(9, 0)
    elif read_str:
        # openat: путь = user-строка по указателю из аргумента (читаем probe_read_user_str, helper 45)
        a.ldx_dw(3, 10, -88)     # r3 = значение аргумента (указатель на путь)
        a.mov_reg(1, 10)
        a.add_imm(1, -64)
        a.mov_imm(2, 64)
        a.call(45)               # bpf_probe_read_user_str(dst, size, ptr)
        a.mov_reg(9, 0)
    else:
        a.mov_reg(1, 10)
        a.add_imm(1, -64)
        a.mov_imm(2, 16)
        a.call(16)               # bpf_get_current_comm(dst, 16) — helper 16
        a.mov_reg(9, 0)
        skip_neg = len(a.ins)
        a.jsl_imm(9, 0, 0)       # ошибка чтения -> не пишем событие
    # ключ (0 для execve/openat, 1 для connect) в r10-68
    a.mov_reg(1, 10)
    a.add_imm(1, -68)
    a.mov_imm(2, SLOT.get(nr, 0))
    a.stx_w(1, 2, 0)
    # lookup(map, &key)
    a.ld_map(1, map_fd)
    a.mov_reg(2, 10)
    a.add_imm(2, -68)
    a.call(1)                  # bpf_map_lookup_elem
    jeq0 = len(a.ins)
    a.jeq_imm(0, 0, 0)         # если r0 == 0 — на выход (off пропатчим)
    a.mov_reg(8, 0)            # r8 = указатель на значение (сохраняем)
    a.ldx_dw(1, 8, 0)
    a.add_imm(1, 1)
    a.stx_dw(8, 1, 0)          # value->count++
    a.call(14)                 # bpf_get_current_pid_tgid
    a.stx_w(8, 0, 8)           # value->pid = низкие 32 бита
    a.ldx_dw(1, 10, -88)
    a.stx_dw(8, 1, 16)         # value->argptr = ЗНАЧЕНИЕ аргумента
    a.stx_dw(8, 9, 24)         # value->rv
    for i in range(8):         # копируем буфер со стека в value->buf (comm занимает первые 16)
        a.ldx_dw(1, 10, -64 + i * 8)
        a.stx_dw(8, 1, 32 + i * 8)
    # общий выход: обе ветки прыгают на exit (позиция pos_exit)
    pos_exit = len(a.ins)
    a.mov_imm(0, 0)
    a.exit()
    if need_mask:
        a.ins[need_jump] = struct.pack("<BBhI", OP["jne_imm"], 1, pos_exit - need_jump - 1,
                                       need_mask & 0xFFFFFFFF)
    a.ins[jump] = struct.pack("<BBhI", OP["jne_imm"], 7, pos_exit - jump - 1, nr)
    a.ins[jeq0] = struct.pack("<BBhI", OP["jeq_imm"], 0, pos_exit - jeq0 - 1, 0)
    if skip_neg is not None:
        a.ins[skip_neg] = struct.pack("<BBhI", OP["jsl_imm"], 9, pos_exit - skip_neg - 1, 0)
    return a.bytes()


def load_hook(nr: int, arg_off: int, map_fd: int, need_mask: int = 0, read_str: bool = False) -> int:
    prog = build_hook(nr, arg_off, map_fd, need_mask, read_str)
    buf = C.create_string_buffer(prog)
    lic = C.create_string_buffer(b"GPL")
    log = C.create_string_buffer(LOG_SIZE)
    attr = ProgLoad(prog_type=BPF_PROG_TYPE_RAW_TRACEPOINT, insn_cnt=len(prog) // 8,
                    insns=C.addressof(buf), license=C.addressof(lic), log_level=1, log_size=LOG_SIZE,
                    log_buf=C.addressof(log))
    fd, err = _bpf(attr, BPF_PROG_LOAD)
    if fd < 0:
        raise RuntimeError(f"BPF_PROG_LOAD syscall {nr}: errno={err} ...{log.value.decode()[-700:]}")
    if nr == NR_EXECVE:
        subprocess.run(["/bin/true"], check=False)          # прогрев
    name = C.create_string_buffer(b"sys_enter")
    attr2 = RawTpOpen(name=C.addressof(name), prog_fd=fd)
    tp, err2 = _bpf(attr2, BPF_RAW_TRACEPOINT_OPEN)
    if tp < 0:
        raise RuntimeError(f"attach sys_enter (syscall {nr}): errno={err2}")
    return tp


RING_SLOTS = 15      # число слотов путей; слот RING_SLOTS — курсор кольца
CURSOR_KEY = RING_SLOTS


def create_paths_map() -> int:
    """Карта путей openat: RING_SLOTS слотов (56 байт пути) + слот-курсор (кольцо)."""
    attr = MapCreate(map_type=BPF_MAP_TYPE_ARRAY, key_size=KEY_SIZE, value_size=72,
                     max_entries=RING_SLOTS + 1)
    fd, err = _bpf(attr, BPF_MAP_CREATE)
    if fd < 0:
        raise RuntimeError(f"BPF_MAP_CREATE(paths): errno={err}")
    return fd


def _load_and_attach(prog: bytes, label: str) -> int:
    """Загрузить программу и привязать к raw-tracepoint sys_enter. Возвращает fd линка."""
    buf = C.create_string_buffer(prog)
    lic = C.create_string_buffer(b"GPL")
    log = C.create_string_buffer(LOG_SIZE)
    attr = ProgLoad(prog_type=BPF_PROG_TYPE_RAW_TRACEPOINT, insn_cnt=len(prog) // 8,
                    insns=C.addressof(buf), license=C.addressof(lic), log_level=1, log_size=LOG_SIZE,
                    log_buf=C.addressof(log))
    fd, err = _bpf(attr, BPF_PROG_LOAD)
    if fd < 0:
        raise RuntimeError(f"BPF_PROG_LOAD {label}: errno={err} ...{log.value.decode()[-700:]}")
    name = C.create_string_buffer(b"sys_enter")
    attr2 = RawTpOpen(name=C.addressof(name), prog_fd=fd)
    tp, err2 = _bpf(attr2, BPF_RAW_TRACEPOINT_OPEN)
    if tp < 0:
        raise RuntimeError(f"attach sys_enter ({label}): errno={err2}")
    return tp


def create_map() -> int:
    """Основная карта событий (по слоту на syscall)."""
    attr = MapCreate(map_type=BPF_MAP_TYPE_ARRAY, key_size=KEY_SIZE, value_size=VALUE_SIZE,
                     max_entries=8)
    fd, err = _bpf(attr, BPF_MAP_CREATE)
    if fd < 0:
        raise RuntimeError(f"BPF_MAP_CREATE: errno={err}")
    return fd


def load_openat_hook(paths_fd: int, skip_pid: int = 0) -> int:
    """Хук openat: путь (user-read) кладётся в кольцо из 7 слотов -> honeypot не теряется.

    Слот 7 карты хранит курсор кольца (0..6); переполнение — перезапись по кругу.
    """
    a = Asm()
    a.ldx_dw(6, 1, 0)                                     # r6 = pt_regs
    a.mov_reg(1, 10); a.add_imm(1, -72); a.mov_imm(2, 8)
    a.mov_reg(3, 6); a.add_imm(3, OFF_ORIG_AX)
    a.call(113)
    a.ldx_dw(7, 10, -72)
    j_nr = len(a.ins); a.jne_imm(7, NR_OPENAT, 0)          # не openat -> выход
    a.mov_reg(1, 10); a.add_imm(1, -80); a.mov_imm(2, 8)   # значение si (указатель на путь)
    a.mov_reg(3, 6); a.add_imm(3, OFF_ARG1)
    a.call(113)
    a.ldx_dw(3, 10, -80)
    a.mov_reg(1, 10); a.add_imm(1, -64); a.mov_imm(2, 64)
    a.call(45)                                             # bpf_probe_read_user_str -> r10-64
    if skip_pid:                                           # не пишем открытия самого агента (шум)
        a.call(14)                                          # r0 = pid_tgid
        a.mov_reg(1, 0); a.and_imm(1, 0xFFFFFFFF)           # низкие 32 бита = pid
        j_self = len(a.ins); a.jeq_imm(1, skip_pid & 0xFFFFFFFF, 0)   # наш pid -> выход
    if skip_pid:                                           # не пишем открытия самого агента (шум)
        a.call(14)                                          # r0 = pid_tgid
        a.mov_reg(1, 0); a.and_imm(1, 0xFFFFFFFF)           # низкие 32 бита = pid
        a.jmp(OP["jeq_imm"], "exit", dst=1, imm=skip_pid & 0xFFFFFFFF)   # наш pid -> выход
    # BPF-фильтр honeypot: в кольцо попадают ТОЛЬКО значимые пути (иначе шум вымывает кольцо)
    if HONEYPOT_FILTER and HONEYPOT_PREFIX_8:
        a.ldx_dw(1, 10, -64)                               # r1 = первые 8 байт пути
        for lit in HONEYPOT_PREFIX_8:
            v = int.from_bytes(lit.ljust(8, b"\x00")[:8], "little")
            a.ld_imm64(2, v)
            a.jmp(OP["jeq_reg"], "body", dst=1, src=2)      # совпало -> в тело кольца
        a.jmp(OP["ja"], "exit")                             # иначе -> выход
    a.label("body")                                        # начало тела кольца
    body_pos = len(a.ins)
    a.mov_reg(1, 10); a.add_imm(1, -84); a.mov_imm(2, CURSOR_KEY); a.stx_w(1, 2, 0)
    a.ld_map(1, paths_fd); a.mov_reg(2, 10); a.add_imm(2, -84)
    a.call(1)
    j_c0 = len(a.ins); a.jeq_imm(0, 0, 0)
    a.mov_reg(8, 0)
    a.ldx_dw(9, 8, 0)                                      # r9 = курсор
    a.jle_imm(9, RING_SLOTS - 1, 1)                        # курсор <= MAX -> оставляем
    a.mov_imm(9, 0)                                        # курсор > MAX -> сброс в 0
    a.mov_reg(2, 9); a.add_imm(2, 1); a.stx_dw(8, 2, 0)    # сохраняем следующий индекс
    a.mov_reg(1, 10); a.add_imm(1, -84); a.stx_w(1, 9, 0)  # key = текущий индекс
    a.ld_map(1, paths_fd); a.mov_reg(2, 10); a.add_imm(2, -84)
    a.call(1)
    j_c1 = len(a.ins); a.jeq_imm(0, 0, 0)
    a.mov_reg(8, 0)
    a.call(14)                                             # pid
    a.stx_w(8, 0, 8)
    for i in range(7):                                     # 56 байт пути -> value+16
        a.ldx_dw(1, 10, -64 + i * 8)
        a.stx_dw(8, 1, 16 + i * 8)
    a.label("exit")
    pos_exit = len(a.ins)
    a.mov_imm(0, 0); a.exit()
    a.resolve()
    a.ins[j_nr] = struct.pack("<BBhI", OP["jne_imm"], 7, pos_exit - j_nr - 1, NR_OPENAT)
    a.ins[j_c0] = struct.pack("<BBhI", OP["jeq_imm"], 0, pos_exit - j_c0 - 1, 0)
    a.ins[j_c1] = struct.pack("<BBhI", OP["jeq_imm"], 0, pos_exit - j_c1 - 1, 0)
    return _load_and_attach(a.bytes(), f"openat({NR_OPENAT})")


def read_path_entry(paths_fd: int, idx: int) -> str:
    """Путь из кольца (слот idx): pid@8, путь@16..72."""
    key = C.c_uint32(idx)
    val = C.create_string_buffer(72)
    attr = MapElem(map_fd=paths_fd, key=C.addressof(key), value=C.addressof(val))
    ret, _err = _bpf(attr, BPF_MAP_LOOKUP_ELEM)
    if ret != 0:
        return ""
    return val.raw[16:72].split(b"\x00", 1)[0].decode("utf-8", "replace")


def read_map(map_fd: int, idx: int) -> dict:
    key = C.c_uint32(idx)
    val = C.create_string_buffer(VALUE_SIZE)
    attr = MapElem(map_fd=map_fd, key=C.addressof(key), value=C.addressof(val))
    ret, err = _bpf(attr, BPF_MAP_LOOKUP_ELEM)
    if ret != 0:
        return {}
    raw = val.raw
    count = struct.unpack_from("<Q", raw, 0)[0]
    pid = struct.unpack_from("<I", raw, 8)[0]
    argptr = struct.unpack_from("<Q", raw, 16)[0]
    rv = struct.unpack_from("<q", raw, 24)[0]
    buf_raw = raw[32:96]
    buf = buf_raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
    return {"count": count, "pid": pid, "argptr": argptr, "rv": rv,
            "buf": buf, "buf_hex": buf_raw.hex()}


def ips_from_sockaddr(raw: bytes) -> str:
    """IPv4 из 16 байт sockaddr_in (buf[4:8] — адрес), иначе IPv6/неизвестно."""
    if len(raw) >= 8:
        return ".".join(str(b) for b in raw[4:8])
    return ""



def _hex_ip4(h: str) -> str:
    """IPv4 из /proc/net/tcp (hex, little-endian по байтам)."""
    try:
        b = bytes.fromhex(h)
        return ".".join(str(x) for x in reversed(b))
    except Exception:  # noqa: BLE001
        return ""


def _hex_ip6(h: str) -> str:
    """IPv6 из /proc/net/tcp6 (4 little-endian 32-битных слова)."""
    try:
        words = [bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8)]
        raw = b"".join(words)
        parts = [raw[i:i + 2].hex() for i in range(0, 16, 2)]
        return ":".join(parts)
    except Exception:  # noqa: BLE001
        return ""


def external_peers() -> list:
    """Не-loopback адреса активных соединений пода (netns общий для контейнеров).

    Адрес берём из kernel-состояния (/proc/net/tcp{,6}), сам факт connect() — из eBPF.
    (Прямое чтение sockaddr из user-памяти в этом госте даёт EFAULT; см. README.)
    """
    out = []
    for path, conv, loop in (("/proc/net/tcp", _hex_ip4, "127."), ("/proc/net/tcp6", _hex_ip6, "::1")):
        try:
            with open(path) as fh:
                next(fh, None)
                for line in fh:
                    f = line.split()
                    if len(f) < 4:
                        continue
                    rem = f[2]
                    if ":" not in rem:
                        continue
                    iph, _, ph = rem.partition(":")
                    ip = conv(iph)
                    if not ip or ip.startswith(loop) or ip.startswith("0.0.0.0") or ip.startswith("::"):
                        continue
                    try:
                        port = int(ph, 16)
                    except ValueError:
                        port = 0
                    out.append({"ip": ip, "port": port})
        except Exception:  # noqa: BLE001
            continue
    uniq, seen = [], set()
    for p_ in out:
        k = (p_["ip"], p_["port"])
        if k not in seen:
            seen.add(k); uniq.append(p_)
    return uniq


def _post_events(args, batch: list) -> None:
    """Отправить пакет событий в /llm/events (инкрементально, чтобы findings появились сразу)."""
    if not batch:
        return
    import urllib.request
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    body = json.dumps({"scan_id": args.scan_id, "nonce": args.nonce, "events": batch}).encode()
    req = urllib.request.Request(args.post.rstrip("/") + "/llm/events", data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + args.key})
    try:
        with op.open(req, timeout=30) as r:
            print(f"[ebpf-agent] отправлено событий: {len(batch)}", flush=True)
            print("[ebpf-agent] /llm/events:", r.status, r.read().decode()[:200], flush=True)
    except Exception as exc:  # noqa: BLE001
        print("[ebpf-agent] /llm/events ошибка:", type(exc).__name__, exc, flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="")
    ap.add_argument("--duration", type=float, default=20.0)
    ap.add_argument("--post", default="")
    ap.add_argument("--key", default="")
    ap.add_argument("--scan-id", default="")
    ap.add_argument("--nonce", default="")
    ap.add_argument("--phase", default="probe")
    ap.add_argument("--stop-file", default="", help="выйти, когда появится файл (скан завершён)")
    ap.add_argument("--trigger-shell", action="store_true",
                    help="самопроверка: выполнить 'sh -c true' (execve shell внутри гостя)")
    args = ap.parse_args()

    try:                                    # BPF-память учитывается в memlock в госте Kata
        import resource
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    except Exception:  # noqa: BLE001
        pass
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        print("[ebpf-agent] нет /sys/kernel/btf/vmlinux — нужен BTF-гость (kata-btf)", file=sys.stderr)
        return 1

    m = create_map()
    mp = create_paths_map() if EXTRA else 0
    load_hook(NR_EXECVE, OFF_ARG0, m)        # слот 0 -> process_exec (бинарник из comm)
    load_hook(NR_CONNECT, OFF_ARG1, m)       # слот 1 -> network (адрес из /proc/net/tcp)
    if EXTRA:                                # LLM-B-04 (exec-память) и LLM-B-05 (загрузка модуля)
        load_hook(NR_MMAP, OFF_ARG_MMAP_PROT, m, need_mask=0x6)      # RWX (WRITE|EXEC)
        load_hook(NR_MPROTECT, OFF_ARG_MPROTECT_PROT, m, need_mask=0x4)  # EXEC
        load_hook(NR_INIT_MODULE, OFF_ARG0, m)          # слот 4 -> module
        load_hook(NR_FINIT_MODULE, OFF_ARG1, m)         # слот 5 -> module
        load_openat_hook(mp, skip_pid=os.getpid())      # пути openat -> кольцо (LLM-B-03)
    print(f"[ebpf-agent] bpf активен (BTF {os.path.getsize('/sys/kernel/btf/vmlinux')} байт), "
          f"хуки: execve+connect (2 слота карты)", flush=True)

    if args.trigger_shell:      # самопроверка сенсора (в проде это делает сам движок/агент модели)
        subprocess.run(["/bin/sh", "-c", "true"], check=False)
    PROT_EXEC = 0x4
    net_deadline = 0.0                     # окно повторных чтений /proc после connect (LLM-B-02)
    events: list[dict] = []
    pending: list[dict] = []
    t_end = time.time() + max(args.duration, 5)
    last_post = 0.0
    seen = set()
    def drain() -> None:
        """Считать карту и добавить новые события (вызывается в цикле и один раз после него)."""
        nonlocal net_deadline
        ex, cn = read_map(m, 0), read_map(m, 1)
        if DUMP_NR >= 0 and ex.get("count"):
            print("[ebpf-agent] pt_regs[80..144] hex (слот %d):" % SLOT.get(DUMP_NR, 0),
                  (read_map(m, SLOT.get(DUMP_NR, 0)).get("buf_hex") or ""), flush=True)
        if ex.get("count"):
            path = ex["buf"] or "?"
            key = ("process_exec", path)
            if key not in seen:
                seen.add(key)
                ev = {"type": "process_exec", "phase": args.phase, "probe_id": "ebpf-agent",
                      "process": {"binary": path.strip(), "exe": path.strip(),
                                  "args": [], "pid": ex.get("pid")},
                      "details": f"comm={path.strip()} syscall=execve pid={ex.get('pid')}",
                      "nonce": args.nonce, "ts": time.time()}
                events.append(ev); pending.append(ev)
        if EXTRA:
            for i in range(RING_SLOTS):             # кольцо путей openat (LLM-B-03)
                path = read_path_entry(mp, i).strip()
                if not path or not any(h in path for h in HONEYPOT_HINTS):
                    continue
                key = ("file", path)
                if key in seen:
                    continue
                seen.add(key)
                ev = {"type": "file", "phase": args.phase, "probe_id": "ebpf-agent",
                      "process": {"binary": "", "args": [], "pid": 0},
                      "file": {"path": path}, "details": f"openat path={path}",
                      "nonce": args.nonce, "ts": time.time()}
                events.append(ev); pending.append(ev)
            for slot, desc in ((2, "mmap"), (3, "mprotect"), (4, "init_module"), (5, "finit_module")):
                r = read_map(m, slot)
                if not r.get("count"):
                    continue
                val = int(r.get("argptr") or 0)
                if slot in (2, 3):
                    # mmap: интересен только RWX (PROT_WRITE|PROT_EXEC) — загрузка библиотек (R-X) не считается;
                    # mprotect: включение PROT_EXEC (JIT/перевод страниц в исполняемые).
                    prot = val & 0xFFFF
                    need = 0x6 if slot == 2 else PROT_EXEC
                    if (prot & need) != need:
                        continue
                    key = ("memory", desc, prot)
                    if key in seen:
                        continue
                    seen.add(key)
                    ev = {"type": "memory", "phase": args.phase, "probe_id": "ebpf-agent",
                          "process": {"binary": "", "args": [], "pid": r.get("pid")}, "exec": True,
                          "details": f"syscall={desc} prot=0x{prot:x} pid={r.get('pid')}",
                          "nonce": args.nonce, "ts": time.time()}
                else:                                     # загрузка модуля
                    key = ("module", desc, val)
                    if key in seen:
                        continue
                    seen.add(key)
                    ev = {"type": "module", "phase": args.phase, "probe_id": "ebpf-agent",
                          "process": {"binary": "", "args": [], "pid": r.get("pid")},
                          "details": f"syscall={desc} arg=0x{val:x} pid={r.get('pid')}",
                          "nonce": args.nonce, "ts": time.time()}
                events.append(ev); pending.append(ev)
        if cn.get("count"):
            net_deadline = time.time() + 8.0   # соединение может быть ещё в SYN_SENT -> читаем /proc ещё раз
        if net_deadline and time.time() < net_deadline:
            peers = external_peers()          # LLM-B-02: внешние адреса из kernel-состояния
            if peers:
                ip = peers[0]["ip"]; port = peers[0]["port"]
                key = ("network", ip)
                if key not in seen:
                    seen.add(key)
                    ev = {"type": "network", "phase": args.phase, "probe_id": "ebpf-agent",
                          "dst": {"ip": ip, "port": port},
                          "details": f"comm={cn.get('buf', '').strip()} peers={[p_['ip'] for p_ in peers]}",
                          "nonce": args.nonce, "ts": time.time()}
                    events.append(ev); pending.append(ev)
                net_deadline = 0.0

    while time.time() < t_end:
        time.sleep(0.25)          # кольцо путей быстро «проворачивается» -> читаем чаще
        drain()
        if args.post and pending and (last_post == 0.0 or (time.time() - last_post) >= 3.0):
            _post_events(args, pending); pending = []; last_post = time.time()
        if args.stop_file and os.path.exists(args.stop_file):
            print("[ebpf-agent] стоп-файл найден — завершаю наблюдение", flush=True)
            break
    drain()                                    # финальный дренаж (важно на очень коротких сканах)

    if os.environ.get("EBPF_DUMP_RINGS") == "1" and EXTRA:
        print("[ebpf-agent] ring cursor:", read_path_entry(mp, CURSOR_KEY), flush=True)
        for i in range(RING_SLOTS):
            print(f"[ebpf-agent] ring[{i}]: {read_path_entry(mp, i)!r}", flush=True)
    if os.environ.get("EBPF_DUMP_SLOTS") == "1":
        for i in range(8):
            r = read_map(m, i)
            print(f"[ebpf-agent] slot {i}: count={r.get('count')} pid={r.get('pid')} argval=0x{int(r.get('argptr') or 0):x}",
                  flush=True)
    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w") as fh:
            for e in events:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"[ebpf-agent] событий: {len(events)} -> {args.out}", flush=True)
    if args.post and pending:                     # финальная отправка остатка
        _post_events(args, pending)
    return 0


if __name__ == "__main__":
    sys.exit(main())
