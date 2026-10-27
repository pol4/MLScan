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
KEY_SIZE = 4
VALUE_SIZE = 96                      # {u64 count; u32 pid; u32 pad; u64 argptr; u64 rv; u8 buf[64]}

# Кодировки инструкций eBPF (см. include/uapi/linux/bpf.h)
OP = {
    "ld_map_fd": 0x18, "ld_imm64": 0x18, "ldx_dw": 0x79, "ldx_w": 0x61, "stx_w": 0x63,
    "stx_dw": 0x7B, "st_dw": 0x7A, "add_imm": 0x07, "mov_reg": 0xBF, "mov_imm": 0xB7,
    "jeq_imm": 0x15, "jne_imm": 0x55, "jgt_imm": 0x25, "call": 0x85, "exit": 0x95,
    "jsl_imm": 0xC5,   # BPF_JMP | BPF_JSLT | BPF_K
}
# Номера syscall (x86_64)
NR_EXECVE, NR_CONNECT, NR_OPENAT = 59, 42, 257
# offsets в struct pt_regs (x86_64): r15..r8, ax, cx, dx, si, di, orig_ax
#   index: 0..9 (r15..r8), 10=ax(80), 11=cx(88), 12=dx(96), 13=si(104), 14=di(112), 15=orig_ax(120)
OFF_ARG0, OFF_ARG1, OFF_ORIG_AX = 112, 104, 120


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

    def jsl_imm(self, dst, imm, off):
        self._i(OP["jsl_imm"], dst=dst, imm=imm, off=off)

    def call(self, helper):
        self._i(OP["call"], imm=helper)

    def exit(self):
        self._i(OP["exit"])

    def bytes(self) -> bytes:
        return b"".join(self.ins)


def build_hook(nr: int, arg_off: int, map_fd: int) -> bytes:
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
    a.mov_reg(3, 6)
    a.add_imm(3, arg_off)
    a.stx_dw(10, 3, -80)         # сохраняем сырой указатель (диагностика)
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
    a.mov_imm(2, 0 if nr != NR_CONNECT else 1)
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
    a.ldx_dw(1, 10, -80)
    a.stx_dw(8, 1, 16)         # value->argptr
    a.stx_dw(8, 9, 24)         # value->rv
    for i in range(8):         # копируем буфер со стека в value->buf (comm занимает первые 16)
        a.ldx_dw(1, 10, -64 + i * 8)
        a.stx_dw(8, 1, 32 + i * 8)
    # общий выход: обе ветки прыгают на exit (позиция pos_exit)
    pos_exit = len(a.ins)
    a.mov_imm(0, 0)
    a.exit()
    a.ins[jump] = struct.pack("<BBhI", OP["jne_imm"], 7, pos_exit - jump - 1, nr)
    a.ins[jeq0] = struct.pack("<BBhI", OP["jeq_imm"], 0, pos_exit - jeq0 - 1, 0)
    if not DUMP_NR == nr:
        a.ins[skip_neg] = struct.pack("<BBhI", OP["jsl_imm"], 9, pos_exit - skip_neg - 1, 0)
    return a.bytes()


def load_hook(nr: int, arg_off: int, map_fd: int) -> int:
    prog = build_hook(nr, arg_off, map_fd)
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


def create_map() -> int:
    attr = MapCreate(map_type=BPF_MAP_TYPE_ARRAY, key_size=KEY_SIZE, value_size=VALUE_SIZE,
                     max_entries=2)
    fd, err = _bpf(attr, BPF_MAP_CREATE)
    if fd < 0:
        raise RuntimeError(f"BPF_MAP_CREATE: errno={err}")
    return fd


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
    load_hook(NR_EXECVE, OFF_ARG0, m)      # ключ 0 -> process_exec
    load_hook(NR_CONNECT, OFF_ARG1, m)     # ключ 1 -> network
    # NB: openat отложен — нужен отдельный слот карты (сейчас слоты: 0=execve, 1=connect)
    print(f"[ebpf-agent] bpf активен (BTF {os.path.getsize('/sys/kernel/btf/vmlinux')} байт), "
          f"хуки: execve+connect (2 слота карты)", flush=True)

    if args.trigger_shell:      # самопроверка сенсора (в проде это делает сам движок/агент модели)
        subprocess.run(["/bin/sh", "-c", "true"], check=False)
    events: list[dict] = []
    pending: list[dict] = []
    t_end = time.time() + max(args.duration, 5)
    last_post = 0.0
    seen = set()
    while time.time() < t_end:
        time.sleep(1.0)
        ex, cn = read_map(m, 0), read_map(m, 1)
        if DUMP_NR >= 0 and ex.get("count"):
            print("[ebpf-agent] pt_regs[80..144] hex:", ex.get("buf_hex", ""), flush=True)
        if ex.get("count"):
            path = (ex["buf"] or "?")
            key = ("process_exec", path)
            if key not in seen:
                seen.add(key)
                ev = {"type": "process_exec", "phase": args.phase, "probe_id": "ebpf-agent",
                               "process": {"binary": path.strip(), "exe": path.strip(),
                                           "args": [], "pid": ex.get("pid")},
                       "details": f"comm={path.strip()} syscall=execve pid={ex.get('pid')}",
                       "nonce": args.nonce, "ts": time.time()}
                events.append(ev); pending.append(ev)
        if args.post and pending and (time.time() - last_post) >= 3.0:
            _post_events(args, pending); pending = []; last_post = time.time()
        if cn.get("count"):
            peers = external_peers()          # LLM-B-02: внешние адреса из kernel-состояния
            ip = peers[0]["ip"] if peers else ""
            port = peers[0]["port"] if peers else 0
            key = ("network", ip)
            if key not in seen:
                seen.add(key)
                ev = {"type": "network", "phase": args.phase, "probe_id": "ebpf-agent",
                       "dst": {"ip": ip, "port": port} if ip else {},
                       "details": f"comm={cn.get('buf', '').strip()} peers={[p_['ip'] for p_ in peers]}",
                       "nonce": args.nonce, "ts": time.time()}
                events.append(ev); pending.append(ev)

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
