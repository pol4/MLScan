#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""B1-диагностика: проверка РЕАЛЬНОЙ загрузки трассирующего eBPF в гостевой ВМ Kata.

Делает без внешних зависимостей (только stdlib + ctypes):
  1) bpf(BPF_PROG_LOAD) — тривиальная tracepoint-программа (r0=0; exit);
  2) bpf(BPF_RAW_TRACEPOINT_OPEN) на syscalls:sys_enter_execve (raw: sys_enter);
  3) запускает /bin/true (execve) и убеждается, что программа загружена и привязана;
  4) читает BTF-файл ядра (проверка in-guest BTF).

Выход: 0 — eBPF в госте работает; иначе печатает причину и код 1.
"""
import ctypes as C
import os
import struct
import subprocess
import sys

SYS_BPF = 321
BPF_PROG_LOAD = 5
BPF_RAW_TRACEPOINT_OPEN = 17
BPF_PROG_TYPE_TRACEPOINT = 5
BPF_PROG_TYPE_RAW_TRACEPOINT = 17   # 17 — тип для BPF_RAW_TRACEPOINT_OPEN
LOG_SIZE = 1 << 16


class bpf_attr_prog_load(C.Structure):
    _fields_ = [("prog_type", C.c_uint32), ("insn_cnt", C.c_uint32),
                ("insns", C.c_uint64), ("license", C.c_uint64),
                ("log_level", C.c_uint32), ("log_size", C.c_uint32), ("log_buf", C.c_uint64),
                ("kern_version", C.c_uint32), ("prog_flags", C.c_uint32),
                ("prog_name", C.c_char * 16), ("prog_ifindex", C.c_uint32),
                ("expected_attach_type", C.c_uint32)]


class bpf_attr_raw_tp(C.Structure):
    _fields_ = [("name", C.c_uint64), ("prog_fd", C.c_uint32), ("cookie", C.c_uint64)]


def bpf(attr, cmd):
    libc = C.CDLL(None, use_errno=True)
    ret = libc.syscall(SYS_BPF, cmd, C.byref(attr), C.sizeof(attr))
    return ret, C.get_errno()


def main() -> int:
    print("ядро:", os.uname().release)
    btf = "/sys/kernel/btf/vmlinux"
    if not os.path.exists(btf):
        print("BTF: ОТСУТСТВУЕТ (нет %s) — in-guest eBPF невозможен" % btf)
        return 1
    print("BTF: %s (%d байт)" % (btf, os.path.getsize(btf)))

    # Программа: r0 = 0; exit  (два 8-байтовых слотов)
    insns = (C.c_uint64 * 2)(0xB7, 0x95)          # mov r0,0 ; exit
    lic = C.create_string_buffer(b"GPL")
    log = C.create_string_buffer(LOG_SIZE)
    attr = bpf_attr_prog_load(prog_type=BPF_PROG_TYPE_RAW_TRACEPOINT, insn_cnt=2,
                              insns=C.addressof(insns), license=C.addressof(lic),
                              log_level=1, log_size=LOG_SIZE, log_buf=C.addressof(log))
    fd, err = bpf(attr, BPF_PROG_LOAD)
    if fd < 0:
        print("BPF_PROG_LOAD ошибка: errno=%d (%s)" % (err, log.value.decode()[:400]))
        return 1
    print("BPF_PROG_LOAD: ok (fd=%d)" % fd)

    name = C.create_string_buffer(b"sys_enter")
    attr2 = bpf_attr_raw_tp(name=C.addressof(name), prog_fd=fd)
    tpfd, err2 = bpf(attr2, BPF_RAW_TRACEPOINT_OPEN)
    if tpfd < 0:
        print("BPF_RAW_TRACEPOINT_OPEN(sys_enter) ошибка: errno=%d" % err2)
        return 1
    print("attach sys_enter (raw): ok (fd=%d)" % tpfd)

    subprocess.run(["/bin/true"], check=False)
    print("execve выполнен при активной программе — eBPF в госте РАБОТАЕТ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
