#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Red-team / escape-тест (Этап 5).

Запускается в песочнице Этапа 1 (Kata, restricted, default-deny egress) и проверяет,
что ожидаемые ограничения действительно соблюдаются. Возвращает JSON и exit code
0, если ВСЕ ожидания выполнены (изоляция работает), иначе 1.
"""
import json
import os
import socket
import sys


def try_external():
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect(("1.1.1.1", 443))
        return "connect_ok"
    except Exception as e:  # noqa: BLE001
        return f"blocked:{type(e).__name__}"
    finally:
        s.close()


def try_sinkhole():
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect(("sinkhole", 8080))
        return "connect_ok"
    except Exception as e:  # noqa: BLE001
        return f"blocked:{type(e).__name__}"
    finally:
        s.close()


def try_write_root():
    try:
        with open("/etc/mlscan_pwn", "w") as fh:
            fh.write("x")
        return "write_ok"
    except Exception as e:  # noqa: BLE001
        return f"blocked:{type(e).__name__}"


def try_shadow():
    try:
        open("/etc/shadow").read()
        return "read_ok"
    except Exception as e:  # noqa: BLE001
        return f"blocked:{type(e).__name__}"


def caps_effective():
    try:
        for line in open("/proc/self/status"):
            if line.startswith("CapEff:"):
                return line.split()[1]
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


def main() -> int:
    checks = []

    def add(name, observed, ok):
        checks.append({"check": name, "observed": observed, "ok": ok})

    sa = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    add("no_serviceaccount_token", "absent" if not os.path.exists(sa) else "present",
        not os.path.exists(sa))
    add("rootfs_readonly", try_write_root(), try_write_root().startswith("blocked"))
    add("external_egress_blocked", try_external(), try_external().startswith("blocked"))
    add("sinkhole_reachable", try_sinkhole(), try_sinkhole() == "connect_ok")
    add("shadow_unreadable", try_shadow(), try_shadow().startswith("blocked"))
    add("no_docker_sock", "absent" if not os.path.exists("/var/run/docker.sock") else "present",
        not os.path.exists("/var/run/docker.sock"))
    ce = caps_effective()
    add("no_capabilities", ce, ce in ("0000000000000000", "0"))

    kernel = os.uname().release
    all_ok = all(c["ok"] for c in checks)
    print(json.dumps({"kernel": kernel, "uid": os.getuid(), "checks": checks,
                      "all_ok": all_ok}, ensure_ascii=False, indent=2))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
