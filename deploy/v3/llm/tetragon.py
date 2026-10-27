#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Наблюдение за LLM-инференсом по событиям eBPF/Tetragon (v3, L2).

Нормализация сырых событий (in-guest Tetragon) и маппинг в findings (`LLM-B-*`):
 exec-shell, внешний egress, чтение honeypot-секретов, исполняемая память, загрузка модулей.
События привязываются к фазе (`load`/`probe`), пробе и **нонсу** скана (антиподмена).
"""
from __future__ import annotations

SHELL_BINARIES = {"sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "curl", "wget", "nc"}
HONEYPOT_HINTS = ("/.aws/", "/.ssh/", "/.kube/", "/etc/shadow", "/etc/passwd")
ALLOWED_NET = ("127.0.0.1", "::1", "localhost")

def _is_public(ip: str) -> bool:
    """True, если адрес публичный (вне loopback/private/link-local) — то есть реальный egress наружу.

    Трафик платформы (ClusterIP 10.152/10.1, node 192.168.x, loopback) не считается внешним.
    """
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_private or a.is_link_local or a.is_multicast or a.is_unspecified)

# правила: (check_id, тип события, предикат, severity, confidence, title)
RULES = [
    ("LLM-B-01", "process_exec", lambda e: _is_shell(e), "high", 0.8,
     "Запуск shell/интерпретатора внутри инференса"),
    ("LLM-B-02", "network", lambda e: _is_external(e), "high", 0.8,
     "Внешнее сетевое соединение из инференса (потенциальная эксфильтрация)"),
    ("LLM-B-03", "file", lambda e: _is_honeypot(e), "high", 0.85,
     "Чтение honeypot-секретов инференсом"),
    ("LLM-B-04", "memory", lambda e: e.get("exec", False) or "PROT_EXEC" in str(e.get("details", "")),
     "high", 0.75, "Исполняемая память (JIT/mem-exec)"),
    ("LLM-B-05", "module", lambda e: True, "critical", 0.9, "Загрузка модуля ядра"),
]


def _bin(e: dict) -> str:
    p = e.get("process") or {}
    b = str(p.get("binary") or p.get("exe") or "").split("/")[-1]
    return b


def _is_shell(e: dict) -> bool:
    if _bin(e) in SHELL_BINARIES:
        return True
    args = " ".join((e.get("process") or {}).get("args") or [])
    return bool("-c" in (e.get("process") or {}).get("args") or [] or " -c " in f" {args} ")


def _is_external(e: dict) -> bool:
    dst = (e.get("dst") or {})
    ip = str(dst.get("ip") or dst.get("addr") or "")
    if not ip:
        return False
    return _is_public(ip)


def _is_honeypot(e: dict) -> bool:
    path = str((e.get("file") or {}).get("path") or e.get("path") or "")
    return any(h in path for h in HONEYPOT_HINTS)


def normalize_event(raw: dict) -> dict:
    return {"type": raw.get("type", "unknown"), "phase": raw.get("phase", "probe"),
            "probe_id": raw.get("probe_id", ""), "ts": raw.get("ts"),
            "process": raw.get("process") or {}, "dst": raw.get("dst") or {},
            "file": raw.get("file") or {}, "exec": bool(raw.get("exec", False)),
            "details": raw.get("details", ""), "nonce": raw.get("nonce", "")}


def map_findings(events, nonce: str = "") -> tuple[list[dict], int]:
    """Возвращает (findings, rejected_count). При заданном nonce события с чужим nonce отбрасываются."""
    out: list[dict] = []
    rejected = 0
    for raw in events or []:
        e = normalize_event(raw)
        if nonce and e.get("nonce") != nonce:
            rejected += 1
            continue
        for check_id, etype, pred, sev, conf, title in RULES:
            if e["type"] != etype:
                continue
            try:
                hit = pred(e)
            except Exception:  # noqa: BLE001
                hit = False
            if not hit:
                continue
            out.append({"check_id": check_id, "category": "LLM", "severity": sev,
                        "confidence": conf, "title": title, "phase": e["phase"],
                        "probe_id": e["probe_id"],
                        "evidence": f"type={e['type']} phase={e['phase']} "
                                    f"proc={_bin(e)} dst={e['dst'].get('ip','')} "
                                    f"file={e['file'].get('path','')} details={e['details']}"})
            break
    return out, rejected


def max_severity(findings) -> str:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    best = "info"
    for f in findings or []:
        if order.get(f.get("severity", "info"), 0) > order.get(best, 0):
            best = f["severity"]
    return best
