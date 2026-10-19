#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MLScan Analytics Engine + UI (Этап 3).

Компонента 3 архитектуры: управляет процессом, собирает результаты сервиса тестирования
(Этап 2), коррелирует находки, считает риск-скор, применяет Policy Engine, ведёт
append-only Evidence Store (hash-chain) и формирует отчёты (JSON/Markdown/SARIF),
а также предоставляет веб-UI.

Только стандартная библиотека. Не общается с Kubernetes API — работает с API сервиса
тестирования по HTTP.

API:
  GET  /                       UI: список сканов (dashboard)
  GET  /artifact/<id>          UI: карточка артефакта + находки
  GET  /api/scans              JSON: все проанализированные сканы
  GET  /api/scans/<id>         JSON: запись скана (скор + решение политики)
  GET  /api/evidence/verify    проверка целостности evidence-цепочки
  GET  /reports/<id>.json|.md|.sarif   отчёты
  GET  /policy                 текущая политика
  POST /sync                   принудительная синхронизация с сервисом тестирования
  GET  /healthz
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TESTING_URL = os.environ.get(
    "TESTING_URL", "http://mlscan-testing.mlscan-testing.svc.cluster.local:8080")
DATA_DIR = os.environ.get("DATA_DIR", "/data")
POLICY_PATH = os.environ.get("POLICY_PATH", "/etc/mlscan/policy.json")
EVIDENCE = os.path.join(DATA_DIR, "evidence.jsonl")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "15"))

SEV_W = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ----------------------------------------------------------------------------
# HTTP client к сервису тестирования
# ----------------------------------------------------------------------------
def http_get_json(url: str, timeout: int = 20):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


# ----------------------------------------------------------------------------
# Политика (JSON, без внешних зависимостей)
# ----------------------------------------------------------------------------
def load_policy() -> dict:
    try:
        with open(POLICY_PATH) as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return {"rules": [], "default": {"action": "quarantine", "verdict": "Needs review"}}


def _match(when: dict, findings: list[dict], max_sev: str) -> bool:
    if not when:
        return True
    if "always" in when and when["always"]:
        return True
    if "check_id_in" in when:
        if not any(f["check_id"] in when["check_id_in"] for f in findings):
            return False
    if "check_id_all" in when:
        have = {f["check_id"] for f in findings}
        if not set(when["check_id_all"]).issubset(have):
            return False
    if "category_in" in when:
        if not any(f["category"] in when["category_in"] for f in findings):
            return False
    if "min_severity" in when and SEV_RANK.get(max_sev, 0) < SEV_RANK.get(when["min_severity"], 0):
        return False
    if "max_severity_at_most" in when and SEV_RANK.get(max_sev, 0) > SEV_RANK.get(when["max_severity_at_most"], 0):
        return False
    if "min_confidence" in when:
        if not any(f.get("confidence", 0) >= when["min_confidence"] for f in findings):
            return False
    return True


def apply_policy(policy: dict, findings: list[dict], max_sev: str) -> dict:
    for rule in policy.get("rules", []):
        if _match(rule.get("when", {}), findings, max_sev):
            return {"rule_id": rule.get("id"), "action": rule.get("action", "quarantine"),
                    "verdict": rule.get("verdict", "Needs review"),
                    "reason": rule.get("reason", "")}
    d = policy.get("default", {"action": "quarantine", "verdict": "Needs review"})
    return {"rule_id": "default", "action": d.get("action", "quarantine"),
            "verdict": d.get("verdict", "Needs review"), "reason": d.get("reason", "")}


# ----------------------------------------------------------------------------
# Скоринг
# ----------------------------------------------------------------------------
def scoring(findings: list[dict]) -> dict:
    if not findings:
        return {"risk_score": 0.0, "max_severity": "info", "by_severity": {}, "active_checks": []}
    sevs = [f["severity"] for f in findings]
    max_sev = max(sevs, key=lambda s: SEV_RANK.get(s, 0))
    weights = sorted((SEV_W.get(f["severity"], 0.5) for f in findings), reverse=True)
    base = weights[0]
    bonus = 0.2 * sum(weights[1:])
    score = round(min(10.0, base + bonus), 2)
    by_sev: dict[str, int] = {}
    for s in sevs:
        by_sev[s] = by_sev.get(s, 0) + 1
    return {"risk_score": score, "max_severity": max_sev, "by_severity": by_sev,
            "active_checks": sorted({f["check_id"] for f in findings})}


# ----------------------------------------------------------------------------
# Evidence Store (append-only + hash chain)
# ----------------------------------------------------------------------------
_lock = threading.Lock()
_index: dict[str, dict] = {}      # scan_id -> stored record
_last_hash = "GENESIS"


def _load_store() -> None:
    global _last_hash
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.isfile(EVIDENCE):
        open(EVIDENCE, "a").close()
        return
    with open(EVIDENCE) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            _last_hash = e.get("hash", _last_hash)
            rec = e.get("record", {})
            if rec.get("scan_id"):
                _index[rec["scan_id"]] = rec


def _append(record: dict) -> dict:
    global _last_hash
    with _lock:
        prev = _last_hash
        payload = json.dumps(record, ensure_ascii=False, sort_keys=True)
        h = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
        entry = {"prev": prev, "hash": h, "record": record}
        with open(EVIDENCE, "a") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _last_hash = h
        _index[record["scan_id"]] = record
        return entry


def verify_chain() -> dict:
    if not os.path.isfile(EVIDENCE):
        return {"ok": True, "entries": 0}
    prev = "GENESIS"
    n = 0
    with open(EVIDENCE) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            payload = json.dumps(e["record"], ensure_ascii=False, sort_keys=True)
            calc = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
            if e.get("prev") != prev or e.get("hash") != calc:
                return {"ok": False, "entries": n, "broken_at": n + 1}
            prev = e["hash"]
            n += 1
    return {"ok": True, "entries": n, "last_hash": prev}


# ----------------------------------------------------------------------------
# Анализ записи из сервиса тестирования
# ----------------------------------------------------------------------------
def analyze(scan: dict) -> dict:
    findings = scan.get("findings", []) or []
    sc = scoring(findings)
    decision = apply_policy(load_policy(), findings, sc["max_severity"])
    # правило политики может переопределить вердикт сервиса тестирования
    verdict = decision["verdict"] if decision.get("verdict") else scan.get("verdict")
    return {
        "scan_id": scan.get("scan_id"),
        "name": scan.get("name"),
        "format": scan.get("format"),
        "sha256": scan.get("sha256"),
        "created": scan.get("created"),
        "service_verdict": scan.get("verdict"),
        "service_reason": scan.get("reason"),
        "score": sc,
        "policy": decision,
        "verdict": verdict,
        "findings": findings,
        "state": scan.get("state"),
        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def sync_once() -> dict:
    try:
        listing = http_get_json(TESTING_URL + "/scans")
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"testing service: {exc}", "new": 0}
    new = 0
    for item in listing.get("scans", []):
        sid = item.get("scan_id")
        if not sid or sid in _index:
            continue
        try:
            scan = http_get_json(f"{TESTING_URL}/scans/{sid}")
        except Exception:  # noqa: BLE001
            continue
        if scan.get("state") != "done":
            continue
        _append(analyze(scan))
        new += 1
    return {"ok": True, "new": new, "total": len(_index)}


def poller() -> None:
    while True:
        try:
            sync_once()
        except Exception:  # noqa: BLE001
            pass
        time.sleep(POLL_INTERVAL)


# ----------------------------------------------------------------------------
# Отчёты
# ----------------------------------------------------------------------------
def report_md(rec: dict) -> str:
    L = [f"# MLScan отчёт: {rec.get('name')}", ""]
    L.append(f"- **scan_id:** `{rec.get('scan_id')}`")
    L.append(f"- **SHA-256:** `{rec.get('sha256')}`")
    L.append(f"- **Формат:** `{rec.get('format')}`")
    L.append(f"- **Вердикт:** **{rec.get('verdict')}** "
             f"(policy: {rec['policy'].get('rule_id')} → {rec['policy'].get('action')})")
    L.append(f"- **Риск-скор:** {rec['score'].get('risk_score')} "
             f"(max severity: {rec['score'].get('max_severity')})")
    L.append(f"- **Причина (сервис):** {rec.get('service_reason')}")
    L.append("")
    L.append("## Находки")
    L.append("")
    L.append("| Уровень | ID | Severity | Уверенность | Находка |")
    L.append("|---------|----|----------|-------------|---------|")
    for f in sorted(rec.get("findings", []), key=lambda x: -SEV_RANK.get(x["severity"], 0)):
        L.append(f"| {f['level']} | {f['check_id']} | {f['severity']} | "
                 f"{f.get('confidence', 0):.2f} | {f['title']} |")
    if not rec.get("findings"):
        L.append("Находок нет.")
    L.append("")
    L.append(f"*Сформировано Analytics Engine: {rec.get('analyzed_at')}*")
    return "\n".join(L)


def report_sarif(rec: dict) -> dict:
    rules = {}
    results = []
    for f in rec.get("findings", []):
        rid = f["check_id"]
        rules.setdefault(rid, {"id": rid, "name": f["title"], "shortDescription": {"text": f["title"]},
                               "properties": {"severity": f["severity"], "category": f["category"]}})
        results.append({
            "ruleId": rid,
            "level": {"critical": "error", "high": "error", "medium": "warning",
                      "low": "note", "info": "note"}.get(f["severity"], "warning"),
            "message": {"text": f["title"] + (f" — {f.get('evidence','')}" if f.get("evidence") else "")},
            "properties": {"confidence": f.get("confidence"), "level": f["level"]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "MLScan", "informationUri": "https://github.com/pol4/MLScan",
                                "rules": list(rules.values())}},
            "results": results,
            "properties": {"verdict": rec.get("verdict"), "risk_score": rec["score"].get("risk_score")},
        }],
    }


# ----------------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------------
def _page(title: str, body: str) -> bytes:
    html = f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>{title} — MLScan</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1117;color:#e6e6e6}}
header{{background:#161a23;padding:14px 24px;border-bottom:1px solid #232a36}}
h1{{font-size:18px;margin:0}} a{{color:#6cb6ff;text-decoration:none}}
main{{padding:24px}} table{{border-collapse:collapse;width:100%}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #232a36;font-size:14px}}
th{{color:#9aa4b2;font-weight:600}}
.v-Malicious{{color:#ff6b6b}} .v-Dangerous{{color:#ffb057}}
.v-Needs{{color:#ffd166}} .v-Safe{{color:#5dd39e}} .v-Inconclusive{{color:#9aa4b2}}
code{{background:#1d2330;padding:1px 5px;border-radius:4px}}
</style></head><body>
<header><h1>MLScan — Analytics</h1></header><main>{body}</main></body></html>"""
    return html.encode("utf-8")


def ui_index() -> bytes:
    rows = []
    for rec in sorted(_index.values(), key=lambda r: r.get("analyzed_at", ""), reverse=True):
        v = rec.get("verdict", "")
        rows.append(f'<tr><td><a href="/artifact/{rec["scan_id"]}">{rec.get("name")}</a></td>'
                    f'<td>{rec.get("format")}</td>'
                    f'<td class="v-{v}">{v}</td>'
                    f'<td>{rec["score"].get("risk_score")}</td>'
                    f'<td>{rec["policy"].get("action")}</td>'
                    f'<td>{rec.get("analyzed_at")}</td></tr>')
    body = ("<p><a href='/api/scans'>JSON</a> · <a href='/api/evidence/verify'>проверка evidence</a>"
            " · <a href='/policy'>политика</a></p>"
            "<table><tr><th>Артефакт</th><th>Формат</th><th>Вердикт</th><th>Скор</th>"
            "<th>Действие</th><th>Когда</th></tr>" + "".join(rows) + "</table>")
    if not rows:
        body = "<p>Пока нет проанализированных сканов. Нажмите <code>POST /sync</code>.</p>" + body
    return _page("Обзор", body)


def ui_artifact(sid: str) -> bytes | None:
    rec = _index.get(sid)
    if not rec:
        return None
    v = rec.get("verdict", "")
    rows = []
    for f in sorted(rec.get("findings", []), key=lambda x: -SEV_RANK.get(x["severity"], 0)):
        rows.append(f'<tr><td>{f["level"]}</td><td>{f["check_id"]}</td><td>{f["severity"]}</td>'
                    f'<td>{f.get("confidence",0):.2f}</td><td>{f["title"]}</td>'
                    f'<td><code>{(f.get("evidence") or "")[:120]}</code></td></tr>')
    body = (f'<p><a href="/">← к обзору</a></p>'
            f'<h2>{rec.get("name")} — <span class="v-{v}">{v}</span></h2>'
            f'<p>SHA-256: <code>{rec.get("sha256")}</code><br>'
            f'Риск-скор: <b>{rec["score"].get("risk_score")}</b>, '
            f'max severity: {rec["score"].get("max_severity")}<br>'
            f'Policy: <code>{rec["policy"].get("rule_id")}</code> → {rec["policy"].get("action")}<br>'
            f'Причина (сервис): {rec.get("service_reason")}</p>'
            f'<p>Отчёты: <a href="/reports/{sid}.json">JSON</a> · '
            f'<a href="/reports/{sid}.md">Markdown</a> · '
            f'<a href="/reports/{sid}.sarif">SARIF</a></p>'
            "<table><tr><th>Ур.</th><th>ID</th><th>Severity</th><th>Увер.</th><th>Находка</th>"
            "<th>Доказательство</th></tr>" + "".join(rows) + "</table>")
    return _page(rec.get("name", "артефакт"), body)


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "MLScanAnalytics/0.3"

    def log_message(self, *a):  # тише
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        p = u.path
        if p == "/healthz":
            return self._json(200, {"status": "ok", "scans": len(_index)})
        if p == "/api/scans":
            return self._json(200, {"scans": list(_index.values())})
        if p == "/api/evidence/verify":
            return self._json(200, verify_chain())
        if p == "/policy":
            return self._json(200, load_policy())
        if p.startswith("/api/scans/"):
            sid = p.split("/", 3)[3]
            rec = _index.get(sid)
            return self._json(200, rec) if rec else self._json(404, {"error": "not found"})
        if p.startswith("/reports/"):
            name = p.split("/", 2)[2]
            sid, _, ext = name.rpartition(".")
            rec = _index.get(sid)
            if not rec:
                return self._json(404, {"error": "not found"})
            if ext == "json":
                return self._send(200, json.dumps(rec, ensure_ascii=False, indent=2).encode(), "application/json")
            if ext == "md":
                return self._send(200, report_md(rec).encode(), "text/markdown; charset=utf-8")
            if ext == "sarif":
                return self._send(200, json.dumps(report_sarif(rec), ensure_ascii=False, indent=2).encode(), "application/json")
            return self._json(404, {"error": "unknown format"})
        if p == "/":
            return self._send(200, ui_index(), "text/html; charset=utf-8")
        if p.startswith("/artifact/"):
            sid = p.split("/", 2)[2]
            html = ui_artifact(sid)
            return self._send(200, html, "text/html; charset=utf-8") if html else self._send(404, b"not found", "text/plain")
        return self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        if u.path == "/sync":
            return self._json(200, sync_once())
        return self._json(404, {"error": "not found"})


def main() -> None:
    _load_store()
    threading.Thread(target=poller, daemon=True).start()
    port = int(os.environ.get("PORT", "8080"))
    print(f"[analytics] on :{port}; testing={TESTING_URL}; evidence={EVIDENCE}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
