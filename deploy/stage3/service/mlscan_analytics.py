#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MLScan Analytics Engine + UI (Этап 3 + доработка: загрузка моделей, прогресс, статистика).

Компонента 3. Собирает результаты сервиса тестирования, коррелирует находки, считает
риск-скор, применяет Policy Engine, ведёт append-only Evidence Store (hash-chain) и
предоставляет веб-UI с загрузкой файлов моделей (в т.ч. больших), прогрессом проверки и
статистикой по хэшам. Только стандартная библиотека Python.

UI/API:
  GET  /                       Dashboard: статистика + форма загрузки + таблица (прогресс/вердикт)
  GET  /artifact/<id>          Карточка артефакта (sha256, размер, тайминги, находки)
  POST /upload?name=&fmt=      Потоковая загрузка файла (проксируется в сервис тестирования)
  GET  /api/overview           Список всех сканов (state/stage/progress) + вердикт/скор
  GET  /api/scans, /api/scans/<id>   Проанализированные записи
  GET  /api/progress/<id>      Живой прогресс конкретного скана
  GET  /api/stats              Статистика (вердикты, объём, число хэшей)
  GET  /api/evidence/verify    Проверка hash-цепочки evidence
  GET  /reports/<id>.json|.md|.sarif  Отчёты
  GET  /policy
  POST /sync
  GET  /healthz
"""
from __future__ import annotations

import hashlib
import http.client
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

_u = urllib.parse.urlparse(TESTING_URL)
TEST_HOST = _u.hostname
TEST_PORT = _u.port or 80


# ----------------------------------------------------------------------------
# HTTP к сервису тестирования
# ----------------------------------------------------------------------------
def http_get_json(url: str, timeout: int = 20):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def progress_of(scan_id: str) -> dict | None:
    try:
        return http_get_json(f"{TESTING_URL}/scans/{scan_id}", timeout=10)
    except Exception:  # noqa: BLE001
        return None


def testing_stats() -> dict:
    try:
        return http_get_json(TESTING_URL + "/stats", timeout=10)
    except Exception:  # noqa: BLE001
        return {}


# ----------------------------------------------------------------------------
# Политика
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
    if when.get("always"):
        return True
    if "check_id_in" in when and not any(f["check_id"] in when["check_id_in"] for f in findings):
        return False
    if "check_id_all" in when:
        if not set(when["check_id_all"]).issubset({f["check_id"] for f in findings}):
            return False
    if "category_in" in when and not any(f["category"] in when["category_in"] for f in findings):
        return False
    if "min_severity" in when and SEV_RANK.get(max_sev, 0) < SEV_RANK.get(when["min_severity"], 0):
        return False
    if "max_severity_at_most" in when and SEV_RANK.get(max_sev, 0) > SEV_RANK.get(when["max_severity_at_most"], 0):
        return False
    if "min_confidence" in when and not any(f.get("confidence", 0) >= when["min_confidence"] for f in findings):
        return False
    return True


def apply_policy(policy: dict, findings: list[dict], max_sev: str) -> dict:
    for rule in policy.get("rules", []):
        if _match(rule.get("when", {}), findings, max_sev):
            return {"rule_id": rule.get("id"), "action": rule.get("action", "quarantine"),
                    "verdict": rule.get("verdict", "Needs review"), "reason": rule.get("reason", "")}
    d = policy.get("default", {"action": "quarantine", "verdict": "Needs review"})
    return {"rule_id": "default", "action": d.get("action", "quarantine"),
            "verdict": d.get("verdict", "Needs review"), "reason": d.get("reason", "")}


def scoring(findings: list[dict]) -> dict:
    if not findings:
        return {"risk_score": 0.0, "max_severity": "info", "by_severity": {}, "active_checks": []}
    sevs = [f["severity"] for f in findings]
    max_sev = max(sevs, key=lambda s: SEV_RANK.get(s, 0))
    weights = sorted((SEV_W.get(f["severity"], 0.5) for f in findings), reverse=True)
    score = round(min(10.0, weights[0] + 0.2 * sum(weights[1:])), 2)
    by_sev: dict[str, int] = {}
    for s in sevs:
        by_sev[s] = by_sev.get(s, 0) + 1
    return {"risk_score": score, "max_severity": max_sev, "by_severity": by_sev,
            "active_checks": sorted({f["check_id"] for f in findings})}


# ----------------------------------------------------------------------------
# Evidence Store (append-only + hash chain)
# ----------------------------------------------------------------------------
_lock = threading.Lock()
_index: dict[str, dict] = {}
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
        with open(EVIDENCE, "a") as fh:
            fh.write(json.dumps({"prev": prev, "hash": h, "record": record}, ensure_ascii=False) + "\n")
        _last_hash = h
        _index[record["scan_id"]] = record
        return {"prev": prev, "hash": h}


def verify_chain() -> dict:
    if not os.path.isfile(EVIDENCE):
        return {"ok": True, "entries": 0}
    prev, n = "GENESIS", 0
    with open(EVIDENCE) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            calc = hashlib.sha256((prev + json.dumps(e["record"], ensure_ascii=False, sort_keys=True)).encode()).hexdigest()
            if e.get("prev") != prev or e.get("hash") != calc:
                return {"ok": False, "entries": n, "broken_at": n + 1}
            prev, n = e["hash"], n + 1
    return {"ok": True, "entries": n, "last_hash": prev}


# ----------------------------------------------------------------------------
# Анализ
# ----------------------------------------------------------------------------
def analyze(scan: dict) -> dict:
    findings = scan.get("findings", []) or []
    sc = scoring(findings)
    decision = apply_policy(load_policy(), findings, sc["max_severity"])
    return {
        "scan_id": scan.get("scan_id"), "name": scan.get("name"), "format": scan.get("format"),
        "sha256": scan.get("sha256"), "size": scan.get("size"), "timings": scan.get("timings"),
        "created": scan.get("created"), "service_verdict": scan.get("verdict"),
        "service_reason": scan.get("reason"), "score": sc, "policy": decision,
        "verdict": decision.get("verdict") or scan.get("verdict"),
        "findings": findings, "state": scan.get("state"),
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
        scan = progress_of(sid)
        if not scan or scan.get("state") != "done":
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


def overview() -> list[dict]:
    try:
        scans = http_get_json(TESTING_URL + "/scans").get("scans", [])
    except Exception:  # noqa: BLE001
        scans = []
    known = set()
    out = []
    for s in scans:
        rid = _index.get(s.get("scan_id"), {})
        known.add(s.get("scan_id"))
        out.append({**s,
                    "verdict": rid.get("verdict") or s.get("verdict"),
                    "risk_score": (rid.get("score") or {}).get("risk_score"),
                    "policy_action": (rid.get("policy") or {}).get("action")})
    for sid, rid in _index.items():          # записи, которых уже нет в testing
        if sid not in known:
            out.append({"scan_id": sid, "name": rid.get("name"), "size": rid.get("size"),
                        "sha256": rid.get("sha256"), "state": "done", "stage": "done",
                        "progress": 100, "verdict": rid.get("verdict"),
                        "risk_score": (rid.get("score") or {}).get("risk_score"),
                        "policy_action": (rid.get("policy") or {}).get("action"),
                        "created": rid.get("created")})
    return out


def stats() -> dict:
    verdicts: dict[str, int] = {}
    total = 0
    for s in overview():
        if s.get("verdict"):
            verdicts[s["verdict"]] = verdicts.get(s["verdict"], 0) + 1
        total += int(s.get("size") or 0)
    return {"scans": len(overview()), "by_verdict": verdicts,
            "total_bytes": total, "testing": testing_stats()}


# ----------------------------------------------------------------------------
# Отчёты
# ----------------------------------------------------------------------------
def report_md(rec: dict) -> str:
    L = [f"# MLScan отчёт: {rec.get('name')}", ""]
    L.append(f"- **scan_id:** `{rec.get('scan_id')}`")
    L.append(f"- **SHA-256:** `{rec.get('sha256')}`")
    L.append(f"- **Размер:** {rec.get('size')} байт")
    L.append(f"- **Формат:** `{rec.get('format')}`")
    L.append(f"- **Вердикт:** **{rec.get('verdict')}** "
             f"(policy: {rec['policy'].get('rule_id')} → {rec['policy'].get('action')})")
    L.append(f"- **Риск-скор:** {rec['score'].get('risk_score')} "
             f"(max severity: {rec['score'].get('max_severity')})")
    if rec.get("timings"):
        L.append(f"- **Тайминги:** {rec['timings']}")
    L.append("")
    L.append("## Находки")
    L.append("")
    L.append("| Уровень | ID | Severity | Уверенность | Находка |")
    L.append("|---------|----|----------|-------------|---------|")
    for f in sorted(rec.get("findings", []), key=lambda x: -SEV_RANK.get(x["severity"], 0)):
        L.append(f"| {f['level']} | {f['check_id']} | {f['severity']} | {f.get('confidence', 0):.2f} | {f['title']} |")
    if not rec.get("findings"):
        L.append("Находок нет.")
    return "\n".join(L)


def report_sarif(rec: dict) -> dict:
    rules, results = {}, []
    for f in rec.get("findings", []):
        rules.setdefault(f["check_id"], {"id": f["check_id"], "name": f["title"],
                                         "shortDescription": {"text": f["title"]},
                                         "properties": {"severity": f["severity"], "category": f["category"]}})
        results.append({"ruleId": f["check_id"],
                        "level": {"critical": "error", "high": "error", "medium": "warning",
                                  "low": "note", "info": "note"}.get(f["severity"], "warning"),
                        "message": {"text": f["title"] + (f" — {f.get('evidence','')}" if f.get("evidence") else "")},
                        "properties": {"confidence": f.get("confidence"), "level": f["level"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "MLScan", "informationUri": "https://github.com/pol4/MLScan",
                                          "rules": list(rules.values())}},
                      "results": results,
                      "properties": {"verdict": rec.get("verdict"), "risk_score": rec["score"].get("risk_score")}}]}


# ----------------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------------
_STYLE = """<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1117;color:#e6e6e6}
header{background:#161a23;padding:14px 24px;border-bottom:1px solid #232a36;display:flex;gap:16px;align-items:center}
h1{font-size:18px;margin:0} a{color:#6cb6ff;text-decoration:none}
main{padding:24px} .cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px}
.card{background:#161a23;border:1px solid #232a36;border-radius:10px;padding:14px 18px;min-width:130px}
.card .n{font-size:24px;font-weight:700} .card .l{color:#9aa4b2;font-size:12px;text-transform:uppercase}
table{border-collapse:collapse;width:100%} th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #232a36;font-size:14px}
th{color:#9aa4b2;font-weight:600} code{background:#1d2330;padding:1px 5px;border-radius:4px}
.v-Malicious{color:#ff6b6b}.v-Dangerous{color:#ffb057}.v-Needs{color:#ffd166}.v-Safe{color:#5dd39e}.v-Inconclusive{color:#9aa4b2}
.pbar{background:#232a36;border-radius:5px;height:14px;position:relative;overflow:hidden;min-width:120px}
.pbar>span{display:block;height:100%;background:#3d7dd8}
form.upload{background:#161a23;border:1px solid #232a36;border-radius:10px;padding:16px;margin-bottom:20px}
input[type=file]{color:#e6e6e6} button{background:#3d7dd8;color:#fff;border:0;border-radius:6px;padding:8px 14px;cursor:pointer}
.uprog{background:#232a36;border-radius:5px;height:12px;margin-top:10px;display:none}
.uprog>span{display:block;height:100%;background:#5dd39e;width:0}
</style>"""


def _page(title: str, body: str, script: str = "") -> bytes:
    return (f"<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
            f"<title>{title} — MLScan</title>{_STYLE}</head><body>"
            f"<header><h1><a href='/'>MLScan — Analytics</a></h1>"
            f"<a href='/api/overview'>JSON</a><a href='/api/evidence/verify'>evidence</a>"
            f"<a href='/policy'>policy</a></header><main>{body}</main>{script}</body></html>").encode()


_JS = """<script>
function fmtBytes(b){b=+b||0;const u=['B','KiB','MiB','GiB'];let i=0;while(b>=1024&&i<u.length-1){b/=1024;i++;}return b.toFixed(b<10&&i>0?1:0)+' '+u[i];}
function esc(s){return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
async function refresh(){
  const ov=(await (await fetch('/api/overview')).json()).scans||[];
  const st=await (await fetch('/api/stats')).json();
  document.getElementById('cards').innerHTML =
    ['Malicious','Dangerous','Needs review','Safe','Inconclusive'].map(v=>
      `<div class="card"><div class="n v-${v.replace(' ','')}">${(st.by_verdict||{})[v]||0}</div><div class="l">${v}</div></div>`).join('')
    + `<div class="card"><div class="n">${st.scans||0}</div><div class="l">Всего</div></div>`
    + `<div class="card"><div class="n">${fmtBytes(st.total_bytes)}</div><div class="l">Объём</div></div>`;
  const rows=ov.map(r=>{
    const v=r.verdict||''; const pr=r.progress||0;
    return `<tr><td><a href="/artifact/${r.scan_id}">${esc(r.name)}</a></td>`
      +`<td>${fmtBytes(r.size)}</td><td><code>${(r.sha256||'').slice(0,12)}…</code></td>`
      +`<td>${esc(r.state)}${r.stage&&r.stage!=='done'?' / '+esc(r.stage):''}<div class="pbar"><span style="width:${pr}%"></span></div></td>`
      +`<td class="v-${String(v).replace(' ','')}">${esc(v||'—')}</td>`
      +`<td>${r.risk_score!=null?r.risk_score:'—'}</td><td>${esc(r.policy_action||'—')}</td></tr>`;}).join('');
  document.getElementById('rows').innerHTML=rows;
}
document.getElementById('f').addEventListener('submit',e=>{
  e.preventDefault();const file=document.querySelector('input[type=file]').files[0];if(!file)return;
  const ext=(file.name.split('.').pop()||'').toLowerCase();
  const fmt={pt:'torch',pth:'torch',bin:'torch',ckpt:'torch',npy:'numpy',npz:'numpy',
             joblib:'joblib',dill:'dill',cloudpickle:'cloudpickle'}[ext]||'pickle';
  const xhr=new XMLHttpRequest();
  xhr.open('POST','/upload?name='+encodeURIComponent(file.name)+'&fmt='+fmt);
  const box=document.getElementById('uprog'),bar=document.getElementById('ubar');
  box.style.display='block';
  xhr.upload.onprogress=ev=>{bar.style.width=Math.round(ev.loaded/ev.total*100)+'%';};
  xhr.onload=()=>{setTimeout(()=>{box.style.display='none';bar.style.width='0';},400);refresh();};
  xhr.onerror=()=>{alert('Ошибка загрузки');};
  xhr.send(file);
});
refresh();setInterval(refresh,3000);
</script>"""


def ui_index() -> bytes:
    body = ("<div class='cards' id='cards'></div>"
            "<form class='upload' id='f'><b>Загрузить модель</b><br><br>"
            "<input type='file' name='file'> <button type='submit'>Загрузить и проверить</button>"
            "<div class='uprog' id='uprog'><span id='ubar'></span></div>"
            "<div style='color:#9aa4b2;font-size:12px;margin-top:6px'>"
            "Поддерживаются большие файлы; формат определяется по расширению.</div></form>"
            "<table><thead><tr><th>Артефакт</th><th>Размер</th><th>SHA-256</th>"
            "<th>Прогресс</th><th>Вердикт</th><th>Скор</th><th>Действие</th></tr></thead>"
            "<tbody id='rows'></tbody></table>")
    return _page("Обзор", body, _JS)


def ui_artifact(sid: str) -> bytes | None:
    rec = _index.get(sid)
    live = None if rec else progress_of(sid)
    if not rec and not live:
        return None
    if not rec:
        return _page("артефакт", f"<p><a href='/'>← к обзору</a></p><h2>{live.get('name')}</h2>"
                                 f"<p>Состояние: <b>{live.get('state')}/{live.get('stage')}</b> "
                                 f"({live.get('progress')}%)</p>"
                                 f"<div class='pbar'><span style='width:{live.get('progress',0)}%'></span></div>")
    v = rec.get("verdict", "")
    rows = "".join(
        f"<tr><td>{f['level']}</td><td>{f['check_id']}</td><td>{f['severity']}</td>"
        f"<td>{f.get('confidence',0):.2f}</td><td>{f['title']}</td>"
        f"<td><code>{(f.get('evidence') or '')[:140]}</code></td></tr>"
        for f in sorted(rec.get("findings", []), key=lambda x: -SEV_RANK.get(x["severity"], 0)))
    body = (f"<p><a href='/'>← к обзору</a></p><h2>{rec.get('name')} — "
            f"<span class='v-{v.replace(' ','')}'>{v}</span></h2>"
            f"<p>SHA-256: <code>{rec.get('sha256')}</code><br>"
            f"Размер: {rec.get('size')} байт<br>"
            f"Риск-скор: <b>{rec['score'].get('risk_score')}</b>, max severity: {rec['score'].get('max_severity')}<br>"
            f"Policy: <code>{rec['policy'].get('rule_id')}</code> → {rec['policy'].get('action')}<br>"
            f"Тайминги: {rec.get('timings')}<br>"
            f"Причина (сервис): {rec.get('service_reason')}</p>"
            f"<p>Отчёты: <a href='/reports/{sid}.json'>JSON</a> · "
            f"<a href='/reports/{sid}.md'>Markdown</a> · <a href='/reports/{sid}.sarif'>SARIF</a></p>"
            "<table><tr><th>Ур.</th><th>ID</th><th>Severity</th><th>Увер.</th><th>Находка</th>"
            "<th>Доказательство</th></tr>" + rows + "</table>")
    return _page(rec.get("name", "артефакт"), body)


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "MLScanAnalytics/0.6"

    def log_message(self, *a):
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def _proxy_upload(self, q: dict) -> None:
        name = q.get("name", ["sample.pkl"])[0]
        fmt = q.get("fmt", ["pickle"])[0]
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return self._json(400, {"error": "empty body"})
        cx = http.client.HTTPConnection(TEST_HOST, TEST_PORT, timeout=1800)
        path = f"/scans/upload?name={urllib.parse.quote(name)}&fmt={urllib.parse.quote(fmt)}"
        cx.putrequest("POST", path)
        cx.putheader("Content-Length", str(n))
        cx.putheader("Content-Type", "application/octet-stream")
        cx.endheaders()
        got = 0
        while got < n:
            chunk = self.rfile.read(min(1 << 20, n - got))
            if not chunk:
                break
            cx.send(chunk)
            got += len(chunk)
        resp = cx.getresponse()
        body = resp.read()
        cx.close()
        self._send(resp.status, body, "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        p = u.path
        if p == "/healthz":
            return self._json(200, {"status": "ok", "scans": len(_index)})
        if p == "/api/scans":
            return self._json(200, {"scans": list(_index.values())})
        if p == "/api/overview":
            return self._json(200, {"scans": overview()})
        if p == "/api/stats":
            return self._json(200, stats())
        if p == "/api/evidence/verify":
            return self._json(200, verify_chain())
        if p == "/policy":
            return self._json(200, load_policy())
        if p.startswith("/api/progress/"):
            live = progress_of(p.split("/", 3)[3])
            return self._json(200, live) if live else self._json(404, {"error": "not found"})
        if p.startswith("/api/scans/"):
            rec = _index.get(p.split("/", 3)[3])
            return self._json(200, rec) if rec else self._json(404, {"error": "not found"})
        if p.startswith("/reports/"):
            sid, _, ext = p.split("/", 2)[2].rpartition(".")
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
            html = ui_artifact(p.split("/", 2)[2])
            return self._send(200, html, "text/html; charset=utf-8") if html else self._send(404, b"not found", "text/plain")
        return self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/sync":
            return self._json(200, sync_once())
        if u.path == "/upload":
            return self._proxy_upload(q)
        return self._json(404, {"error": "not found"})


def main() -> None:
    _load_store()
    threading.Thread(target=poller, daemon=True).start()
    port = int(os.environ.get("PORT", "8080"))
    print(f"[analytics] on :{port}; testing={TESTING_URL}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
