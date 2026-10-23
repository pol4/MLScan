#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MLScan Ops / Observability (Этап 5).

Промышленная эксплуатация: метрики (Prometheus), здоровье стека, метрики качества
(TPR/FPR на golden-наборе), SLA, непрерывный retest. Только стандартная библиотека.

API:
  GET  /healthz
  GET  /health/stack        здоровье analytics/testing/integrations
  GET  /metrics             Prometheus text exposition
  GET  /quality             TPR/FPR/precision/accuracy на golden-наборе
  GET  /sla                 счётчики, длина evidence, время последнего retest
  POST /retest              перезапуск проверки golden-набора + ресинк
"""
from __future__ import annotations

import glob
import json
import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, "/opt/auth")
try:
    import authz  # noqa: E402
except Exception:  # noqa: BLE001
    authz = None  # type: ignore

sys.path.insert(0, "/opt/i18n")
try:
    import i18n  # noqa: E402
except Exception:  # noqa: BLE001
    i18n = None  # type: ignore


def T(key: str, lang: str = "ru", **fmt) -> str:
    return i18n.t(key, lang, **fmt) if i18n else key

INTERNAL_KEY = os.environ.get("INTERNAL_KEY", "")
PGHOST = os.environ.get("PGHOST", "")
GARAGE_ADMIN_URL = os.environ.get("GARAGE_ADMIN_URL", "")
GARAGE_ADMIN_TOKEN = os.environ.get("GARAGE_ADMIN_TOKEN", "")
_Pg = None
if PGHOST:
    try:
        sys.path.insert(0, "/opt/pg")
        from pgclient import Pg as _Pg  # noqa: E402
    except Exception:  # noqa: BLE001
        _Pg = None


def _auth_headers() -> dict:
    return {"Authorization": f"Bearer {INTERNAL_KEY}"} if INTERNAL_KEY else {}


_integrity_bad: list[str] = []   # сервисы с нарушенной целостностью кода/конфигурации (P1-6)
ANALYTICS_URL = os.environ.get("ANALYTICS_URL", "http://mlscan-analytics.mlscan-analytics.svc.cluster.local:8080")
TESTING_URL = os.environ.get("TESTING_URL", "http://mlscan-testing.mlscan-testing.svc.cluster.local:8080")
INTEGRATIONS_URL = os.environ.get("INTEGRATIONS_URL", "http://mlscan-integrations.mlscan-integrations.svc.cluster.local:8080")
GOLDEN_PATH = os.environ.get("GOLDEN_PATH", "/etc/mlscan/golden.json")
SAMPLES_DIR = os.environ.get("SAMPLES_DIR", "/samples")
RETEST_INTERVAL = int(os.environ.get("RETEST_INTERVAL", "0"))   # 0 = только по CronJob/ручному вызову

MALICIOUS = {"Malicious", "Dangerous"}
_state = {"retest_runs": 0, "retest_last_ts": 0, "retest_error": None}
_lock = threading.Lock()


def get_json(url, timeout=15):
    req = urllib.request.Request(url, headers=_auth_headers())
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def post_bytes(url, data, timeout=90):
    req = urllib.request.Request(url, data=data, method="POST", headers=_auth_headers())
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def stack_health() -> dict:
    out = {}
    for name, url in (("analytics", ANALYTICS_URL), ("testing", TESTING_URL),
                      ("integrations", INTEGRATIONS_URL)):
        try:
            h = get_json(url + "/healthz", timeout=5)
            out[name] = {"up": True, "info": h}
        except Exception as exc:  # noqa: BLE001
            out[name] = {"up": False, "error": str(exc)[:120]}
    out["_overall"] = all(v.get("up") for k, v in out.items() if not k.startswith("_"))
    return out


def quality() -> dict:
    try:
        golden = json.load(open(GOLDEN_PATH))
    except Exception:  # noqa: BLE001
        golden = {}
    try:
        scans = get_json(ANALYTICS_URL + "/api/scans").get("scans", [])
    except Exception:  # noqa: BLE001
        return {"error": "analytics unavailable"}
    latest: dict[str, str] = {}
    for s in sorted(scans, key=lambda x: x.get("analyzed_at", "")):
        latest[s.get("name")] = s.get("verdict")
    tp = fp = tn = fn = skipped = 0
    detail = []
    for name, expected in golden.items():
        v = latest.get(name)
        if v is None:
            skipped += 1
            detail.append({"name": name, "expected": expected, "verdict": None, "result": "missing"})
            continue
        if v in ("Inconclusive", "Needs review"):
            skipped += 1
            detail.append({"name": name, "expected": expected, "verdict": v, "result": "inconclusive"})
            continue
        pred_mal = v in MALICIOUS
        exp_mal = expected == "malicious"
        if exp_mal and pred_mal:
            tp += 1; r = "TP"
        elif exp_mal and not pred_mal:
            fn += 1; r = "FN"
        elif not exp_mal and pred_mal:
            fp += 1; r = "FP"
        else:
            tn += 1; r = "TN"
        detail.append({"name": name, "expected": expected, "verdict": v, "result": r})
    tpr = tp / (tp + fn) if (tp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    prec = tp / (tp + fp) if (tp + fp) else None
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else None
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "skipped": skipped,
            "tpr": tpr, "fpr": fpr, "precision": prec, "accuracy": acc, "detail": detail}


def retest() -> dict:
    files = sorted(f for f in glob.glob(os.path.join(SAMPLES_DIR, "*")) if os.path.isfile(f))
    started = time.time()
    submitted = []
    for f in files:
        name = os.path.basename(f)
        try:
            with open(f, "rb") as fh:
                data = fh.read()
            ext = name.rsplit(".", 1)[-1].lower()
            fmt = {"pt": "torch", "pth": "torch", "bin": "torch", "ckpt": "torch",
                   "npy": "numpy", "npz": "numpy", "joblib": "joblib", "mar": "raw",
                   "safetensors": "raw", "onnx": "raw", "gguf": "raw", "h5": "raw",
                   "tar": "raw", "tgz": "raw", "zip": "raw", "xml": "raw", "yaml": "raw",
                   "yml": "raw", "json": "raw", "md": "raw", "py": "raw"}.get(ext, "pickle")
            r = post_bytes(f"{TESTING_URL}/scans?name={name}&fmt={fmt}", data)
            submitted.append((name, r.get("scan_id")))
        except Exception as exc:  # noqa: BLE001
            submitted.append((name, None))
    # ждём завершения (ограниченно)
    deadline = time.time() + 300
    pending = {sid for _, sid in submitted if sid}
    while pending and time.time() < deadline:
        done = set()
        for sid in pending:
            try:
                rec = get_json(f"{TESTING_URL}/scans/{sid}")
                if rec.get("state") in ("done", "error"):
                    done.add(sid)
            except Exception:  # noqa: BLE001
                pass
        pending -= done
        if pending:
            time.sleep(3)
    # ресинк аналитики и интеграций
    sync = {}
    for name, url in (("analytics", ANALYTICS_URL), ("integrations", INTEGRATIONS_URL)):
        try:
            sync[name] = post_bytes(url + "/sync", b"")
        except Exception as exc:  # noqa: BLE001
            sync[name] = {"error": str(exc)[:120]}
    with _lock:
        _state["retest_runs"] += 1
        _state["retest_last_ts"] = int(time.time())
    # аттестация evidence (P1-5): результат проверки целостности в ответе /retest
    try:
        ev = get_json(ANALYTICS_URL + "/api/evidence/verify")
    except Exception:  # noqa: BLE001
        ev = {"ok": False, "error": "analytics unavailable"}
    return {"submitted": len(submitted), "files": [n for n, _ in submitted],
            "elapsed_s": round(time.time() - started, 1), "sync": sync, "evidence": ev}


def sla() -> dict:
    out = {"retest_runs": _state["retest_runs"], "retest_last_ts": _state["retest_last_ts"]}
    try:
        ev = get_json(ANALYTICS_URL + "/api/evidence/verify")
        out["evidence"] = ev
    except Exception as exc:  # noqa: BLE001
        out["evidence"] = {"error": str(exc)[:120]}
    try:
        reg = get_json(INTEGRATIONS_URL + "/registry")
        out["registry_entries"] = len(reg.get("entries", []))
    except Exception:  # noqa: BLE001
        out["registry_entries"] = None
    return out


def _pg():
    if not (PGHOST and _Pg):
        return None
    try:
        c = _Pg(PGHOST, int(os.environ.get("PGPORT", "5432")),
                os.environ.get("PGUSER", "mlscan"), os.environ.get("PGPASSWORD", ""),
                os.environ.get("PGDATABASE", "mlscan"), timeout=10)
        c.connect()
        return c
    except Exception:  # noqa: BLE001
        return None


def storage_metrics() -> list[str]:
    """Метрики PostgreSQL и Garage (Prometheus-совместимые строки)."""
    out: list[str] = []
    c = _pg()
    if c is None:
        out.append("mlscan_pg_up 0")
    else:
        try:
            _cols, rows = c.query("SELECT pg_database_size(current_database())")
            out.append(f"mlscan_pg_size_bytes {rows[0][0]}")
            for t in ("artifacts", "artifact_fingerprints", "scans", "findings",
                      "evidence", "uploads", "connections", "audit_log"):
                _c, r = c.query(f"SELECT count(*) FROM {t}")
                out.append(f'mlscan_pg_rows{{table="{t}"}} {r[0][0]}')
            _c, r = c.query("SELECT count(*) FROM evidence")
            out.append(f"mlscan_evidence_entries {r[0][0]}")
            out.append("mlscan_pg_up 1")
        except Exception:  # noqa: BLE001
            out.append("mlscan_pg_up 0")
        finally:
            c.close()
    # P1-6: целостность кода/конфигурации сервисов и качество покрытия вердиктов
    for name, url in (("analytics", ANALYTICS_URL), ("testing", TESTING_URL)):
        try:
            hz = get_json(url + "/healthz")
            val = 1 if hz.get("integrity", True) else 0
            out.append(f'mlscan_integrity_ok{{service="{name}"}} {val}')
            if hz.get("integrity") is False and name not in _integrity_bad:
                _integrity_bad.append(name)
        except Exception:  # noqa: BLE001
            pass
    try:
        ev = get_json(ANALYTICS_URL + "/api/evidence/verify")
        out.append("mlscan_evidence_ok %d" % (1 if ev.get("ok") else 0))
        out.append("mlscan_evidence_signed %d" % (1 if ev.get("signed") else 0))
        out.append("mlscan_evidence_entries %d" % int(ev.get("entries") or 0))
    except Exception:  # noqa: BLE001
        pass
    try:
        by = (get_json(ANALYTICS_URL + "/api/stats").get("by_verdict") or {})
        total = sum(by.values())
        incon = by.get("Inconclusive", 0)
        out.append(f"mlscan_scans_inconclusive_total {incon}")
        out.append(f"mlscan_scans_total {total}")
        out.append(f"mlscan_scans_inconclusive_ratio {(incon / max(1, total)):.4f}")
    except Exception:  # noqa: BLE001
        pass
    if GARAGE_ADMIN_URL:
        try:
            req = urllib.request.Request(GARAGE_ADMIN_URL.rstrip("/") + "/metrics",
                                         headers={"Authorization": f"Bearer {GARAGE_ADMIN_TOKEN}"})
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read().decode("utf-8", "replace")
            for line in body.splitlines():
                if line.startswith("garage_"):
                    out.append(line)
            out.append("mlscan_s3_up 1")
        except Exception:  # noqa: BLE001
            out.append("mlscan_s3_up 0")
    return out


def alerts(lang: str = "ru") -> list[dict]:
    """Простые проверки состояния хранилищ (без внешнего alertmanager)."""
    res: list[dict] = []
    c = _pg()
    if c is None:
        res.append({"id": "pg_down", "severity": "critical",
                    "summary": T("msg.alert_pg_down", lang)})
    else:
        try:
            _cols, rows = c.query("SELECT pg_database_size(current_database())")
            if int(rows[0][0]) > int(os.environ.get("PG_SIZE_ALERT_BYTES", str(2 * 1024**3))):
                res.append({"id": "pg_size_high", "severity": "warning",
                            "summary": T("msg.alert_db_size", lang, size=rows[0][0])})
        except Exception:  # noqa: BLE001
            pass
        finally:
            c.close()
    if GARAGE_ADMIN_URL:
        try:
            req = urllib.request.Request(GARAGE_ADMIN_URL.rstrip("/") + "/metrics",
                                         headers={"Authorization": f"Bearer {GARAGE_ADMIN_TOKEN}"})
            with urllib.request.urlopen(req, timeout=8) as r:
                r.read()
        except Exception:  # noqa: BLE001
            res.append({"id": "s3_down", "severity": "critical",
                        "summary": T("msg.alert_s3_down", lang)})
    try:
        ev = get_json(ANALYTICS_URL + "/api/evidence/verify")
        if not ev.get("ok"):
            res.append({"id": "evidence_broken", "severity": "critical",
                        "summary": T("msg.alert_evidence_broken", lang, ev=ev)})
    except Exception:  # noqa: BLE001
        res.append({"id": "evidence_unavailable", "severity": "warning",
                    "summary": T("msg.alert_evidence_unchecked", lang)})
    # P1-6: алерты по целостности кода/конфигурации и качеству покрытия
    for name in _integrity_bad:
        res.append({"id": "integrity_" + name, "severity": "critical",
                    "summary": "integrity of code/config of service " + name + " is violated"})
    try:
        by = (get_json(ANALYTICS_URL + "/api/stats").get("by_verdict") or {})
        total = sum(by.values())
        ratio = by.get("Inconclusive", 0) / max(1, total)
        if ratio > 0.2 and total > 20:
            res.append({"id": "coverage_low", "severity": "warning",
                        "summary": "share of incomplete scans (Inconclusive) is %.0f%%" % (ratio * 100)})
    except Exception:  # noqa: BLE001
        pass
    return res


def metrics_text() -> str:
    L = []
    health = stack_health()
    for name in ("analytics", "testing", "integrations"):
        L.append(f'mlscan_stack_up{{service="{name}"}} {1 if health[name]["up"] else 0}')
    try:
        scans = get_json(ANALYTICS_URL + "/api/scans").get("scans", [])
    except Exception:  # noqa: BLE001
        scans = []
    verdicts: dict[str, int] = {}
    for s in scans:
        verdicts[s.get("verdict") or "unknown"] = verdicts.get(s.get("verdict") or "unknown", 0) + 1
    for v, n in verdicts.items():
        L.append(f'mlscan_verdict_total{{verdict="{v}"}} {n}')
    try:
        L.append(f'mlscan_evidence_entries {get_json(ANALYTICS_URL + "/api/evidence/verify").get("entries", 0)}')
    except Exception:  # noqa: BLE001
        pass
    try:
        reg = get_json(INTEGRATIONS_URL + "/registry")
        L.append(f'mlscan_registry_entries {len(reg.get("entries", []))}')
    except Exception:  # noqa: BLE001
        pass
    try:
        events = []
        with urllib.request.urlopen(INTEGRATIONS_URL + "/events", timeout=10) as r:
            for line in r.read().decode().splitlines():
                if line.strip():
                    events.append(json.loads(line))
        dec: dict[str, int] = {}
        for e in events:
            dec[e.get("decision") or "unknown"] = dec.get(e.get("decision") or "unknown", 0) + 1
        for d, n in dec.items():
            L.append(f'mlscan_gate_total{{decision="{d}"}} {n}')
    except Exception:  # noqa: BLE001
        pass
    q = quality()
    for k in ("tpr", "fpr", "precision", "accuracy"):
        if q.get(k) is not None:
            L.append(f"mlscan_quality_{k} {q[k]:.4f}")
    L.append(f'mlscan_quality_samples {q.get("tp",0)+q.get("fp",0)+q.get("tn",0)+q.get("fn",0)}')
    L.append(f'mlscan_retest_runs_total {_state["retest_runs"]}')
    if _state["retest_last_ts"]:
        L.append(f'mlscan_retest_last_success_timestamp_seconds {_state["retest_last_ts"]}')
    L.extend(storage_metrics())
    return "\n".join(L) + "\n"


def background_retest() -> None:
    if RETEST_INTERVAL <= 0:
        return
    while True:
        try:
            retest()
        except Exception as exc:  # noqa: BLE001
            _state["retest_error"] = str(exc)[:200]
        time.sleep(RETEST_INTERVAL)


class Handler(BaseHTTPRequestHandler):
    server_version = "MLScanOps/0.5"

    def log_message(self, *a):
        pass

    def _lang(self, query: dict | None = None) -> str:
        """Язык запроса (RU/EN): ?lang= → cookie → X-MLScan-Lang → глобальная настройка."""
        if i18n is None:
            return "ru"
        raw = self.headers.get("Cookie", "") or ""
        cookie = ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "mlscan_lang":
                cookie = v
                break
        return i18n.resolve(headers=self.headers, query=query, cookie=cookie)

    def _require(self, allowed=None):
        if authz is None:
            return {"subject": "anonymous", "roles": ["admin"]}
        self._rid = authz.request_id(self.headers)
        ent = authz.authenticate(self.headers)
        if ent is None:
            ent = authz.from_cookie(self.headers)
        if ent is None:
            self._subject = "anonymous"
            self._json(401, {"error": T("msg.unauthorized", self._lang()),
                             "request_id": self._rid})
            return None
        allowed = allowed or ["admin", "ci-reader", "service"]
        if not (set(ent["roles"]) & set(allowed)):
            self._subject = ent["subject"]
            self._json(403, {"error": T("msg.forbidden", self._lang()),
                             "request_id": self._rid})
            return None
        self._subject = ent["subject"]
        return ent

    def _send(self, code, body: bytes, ctype="application/json; charset=utf-8"):
        rid = getattr(self, "_rid", None)
        if rid is None and authz is not None:
            rid = authz.new_request_id()
            self._rid = rid
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if rid:
            self.send_header("X-Request-ID", rid)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def do_GET(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        p = u.path
        if p == "/healthz":
            return self._json(200, {"status": "ok", "language": self._lang(q)})
        if self._require() is None:
            return
        lang = self._lang(q)
        if p == "/health/stack":
            h = stack_health()
            return self._json(200 if h["_overall"] else 503, h)
        if p == "/metrics":
            return self._send(200, metrics_text().encode(), "text/plain; version=0.0.4; charset=utf-8")
        if p == "/quality":
            return self._json(200, quality())
        if p == "/sla":
            return self._json(200, sla())
        if p == "/alerts":
            a = alerts(lang)
            return self._json(200, {"alerts": a, "count": len(a), "language": lang})
        if p == "/settings":
            return self._json(200, {"language": i18n.global_lang() if i18n else "ru",
                                    "startup_language": i18n.startup_lang() if i18n else "ru",
                                    "supported": list(i18n.SUPPORTED) if i18n else ["ru"],
                                    "request_language": lang})
        return self._json(404, {"error": T("msg.not_found", lang)})

    def do_POST(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        p = u.path
        ent = self._require()
        if ent is None:
            return
        lang = self._lang(q)
        if p == "/settings/language":
            # ГЛОБАЛЬНАЯ настройка языка всей системы (только администратор)
            if "admin" not in (ent.get("roles") or []):
                return self._json(403, {"error": T("msg.forbidden", lang)})
            n = int(self.headers.get("Content-Length", "0") or "0")
            form = urllib.parse.parse_qs(self.rfile.read(n).decode()) if n else {}
            code = (form.get("lang", [""])[0] or q.get("lang", [""])[0] or "").strip()
            applied = i18n.set_global_lang(code) if i18n else "ru"
            if authz is not None:
                try:
                    authz.audit(ent["subject"], "set_language", "settings", "language",
                                getattr(self, "_rid", ""), self.client_address[0], {"lang": applied})
                except Exception:  # noqa: BLE001
                    pass
            return self._json(200, {"language": applied,
                                    "startup_language": i18n.startup_lang() if i18n else "ru"})
        if p == "/retest":
            return self._json(200, retest())
        return self._json(404, {"error": T("msg.not_found", lang)})


def main() -> None:
    threading.Thread(target=background_retest, daemon=True).start()
    port = int(os.environ.get("PORT", "8080"))
    print(f"[ops] on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
