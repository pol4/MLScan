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
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def post_bytes(url, data, timeout=90):
    req = urllib.request.Request(url, data=data, method="POST")
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
    files = sorted(glob.glob(os.path.join(SAMPLES_DIR, "*.pkl")))
    started = time.time()
    submitted = []
    for f in files:
        name = os.path.basename(f)
        try:
            with open(f, "rb") as fh:
                data = fh.read()
            r = post_bytes(f"{TESTING_URL}/scans?name={name}&fmt=pickle", data)
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
    return {"submitted": len(submitted), "files": [n for n, _ in submitted],
            "elapsed_s": round(time.time() - started, 1), "sync": sync}


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

    def _send(self, code, body: bytes, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def do_GET(self) -> None:  # noqa: N802
        p = self.path.split("?")[0]
        if p == "/healthz":
            return self._json(200, {"status": "ok"})
        if p == "/health/stack":
            h = stack_health()
            return self._json(200 if h["_overall"] else 503, h)
        if p == "/metrics":
            return self._send(200, metrics_text().encode(), "text/plain; version=0.0.4; charset=utf-8")
        if p == "/quality":
            return self._json(200, quality())
        if p == "/sla":
            return self._json(200, sla())
        return self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        p = self.path.split("?")[0]
        if p == "/retest":
            return self._json(200, retest())
        return self._json(404, {"error": "not found"})


def main() -> None:
    threading.Thread(target=background_retest, daemon=True).start()
    port = int(os.environ.get("PORT", "8080"))
    print(f"[ops] on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
