#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MLScan Testing Service (Этап 2 + доработка UI: потоковая загрузка и прогресс).

Компонента 2 архитектуры. Принимает артефакты ЛЮБОГО размера (потоковая запись на PVC),
запускает анализ в песочнице (Kata) и отдаёт прогресс/статистику. Только stdlib.

Транспорт артефакта: файл лежит на PVC сервиса (/artifacts/<scan_id>/<name>);
sandbox-Job скачивает его по одноразовому токенизированному URL с отдельного порта
(8090) — это единственное узкое исключение в сетевой политике (sandbox → testing:8090).

API (8080):
  POST /scans/upload?name=&fmt=   потоковая загрузка (Content-Length) -> 202 {scan_id}
  POST /scans                     совместимый алиас загрузки
  GET  /scans                     список (state/stage/progress/verdict/sha256/size)
  GET  /scans/<id>                запись целиком (стадии, находки, тайминги)
  GET  /stats                     агрегированная статистика (хэши/вердикты/объём)
  GET  /healthz

Artifact-сервер (8090):
  GET  /a/<scan_id>/<token>/<name>   отдача артефакта в песочницу (по токену)
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import threading
import time
import uuid
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, "/opt/mlscan")
import mlscan_poc  # noqa: E402

SANDBOX_NS = os.environ.get("SANDBOX_NS", "mlscan-sandbox")
DATA_DIR = os.environ.get("DATA_DIR", "/data")
ARTIFACTS_DIR = os.environ.get("ARTIFACTS_DIR", "/artifacts")
HARNESS_CM = os.environ.get("HARNESS_CM", "mlscan-harness")
JOB_TIMEOUT = int(os.environ.get("JOB_TIMEOUT", "600"))
ARTIFACT_PORT = int(os.environ.get("ARTIFACT_PORT", "8090"))
ARTIFACT_BASE = os.environ.get("ARTIFACT_BASE", "http://mlscan-testing.mlscan-testing.svc.cluster.local:8090")
MAX_UPLOAD = int(os.environ.get("MAX_UPLOAD", str(20 * 1024**3)))
JOB_MEMORY = os.environ.get("JOB_MEMORY", "2Gi")
JOB_EPHEMERAL = os.environ.get("JOB_EPHEMERAL", "8Gi")
TMP_SIZE = os.environ.get("TMP_SIZE", "6Gi")
SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", "python:3.12-slim")

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
K8S_HOST = os.environ.get("KUBERNETES_SERVICE_HOST", "")
K8S_PORT = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
_ssl_ctx = ssl.create_default_context(cafile=os.path.join(SA_DIR, "ca.crt"))
_token = open(os.path.join(SA_DIR, "token")).read().strip()

_lock = threading.Lock()


# ----------------------------------------------------------------------------
# Kubernetes API
# ----------------------------------------------------------------------------
def k8s(method: str, path: str, body: dict | None = None, expect_json: bool = True):
    conn = http.client.HTTPSConnection(K8S_HOST, int(K8S_PORT), context=_ssl_ctx, timeout=30)
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {_token}", "Accept": "application/json"}
    if data:
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    if resp.status >= 400:
        raise RuntimeError(f"k8s {method} {path} -> {resp.status}: {raw[:300]!r}")
    if not raw:
        return None
    return json.loads(raw) if expect_json else raw


# ----------------------------------------------------------------------------
# Хранилище записей
# ----------------------------------------------------------------------------
def store_dir() -> str:
    d = os.path.join(DATA_DIR, "scans")
    os.makedirs(d, exist_ok=True)
    return d


def save_scan(rec: dict) -> None:
    rec["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    tmp = os.path.join(store_dir(), rec["scan_id"] + ".json.tmp")
    with open(tmp, "w") as fh:
        json.dump(rec, fh, ensure_ascii=False)
    os.replace(tmp, os.path.join(store_dir(), rec["scan_id"] + ".json"))


def load_scan(scan_id: str) -> dict | None:
    if not re.fullmatch(r"[0-9a-f]{6,64}", scan_id or ""):
        return None
    p = os.path.join(store_dir(), scan_id + ".json")
    if not os.path.isfile(p):
        return None
    try:
        with open(p) as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return None


def update(scan_id: str, **fields) -> None:
    with _lock:
        rec = load_scan(scan_id)
        if not rec:
            return
        rec.update(fields)
        save_scan(rec)


def list_scans() -> list[dict]:
    out = []
    for fn in sorted(os.listdir(store_dir()), reverse=True):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(store_dir(), fn)) as fh:
                r = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        out.append({k: r.get(k) for k in ("scan_id", "name", "size", "sha256", "state",
                                          "stage", "progress", "verdict", "created", "updated")})
    return out


def stats() -> dict:
    scans = list_scans()
    by_state: dict[str, int] = {}
    by_verdict: dict[str, int] = {}
    total_bytes = 0
    hashes = set()
    for s in scans:
        by_state[s.get("state") or "?"] = by_state.get(s.get("state") or "?", 0) + 1
        if s.get("verdict"):
            by_verdict[s["verdict"]] = by_verdict.get(s["verdict"], 0) + 1
        total_bytes += int(s.get("size") or 0)
        if s.get("sha256"):
            hashes.add(s["sha256"])
    return {"scans": len(scans), "by_state": by_state, "by_verdict": by_verdict,
            "total_bytes": total_bytes, "distinct_sha256": len(hashes)}


# ----------------------------------------------------------------------------
# Песочница
# ----------------------------------------------------------------------------
def sandbox_job_manifest(job_name: str, scan_id: str, artifact_url: str, name: str, fmt: str) -> dict:
    cmd = ('python -c "import urllib.request,sys;urllib.request.urlretrieve(sys.argv[1],sys.argv[2])" '
           '"$ARTIFACT_URL" "/tmp/$MODEL_NAME" '
           '&& exec python /opt/mlscan/harness.py "$MODEL_FMT" "$MODEL_NAME" < "/tmp/$MODEL_NAME"')
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": job_name, "namespace": SANDBOX_NS,
                     "labels": {"app": "mlscan-sandbox", "mlscan.io/stage": "2"}},
        "spec": {
            "backoffLimit": 0, "ttlSecondsAfterFinished": 600,
            "template": {
                "metadata": {"labels": {"app": "mlscan-sandbox"}},
                "spec": {
                    "runtimeClassName": "kata",
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                        "runAsGroup": 65532, "fsGroup": 65532,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": "sandbox",
                        "image": SANDBOX_IMAGE, "imagePullPolicy": "IfNotPresent",
                        "command": ["/bin/sh", "-c", cmd],
                        "env": [{"name": "ARTIFACT_URL", "value": artifact_url},
                                {"name": "MODEL_NAME", "value": name},
                                {"name": "MODEL_FMT", "value": fmt},
                                {"name": "HOME", "value": "/deception"},
                                {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                                {"name": "PYTHONUTF8", "value": "1"},
                                {"name": "TMPDIR", "value": "/tmp"}],
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                        "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                                      "limits": {"cpu": "1", "memory": JOB_MEMORY,
                                                 "ephemeral-storage": JOB_EPHEMERAL}},
                        "volumeMounts": [
                            {"name": "harness", "mountPath": "/opt/mlscan", "readOnly": True},
                            {"name": "deception", "mountPath": "/deception", "readOnly": True},
                            {"name": "tmp", "mountPath": "/tmp"}],
                    }],
                    "volumes": [
                        {"name": "harness", "configMap": {"name": HARNESS_CM}},
                        {"name": "deception", "configMap": {"name": "mlscan-deception"}},
                        {"name": "tmp", "emptyDir": {"sizeLimit": TMP_SIZE}},
                    ],
                },
            },
        },
    }


def pod_for_job(job_name: str) -> str | None:
    sel = urllib.parse.quote(f"job-name={job_name}")
    data = k8s("GET", f"/api/v1/namespaces/{SANDBOX_NS}/pods?labelSelector={sel}")
    items = data.get("items", [])
    return items[0]["metadata"]["name"] if items else None


def wait_job(scan_id: str, job_name: str, timeout: int) -> tuple[str, bool]:
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = k8s("GET", f"/apis/batch/v1/namespaces/{SANDBOX_NS}/jobs/{job_name}")
        st = j.get("status", {})
        if st.get("succeeded"):
            return "succeeded", False
        if st.get("failed"):
            return "failed", False
        el = int(time.time() - t0)
        update(scan_id, stage="running", progress=min(85, 40 + el))
        time.sleep(2)
    return "timeout", True


def run_sandbox(scan_id: str, name: str, fmt: str, artifact_url: str) -> dict:
    job = f"mlscan-scan-{scan_id[:20]}"
    k8s("POST", f"/apis/batch/v1/namespaces/{SANDBOX_NS}/jobs",
        sandbox_job_manifest(job, scan_id, artifact_url, name, fmt))
    status, timed_out = wait_job(scan_id, job, JOB_TIMEOUT)
    result: dict = {"status": status, "timed_out": timed_out}
    pod = pod_for_job(job)
    if pod:
        try:
            logs = k8s("GET", f"/api/v1/namespaces/{SANDBOX_NS}/pods/{pod}/log?timestamps=false",
                       expect_json=False)
            if isinstance(logs, (bytes, bytearray)):
                logs = logs.decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            logs, result["log_error"] = "", str(exc)
        payload = None
        for line in (logs or "").splitlines():
            if line.startswith("MLSCAN_RESULT_JSON:"):
                payload = line[len("MLSCAN_RESULT_JSON:"):]
        if payload:
            try:
                result.update(json.loads(payload))
            except Exception as exc:  # noqa: BLE001
                result["parse_error"] = str(exc)
        result["stdout_tail"] = (logs or "")[-1200:]
    try:
        k8s("DELETE", f"/apis/batch/v1/namespaces/{SANDBOX_NS}/jobs/{job}?propagationPolicy=Background",
            expect_json=False)
    except Exception:  # noqa: BLE001
        pass
    return result


def normalize(scan_id: str, artifact_hash: str, static: dict, dynamic: dict) -> list[dict]:
    out: list[dict] = []
    for f in static.get("findings", []):
        out.append({"scan_id": scan_id, "artifact_hash": artifact_hash, "level": "L1",
                    "category": f["category"], "check_id": f["check_id"], "title": f["title"],
                    "severity": f["severity"], "confidence": f["confidence"],
                    "evidence": f.get("evidence", "")})
    for f in (dynamic.get("behavior") or {}).get("findings", []):
        out.append({"scan_id": scan_id, "artifact_hash": artifact_hash, "level": "L3",
                    "category": f["category"], "check_id": f["check_id"], "title": f["title"],
                    "severity": f["severity"], "confidence": f.get("confidence", 0.6),
                    "evidence": f.get("evidence", "")})
    return out


def process_scan(scan_id: str, name: str, fmt: str, path: str) -> None:
    timings = {}
    try:
        t = time.time()
        update(scan_id, state="running", stage="static", progress=10)
        static = mlscan_poc.static_stage(Path(path))
        timings["static_s"] = round(time.time() - t, 2)

        rec = load_scan(scan_id) or {}
        artifact_url = f"{ARTIFACT_BASE}/a/{scan_id}/{rec.get('artifact_token','')}/{urllib.parse.quote(name)}"
        update(scan_id, stage="submitted", progress=25)
        t = time.time()
        dynamic = run_sandbox(scan_id, name, fmt, artifact_url)
        timings["sandbox_s"] = round(time.time() - t, 2)

        update(scan_id, stage="collecting", progress=90)
        findings = normalize(scan_id, rec.get("sha256", ""), static, dynamic)
        verdict, reason = mlscan_poc.decide(static, dynamic)
        update(scan_id, state="done", stage="done", progress=100, verdict=verdict, reason=reason,
               findings=findings, static=static, sandbox=dynamic, timings=timings)
    except Exception as exc:  # noqa: BLE001
        update(scan_id, state="error", stage="error", progress=100, verdict="Inconclusive",
               reason=f"ошибка сервиса тестирования: {type(exc).__name__}: {exc}", timings=timings)


# ----------------------------------------------------------------------------
# Artifact-сервер (порт 8090) — отдача артефакта в песочницу по токену
# ----------------------------------------------------------------------------
class ArtifactHandler(BaseHTTPRequestHandler):
    server_version = "MLScanArtifacts/0.6"

    def log_message(self, *a):
        pass

    def do_GET(self) -> None:  # noqa: N802
        m = re.match(r"^/a/([0-9a-f]+)/([0-9a-f]+)/(.+)$", self.path)
        if not m:
            self.send_error(404)
            return
        scan_id, token, name = m.group(1), m.group(2), urllib.parse.unquote(m.group(3))
        rec = load_scan(scan_id)
        if not rec or rec.get("artifact_token") != token:
            self.send_error(403)
            return
        path = os.path.join(ARTIFACTS_DIR, scan_id, os.path.basename(name))
        if not os.path.isfile(path):
            self.send_error(404)
            return
        size = os.path.getsize(path)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                self.wfile.write(chunk)


# ----------------------------------------------------------------------------
# Основной API (порт 8080)
# ----------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "MLScanTesting/0.6"

    def log_message(self, *a):
        pass

    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        if u.path == "/healthz":
            return self._json(200, {"status": "ok", "sandbox_ns": SANDBOX_NS})
        if u.path == "/scans":
            return self._json(200, {"scans": list_scans()})
        if u.path == "/stats":
            return self._json(200, stats())
        if u.path.startswith("/scans/"):
            rec = load_scan(u.path.split("/", 2)[2])
            return self._json(200, rec) if rec else self._json(404, {"error": "not found"})
        return self._json(404, {"error": "not found"})

    def _receive_upload(self, query: dict) -> None:
        name = os.path.basename((query.get("name", ["sample.pkl"])[0]) or "sample.pkl")
        fmt = query.get("fmt", ["pickle"])[0]
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return self._json(400, {"error": "empty body (требуется Content-Length)"})
        if n > MAX_UPLOAD:
            return self._json(413, {"error": f"artifact too large ({n} > {MAX_UPLOAD})"})
        scan_id = uuid.uuid4().hex
        d = os.path.join(ARTIFACTS_DIR, scan_id)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, name)
        h = hashlib.sha256()
        got = 0
        with open(path, "wb") as fh:
            while got < n:
                chunk = self.rfile.read(min(1 << 20, n - got))
                if not chunk:
                    break
                fh.write(chunk)
                h.update(chunk)
                got += len(chunk)
        token = uuid.uuid4().hex
        rec = {"scan_id": scan_id, "name": name, "format": fmt, "size": got,
               "sha256": h.hexdigest(), "artifact_token": token,
               "state": "queued", "stage": "queued", "progress": 0,
               "created": time.strftime("%Y-%m-%dT%H:%M:%S")}
        save_scan(rec)
        threading.Thread(target=process_scan, args=(scan_id, name, fmt, path), daemon=True).start()
        return self._json(202, {"scan_id": scan_id, "state": "queued", "size": got,
                                "sha256": h.hexdigest()})

    def do_POST(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path in ("/scans", "/scans/upload", "/upload"):
            return self._receive_upload(q)
        return self._json(404, {"error": "not found"})


def main() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    threading.Thread(target=lambda: ThreadingHTTPServer(("0.0.0.0", ARTIFACT_PORT),
                                                        ArtifactHandler).serve_forever(),
                     daemon=True).start()
    port = int(os.environ.get("PORT", "8080"))
    print(f"[testing] api :{port}, artifacts :{ARTIFACT_PORT}, artifacts_dir={ARTIFACTS_DIR}",
          flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
