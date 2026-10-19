#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MLScan Testing Service (Этап 2).

Компонента 2 архитектуры: принимает артефакты, запускает их анализ в песочнице
(Этап 1, namespace mlscan-sandbox, Kata), собирает и нормализует результаты,
выдаёт вердикт. Реализовано только на стандартной библиотеке (без внешних зависимостей).

Переиспользует анализ из PoC (`mlscan_poc.py`): статический разбор L1 и `decide()`.

API (HTTP):
  POST /scans?name=<file>&fmt=<fmt>   тело = байты артефакта -> {"scan_id": "..."}
  GET  /scans                         список сканов
  GET  /scans/<id>                    результат скана (нормализованные находки + вердикт)
  GET  /healthz                       проверка живости

Окружение: Kubernetes (in-cluster SA), доступ к API для создания ConfigMap/Job
в namespace песочницы и чтения логов пода.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import ssl
import sys
import threading
import time
import uuid
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, "/opt/mlscan")           # mlscan_poc.py смонтирован сюда
try:
    import mlscan_poc  # noqa: E402  (общий анализ: static_stage, decide, SEV_RANK)
except Exception as exc:  # noqa: BLE001
    print("FATAL: cannot import mlscan_poc:", exc, file=sys.stderr)
    raise

SANDBOX_NS = os.environ.get("SANDBOX_NS", "mlscan-sandbox")
DATA_DIR = os.environ.get("DATA_DIR", "/data")
HARNESS_CM = os.environ.get("HARNESS_CM", "mlscan-harness")
JOB_TIMEOUT = int(os.environ.get("JOB_TIMEOUT", "240"))
MAX_ARTIFACT = 900 * 1024                    # лимит ConfigMap (1MiB)

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
K8S_HOST = os.environ.get("KUBERNETES_SERVICE_HOST", "")
K8S_PORT = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")

_ssl_ctx = ssl.create_default_context(cafile=os.path.join(SA_DIR, "ca.crt"))
_token = open(os.path.join(SA_DIR, "token")).read().strip()


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


def create_artifact_cm(name: str, filename: str, data: bytes) -> None:
    body = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": SANDBOX_NS,
                     "labels": {"app": "mlscan-artifact", "mlscan.io/stage": "2"}},
        "binaryData": {filename: base64.b64encode(data).decode()},
    }
    k8s("POST", f"/api/v1/namespaces/{SANDBOX_NS}/configmaps", body)


def delete_cm(name: str) -> None:
    try:
        k8s("DELETE", f"/api/v1/namespaces/{SANDBOX_NS}/configmaps/{name}", expect_json=False)
    except Exception:  # noqa: BLE001
        pass


def sandbox_job_manifest(job_name: str, artifact_cm: str, filename: str, fmt: str) -> dict:
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": job_name, "namespace": SANDBOX_NS,
                     "labels": {"app": "mlscan-sandbox", "mlscan.io/stage": "2"}},
        "spec": {
            "backoffLimit": 0, "ttlSecondsAfterFinished": 300,
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
                        "image": "python:3.12-slim", "imagePullPolicy": "IfNotPresent",
                        "command": ["/bin/sh", "-c",
                                    'exec python /opt/mlscan/harness.py "$MODEL_FMT" '
                                    '"$(basename "$MODEL_FILE")" < "$MODEL_FILE"'],
                        "env": [{"name": "MODEL_FILE", "value": f"/scan/{filename}"},
                                {"name": "MODEL_FMT", "value": fmt},
                                {"name": "HOME", "value": "/deception"},
                                {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                                {"name": "PYTHONUTF8", "value": "1"},
                                {"name": "TMPDIR", "value": "/tmp"}],
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                        "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                                      "limits": {"cpu": "1", "memory": "512Mi",
                                                 "ephemeral-storage": "256Mi"}},
                        "volumeMounts": [
                            {"name": "harness", "mountPath": "/opt/mlscan", "readOnly": True},
                            {"name": "artifact", "mountPath": "/scan", "readOnly": True},
                            {"name": "deception", "mountPath": "/deception", "readOnly": True},
                            {"name": "tmp", "mountPath": "/tmp"}],
                    }],
                    "volumes": [
                        {"name": "harness", "configMap": {"name": HARNESS_CM}},
                        {"name": "artifact", "configMap": {"name": artifact_cm}},
                        {"name": "deception", "configMap": {"name": "mlscan-deception"}},
                        {"name": "tmp", "emptyDir": {"sizeLimit": "128Mi", "medium": "Memory"}},
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


def wait_job(job_name: str, timeout: int) -> tuple[str, bool]:
    """Возвращает (status, timed_out)."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = k8s("GET", f"/apis/batch/v1/namespaces/{SANDBOX_NS}/jobs/{job_name}")
        st = j.get("status", {})
        if st.get("succeeded"):
            return "succeeded", False
        if st.get("failed"):
            return "failed", False
        time.sleep(2)
    return "timeout", True


def run_sandbox(scan_id: str, filename: str, fmt: str, data: bytes) -> dict:
    cm = f"mlscan-art-{scan_id[:20]}"
    job = f"mlscan-scan-{scan_id[:20]}"
    create_artifact_cm(cm, filename, data)
    k8s("POST", f"/apis/batch/v1/namespaces/{SANDBOX_NS}/jobs",
        sandbox_job_manifest(job, cm, filename, fmt))
    status, timed_out = wait_job(job, JOB_TIMEOUT)
    result: dict = {"status": status, "timed_out": timed_out, "exit_code": None}
    pod = pod_for_job(job)
    if pod:
        try:
            logs = k8s("GET",
                       f"/api/v1/namespaces/{SANDBOX_NS}/pods/{pod}/log?timestamps=false",
                       expect_json=False)
            if isinstance(logs, (bytes, bytearray)):
                logs = logs.decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            logs = ""
            result["log_error"] = str(exc)
        payload = None
        for line in (logs or "").splitlines():
            if line.startswith("MLSCAN_RESULT_JSON:"):
                payload = line[len("MLSCAN_RESULT_JSON:"):]
        if payload:
            try:
                result.update(json.loads(payload))
            except Exception as exc:  # noqa: BLE001
                result["parse_error"] = str(exc)
        result["stdout_tail"] = (logs or "")[-1500:]
    # уборка
    try:
        k8s("DELETE", f"/apis/batch/v1/namespaces/{SANDBOX_NS}/jobs/{job}"
            "?propagationPolicy=Background", expect_json=False)
    except Exception:  # noqa: BLE001
        pass
    delete_cm(cm)
    return result


def normalize(scan_id: str, artifact_hash: str, static: dict, dynamic: dict) -> list[dict]:
    out: list[dict] = []
    for f in static.get("findings", []):
        out.append({"scan_id": scan_id, "artifact_hash": artifact_hash, "level": "L1",
                    "category": f["category"], "check_id": f["check_id"], "title": f["title"],
                    "severity": f["severity"], "confidence": f["confidence"],
                    "evidence": f.get("evidence", "")})
    beh = dynamic.get("behavior") or {}
    for f in beh.get("findings", []):
        out.append({"scan_id": scan_id, "artifact_hash": artifact_hash, "level": "L3",
                    "category": f["category"], "check_id": f["check_id"], "title": f["title"],
                    "severity": f["severity"], "confidence": f.get("confidence", 0.6),
                    "evidence": f.get("evidence", "")})
    return out


def store_dir() -> str:
    d = os.path.join(DATA_DIR, "scans")
    os.makedirs(d, exist_ok=True)
    return d


def save_scan(rec: dict) -> None:
    with open(os.path.join(store_dir(), rec["scan_id"] + ".json"), "w") as fh:
        json.dump(rec, fh, ensure_ascii=False)


def load_scan(scan_id: str) -> dict | None:
    p = os.path.join(store_dir(), scan_id + ".json")
    if not os.path.isfile(p):
        return None
    with open(p) as fh:
        return json.load(fh)


def list_scans() -> list[dict]:
    out = []
    for fn in sorted(os.listdir(store_dir()), reverse=True):
        if fn.endswith(".json"):
            try:
                with open(os.path.join(store_dir(), fn)) as fh:
                    r = json.load(fh)
                out.append({"scan_id": r["scan_id"], "name": r.get("name"),
                            "verdict": r.get("verdict"), "created": r.get("created")})
            except Exception:  # noqa: BLE001
                pass
    return out


def process_scan(scan_id: str, filename: str, fmt: str, data: bytes) -> None:
    rec = {"scan_id": scan_id, "name": filename, "format": fmt,
           "sha256": hashlib.sha256(data).hexdigest(), "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "state": "running"}
    save_scan(rec)
    try:
        # L1 — статика (безопасно, в самом сервисе)
        import tempfile
        with tempfile.NamedTemporaryFile(suffix="_" + filename, delete=False) as tf:
            tf.write(data)
            tmp = tf.name
        try:
            static = mlscan_poc.static_stage(__import__("pathlib").Path(tmp))
        finally:
            os.unlink(tmp)
        # L2/L3 — в песочнице
        dynamic = run_sandbox(scan_id, filename, fmt, data)
        # нормализация и вердикт
        findings = normalize(scan_id, rec["sha256"], static, dynamic)
        verdict, reason = mlscan_poc.decide(static, dynamic)
        rec.update({"state": "done", "verdict": verdict, "reason": reason,
                    "findings": findings, "static": static, "sandbox": dynamic})
    except Exception as exc:  # noqa: BLE001
        rec.update({"state": "error", "error": f"{type(exc).__name__}: {exc}",
                    "verdict": "Inconclusive", "reason": "ошибка сервиса тестирования"})
    save_scan(rec)


class Handler(BaseHTTPRequestHandler):
    server_version = "MLScanTesting/0.2"

    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # тише в логах
        pass

    def do_GET(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        if u.path == "/healthz":
            return self._json(200, {"status": "ok", "sandbox_ns": SANDBOX_NS})
        if u.path == "/scans":
            return self._json(200, {"scans": list_scans()})
        if u.path.startswith("/scans/"):
            scan_id = u.path.split("/", 2)[2]
            rec = load_scan(scan_id)
            if not rec:
                return self._json(404, {"error": "not found"})
            return self._json(200, rec)
        return self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        if u.path != "/scans":
            return self._json(404, {"error": "not found"})
        q = urllib.parse.parse_qs(u.query)
        name = (q.get("name", ["sample.pkl"])[0]) or "sample.pkl"
        fmt = q.get("fmt", ["pickle"])[0]
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return self._json(400, {"error": "empty body"})
        if n > MAX_ARTIFACT:
            return self._json(413, {"error": f"artifact too large ({n} > {MAX_ARTIFACT}); "
                                             "используйте PVC-транспорт (Этап 3+)"})
        data = self.rfile.read(n)
        scan_id = uuid.uuid4().hex
        threading.Thread(target=process_scan, args=(scan_id, name, fmt, data), daemon=True).start()
        return self._json(202, {"scan_id": scan_id, "state": "running"})


def main() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    port = int(os.environ.get("PORT", "8080"))
    print(f"[testing] MLScan Testing Service on :{port}, sandbox_ns={SANDBOX_NS}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
