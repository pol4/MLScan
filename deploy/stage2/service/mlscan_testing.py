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
import secrets
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
DATA_TMP = os.environ.get("DATA_TMP", "/var/tmp")
S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "")
S3_ENABLED = bool(S3_ENDPOINT)
_s3 = None
if S3_ENABLED:
    sys.path.insert(0, "/opt/s3")
    from s3client import S3  # noqa: E402
    _s3 = S3(S3_ENDPOINT, os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
             region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=3600,
             public_endpoint=os.environ.get("S3_PUBLIC_ENDPOINT", ""))

# Multipart-загрузка в S3 (этап P0-1, docs/15 §11.6): объекты ≥ порога грузятся
# параллельными частями вместо одиночного PUT (снимает одно-поточный потолок).
S3_MULTIPART_THRESHOLD = int(os.environ.get("S3_MULTIPART_THRESHOLD", str(64 * 1024 ** 2)))
S3_PART_SIZE = int(os.environ.get("S3_PART_SIZE", str(64 * 1024 ** 2)))
S3_PART_WORKERS = int(os.environ.get("S3_PART_WORKERS", "8"))

# Прямая presigned-multipart загрузка клиентом в Garage (этап P0-2, docs/15 §11.6):
# клиент (браузер/aws-cli/rclone/CI) грузит объект напрямую в S3 в партицию
# tenant/<субъект>/, минуя сервис тестирования (он выдаёт presigned-URL и регистрирует объект).
DIRECT_PART_SIZE = int(os.environ.get("DIRECT_PART_SIZE", str(128 * 1024 ** 2)))
DIRECT_URL_TTL = int(os.environ.get("DIRECT_URL_TTL", "3600"))
DIRECT_MATERIALIZE_MAX = int(os.environ.get("DIRECT_MATERIALIZE_MAX", str(4 * 1024 ** 3)))
_pending_uploads: dict = {}
_pending_lock = threading.Lock()

# --- PostgreSQL (dual-write; не критично для работы сервиса) ---
PG_HOST = os.environ.get("PGHOST", "")
DB_ENABLED = bool(PG_HOST)
_Pg = None
if DB_ENABLED:
    sys.path.insert(0, "/opt/pg")
    from pgclient import Pg as _Pg  # noqa: E402


def _lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def db_exec(sql: str) -> None:
    if not DB_ENABLED or _Pg is None:
        return
    try:
        c = _Pg(PG_HOST, int(os.environ.get("PGPORT", "5432")),
                os.environ.get("PGUSER", "mlscan"), os.environ.get("PGPASSWORD", ""),
                os.environ.get("PGDATABASE", "mlscan"), timeout=15)
        c.connect()
        c.query(sql)
        c.close()
    except Exception as exc:  # noqa: BLE001
        print(f"[db] {type(exc).__name__}: {exc} | SQL: {sql[:160]}", file=sys.stderr)
def db_query(sql: str):
    """Читающий запрос к PostgreSQL: список кортежей или None (БД недоступна)."""
    if not DB_ENABLED or _Pg is None:
        return None
    try:
        c = _Pg(PG_HOST, int(os.environ.get("PGPORT", "5432")),
                os.environ.get("PGUSER", "mlscan"), os.environ.get("PGPASSWORD", ""),
                os.environ.get("PGDATABASE", "mlscan"), timeout=30)
        c.connect()
        _cols, rows = c.query(sql)
        c.close()
        return rows
    except Exception as exc:  # noqa: BLE001
        print(f"[db] query {type(exc).__name__}: {exc}", file=sys.stderr)
        return None


MAX_UPLOAD = int(os.environ.get("MAX_UPLOAD", str(20 * 1024**3)))
JOB_MEMORY = os.environ.get("JOB_MEMORY", "2Gi")
JOB_EPHEMERAL = os.environ.get("JOB_EPHEMERAL", "8Gi")
TMP_SIZE = os.environ.get("TMP_SIZE", "6Gi")
SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", "python:3.12-slim")

sys.path.insert(0, "/opt/formats")
try:
    import detector as format_adapter  # noqa: E402
except Exception:  # noqa: BLE001
    format_adapter = None  # type: ignore

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


def TR(text, lang: str = "ru"):
    return i18n.tr(text, lang) if i18n else text

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
K8S_HOST = os.environ.get("KUBERNETES_SERVICE_HOST", "")
K8S_PORT = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
_ssl_ctx = ssl.create_default_context(cafile=os.path.join(SA_DIR, "ca.crt"))
_token = open(os.path.join(SA_DIR, "token")).read().strip()

_lock = threading.RLock()   # реентерабельный: update() держит _lock и вызывает save_scan()

# Кэш списка сканов: чтение тысяч JSON-файлов на каждый запрос дорого (дашборд опрашивает
# /scans и /stats часто). TTL 5 с; сбрасывается при сохранении нового скана.
_scans_cache: dict = {"ts": 0.0, "data": None}
_SCANS_TTL = 30.0   # кэш списка сканов; сбрасывается при записи (save_scan)


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
    _invalidate_scans_cache()


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
    # прогресс скана зеркалируется в PostgreSQL, чтобы список/статистика читались из БД
    # (вне _lock: сетевой ввод-вывод не должен блокировать остальные операции)
    sets = []
    if "state" in fields:
        sets.append(f"status={_lit(fields['state'])}")
    if "stage" in fields:
        sets.append(f"stage={_lit(fields['stage'])}")
    if "progress" in fields:
        sets.append(f"progress={int(fields['progress'])}")
    if sets:
        db_exec(f"UPDATE scans SET {', '.join(sets)} WHERE scan_id={_lit(scan_id)}")


def _invalidate_scans_cache() -> None:
    with _lock:
        _scans_cache["data"] = None
        _scans_cache["ts"] = 0.0


_LIST_SQL = (
    "SELECT s.scan_id, a.filename, a.size, a.sha256, s.status, s.stage, s.progress, s.verdict, "
    "to_char(s.created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS'), "
    "to_char(COALESCE(s.finished_at, s.created_at), 'YYYY-MM-DD\"T\"HH24:MI:SS') "
    "FROM scans s LEFT JOIN artifacts a ON a.id = s.artifact_id "
    "ORDER BY s.created_at DESC")


def list_scans() -> list[dict]:
    # Основной путь — PostgreSQL (метаданные сканов и артефактов), без чтения тысяч файлов.
    rows = db_query(_LIST_SQL)
    if rows:
        keys = ("scan_id", "name", "size", "sha256", "state", "stage", "progress",
                "verdict", "created", "updated")
        return [dict(zip(keys, r)) for r in rows]
    # Фолбэк (БД недоступна): файлы /data/scans/*.json
    now = time.time()
    with _lock:
        cached = _scans_cache["data"]
        fresh = cached is not None and (now - _scans_cache["ts"]) < _SCANS_TTL
    if fresh:
        return cached
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
    with _lock:
        _scans_cache["data"] = out
        _scans_cache["ts"] = time.time()
    return out


def stats() -> dict:
    rows = db_query("SELECT s.status, s.verdict, a.size, a.sha256 "
                    "FROM scans s LEFT JOIN artifacts a ON a.id = s.artifact_id")
    if rows is not None:
        by_state: dict[str, int] = {}
        by_verdict: dict[str, int] = {}
        total_bytes = 0
        hashes = set()
        for status, verdict, size, sha in rows:
            by_state[status or "?"] = by_state.get(status or "?", 0) + 1
            if verdict:
                by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
            total_bytes += int(size or 0)
            if sha:
                hashes.add(sha)
        return {"scans": len(rows), "by_state": by_state, "by_verdict": by_verdict,
                "total_bytes": total_bytes, "distinct_sha256": len(hashes)}
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
def sandbox_job_manifest(job_name: str, scan_id: str, artifact_url: str, name: str, fmt: str, nonce: str = "") -> dict:
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
                                {"name": "TMPDIR", "value": "/tmp"},
                                {"name": "MLSCAN_NONCE", "value": nonce}],
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
    # Нонс результата: harness печатает маркеры со своим нонсом, сервис принимает только их
    # (payload не может подделать «чистый» результат, напечатав свою строку — см. docs/14, P0-1).
    nonce = secrets.token_hex(8)
    job = f"mlscan-scan-{scan_id[:20]}"
    k8s("POST", f"/apis/batch/v1/namespaces/{SANDBOX_NS}/jobs",
        sandbox_job_manifest(job, scan_id, artifact_url, name, fmt, nonce))
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
        summary_raw = None
        res_prefix = "MLSCAN_RESULT_JSON:" + nonce + ":"
        sum_prefix = "MLSCAN_SUMMARY:" + nonce + ":"
        forged = 0
        for line in (logs or "").splitlines():
            if line.startswith("MLSCAN_RESULT_JSON:"):
                if line.startswith(res_prefix):
                    payload = line[len(res_prefix):]
                else:
                    forged += 1                      # маркер без нашего нонса — попытка подмены
            elif line.startswith("MLSCAN_SUMMARY:"):
                if line.startswith(sum_prefix):
                    summary_raw = line[len(sum_prefix):]
                else:
                    forged += 1
        if forged:
            result.setdefault("errors", []).append(
                f"обнаружен результат без нонса скана ({forged} стр.) — возможна попытка подделки")
        if payload and summary_raw:
            try:
                sm = json.loads(summary_raw)
                load_ok = (result.get("load") or {}).get("ok")
                # сверяем только стабильные признаки: формат и факт загрузки
                if (sm.get("format") and result.get("format") and sm["format"] != result["format"]) or \
                        (sm.get("load_ok") is not None and load_ok is not None
                         and bool(sm["load_ok"]) != bool(load_ok)):
                    result.setdefault("errors", []).append("несоответствие summary и результата песочницы")
                    result["status"] = "failed"
            except Exception:  # noqa: BLE001
                result.setdefault("errors", []).append("нечитаемый MLSCAN_SUMMARY")
        elif summary_raw and not payload:
            # summary есть, результата со своим нонсом нет — считать динамику неуспешной
            result.setdefault("errors", []).append("результат песочницы не получен (есть только summary)")
            result["status"] = "failed"
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
        if format_adapter is not None and "adapter_format" not in static:
            # PoC (mlscan_poc.static_stage) уже применяет тот же адаптер форматов,
            # поэтому повторный вызов нужен только если он недоступен
            try:
                fa = format_adapter.static_scan(Path(path))
                if fa.get("findings"):
                    static.setdefault("findings", []).extend(fa["findings"])
                if fa.get("format"):
                    static["adapter_format"] = fa["format"]
                    if fa["format"] != "pickle":
                        static["format"] = fa["format"]
            except Exception as exc:  # noqa: BLE001
                static.setdefault("findings", []).append(
                    {"check_id": "FMT-00", "category": "FMT", "title": "Ошибка адаптера формата",
                     "severity": "low", "confidence": 0.3, "evidence": str(exc)})
        timings["static_s"] = round(time.time() - t, 2)
        if S3_ENABLED:                      # локальная копия нужна была только для L1
            try:
                os.unlink(path)
            except OSError:
                pass

        rec = load_scan(scan_id) or {}
        artifact_url = f"{ARTIFACT_BASE}/a/{scan_id}/{rec.get('artifact_token','')}/{urllib.parse.quote(name)}"
        sandbox_fmt = fmt
        af = (static or {}).get("adapter_format")
        # Формат песочницы = формат адаптера: harness умеет загружать не только pickle,
        # но и safetensors/onnx/hdf5/keras/gguf/архивы/текстовые артефакты (mmap/парсеры),
        # поэтому динамика не «не применима», а реально проверяется.
        if af in ("torchserve-mar", "model-as-code", "python"):
            sandbox_fmt = "model-as-code"
        elif af in ("safetensors", "onnx", "hdf5", "keras", "gguf", "tar", "zip",
                    "config", "card", "xml", "yaml", "tokenizer", "image", "pmml",
                    "notebook", "script", "dataset", "tflite", "coreml",
                    "mlflow", "savedmodel", "jinja", "native", "sitepath",
                    "html", "dockerfile", "jsonl", "csv", "msgpack",
                    "compressed", "unsupported"):
            sandbox_fmt = af
        elif af in ("torch-package", "torch-zip"):
            sandbox_fmt = "zip"
        elif af in ("unknown", None):
            sandbox_fmt = "raw"
        update(scan_id, stage="submitted", progress=25, sandbox_fmt=sandbox_fmt)
        t = time.time()
        dynamic = run_sandbox(scan_id, name, sandbox_fmt, artifact_url)
        timings["sandbox_s"] = round(time.time() - t, 2)

        update(scan_id, stage="collecting", progress=90)
        findings = normalize(scan_id, rec.get("sha256", ""), static, dynamic)
        findings, _truncated = cap_findings(findings)
        verdict, reason = mlscan_poc.decide(static, dynamic)
        if _truncated:
            reason = f"{reason}; показаны первые {MAX_FINDINGS} находок из {MAX_FINDINGS + _truncated}"
            print(f"[testing] {scan_id}: находок больше лимита, усечено {_truncated}", file=sys.stderr)
        # полнота покрытия: какие модули реально отработали (см. poc.coverage_of)
        coverage = mlscan_poc.coverage_of(static, dynamic)
        if not coverage.get("complete"):
            print(f"[testing] {scan_id}: неполное покрытие — {coverage.get('failed')}", file=sys.stderr)
        update(scan_id, state="done", stage="done", progress=100, verdict=verdict, reason=reason,
               findings=findings, static=static, sandbox=dynamic, timings=timings,
               coverage=coverage)
        if DB_ENABLED:
            import json as _json
            db_exec("INSERT INTO scans(scan_id,status,stage,progress,verdict,reason,timings,finished_at) VALUES "
                    f"({_lit(scan_id)},'done','done',100,{_lit(verdict)},{_lit(reason)},"
                    f"{_lit(_json.dumps(timings, ensure_ascii=False))},now()) "
                    "ON CONFLICT (scan_id) DO UPDATE SET status=EXCLUDED.status, verdict=EXCLUDED.verdict, "
                    "reason=EXCLUDED.reason, timings=EXCLUDED.timings, finished_at=now()")
            for f in findings:
                ev = f.get("evidence")
                ev_sql = "NULL" if ev is None else _lit(_json.dumps(ev, ensure_ascii=False))
                db_exec("INSERT INTO findings(scan_id,level,check_id,category,severity,confidence,title,evidence) VALUES "
                        f"({_lit(scan_id)},{_lit(f.get('level'))},{_lit(f.get('check_id'))},{_lit(f.get('category'))},"
                        f"{_lit(f.get('severity'))},{f.get('confidence') if f.get('confidence') is not None else 'NULL'},"
                        f"{_lit(f.get('title'))},{ev_sql})")
    except Exception as exc:  # noqa: BLE001
        import traceback
        print(f"[testing] scan {scan_id} failed on stage={timings.get('stage', '?')}: "
              f"{type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        detail = f"{type(exc).__name__}: {exc}"
        update(scan_id, state="error", stage="error", progress=100, verdict="Inconclusive",
               reason=f"ошибка сервиса тестирования: {detail}", timings=timings,
               coverage={"complete": False, "failed": ["static", "dynamic", "behavior"],
                         "modules": {m: {"ok": False, "reason": f"ошибка сервиса тестирования: {detail}"}
                                     for m in ("static", "dynamic", "behavior")}})


def _materialize_and_scan(scan_id: str, name: str, fmt: str, key: str, size: int) -> None:
    """Прямая загрузка (P0-2): при размере в пределах лимита — локальная копия и
    обычный анализ; иначе (ТБ-объекты) — честный Inconclusive до потокового анализа (P1-6)."""
    if size <= DIRECT_MATERIALIZE_MAX:
        tmp = os.path.join(DATA_TMP, "up-" + scan_id + "-" + name)
        try:
            os.makedirs(DATA_TMP, exist_ok=True)
            st, hd, resp = _s3.get_stream(key)
            if st != 200:
                raise RuntimeError(f"get_stream {st}")
            with open(tmp, "wb") as fh:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    fh.write(chunk)
            process_scan(scan_id, name, fmt, tmp)
            return
        except Exception as exc:  # noqa: BLE001
            print(f"[testing] {scan_id}: материализация не удалась: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
    update(scan_id, state="done", stage="done", progress=100, verdict="Inconclusive",
           reason="объект больше лимита локальной материализации — анализ будет потоковым (P1-6)",
           coverage={"complete": False, "failed": ["static", "dynamic", "behavior"],
                     "modules": {m: {"ok": False, "reason": "ожидает потокового анализа (P1-6)"}
                                 for m in ("static", "dynamic", "behavior")}})


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
        if rec.get("s3_key") and _s3 is not None:
            try:
                st, hd, resp = _s3.get_stream(rec["s3_key"])
            except Exception:  # noqa: BLE001
                self.send_error(502)
                return
            if st != 200:
                self.send_error(st)
                return
            self.send_response(200)
            cl = hd.get("Content-Length")
            if cl:
                self.send_header("Content-Length", cl)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                self.wfile.write(chunk)
            return
        path = rec.get("local_path") or os.path.join(ARTIFACTS_DIR, scan_id, os.path.basename(name))
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

    def _require(self):
        if authz is None:
            return {"subject": "anonymous"}
        self._rid = authz.request_id(self.headers)
        ent = authz.authenticate(self.headers)
        if ent is None:
            self._subject = "anonymous"
            try:
                authz.audit("anonymous", "auth_denied", "http", self.path, self._rid,
                            self.client_address[0], {"method": self.command})
            except Exception:  # noqa: BLE001
                pass
            self._json(401, {"error": T("msg.unauthorized", self._lang()),
                             "request_id": self._rid})
            return None
        self._subject = ent["subject"]
        return ent

    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        rid = getattr(self, "_rid", None)
        if rid is None and authz is not None:
            rid = authz.new_request_id()
            self._rid = rid
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if rid:
            self.send_header("X-Request-ID", rid)
        self.end_headers()
        self.wfile.write(body)
        if authz is not None and not getattr(self, "_logged", False):
            self._logged = True
            try:
                authz.log_connection(getattr(self, "_subject", "anonymous"), rid,
                                     self.client_address[0], self.headers.get("User-Agent", ""),
                                     self.path, self.command, code)
            except Exception:  # noqa: BLE001
                pass

    def do_GET(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/healthz":
            lang = self._lang(q)
            return self._json(200, {"status": "ok" if INTEGRITY_OK else "degraded", "sandbox_ns": SANDBOX_NS,
                                    "language": lang, "integrity": INTEGRITY_OK, "expected_digest": INTEGRITY_ENV,
                                    "actual_digest": INTEGRITY_DIGEST})
        if self._require() is None:
            return
        lang = self._lang(q)
        if u.path == "/scans":
            return self._json(200, {"scans": list_scans(), "language": lang})
        if u.path == "/stats":
            return self._json(200, stats())
        if u.path.startswith("/scans/"):
            rec = load_scan(u.path.split("/", 2)[2])
            if not rec:
                return self._json(404, {"error": T("msg.not_found", lang)})
            # сообщения отдаются на выбранном языке (находки/причина — по правилам i18n)
            if i18n is not None and lang != "ru":
                rec = dict(rec)
                rec["findings"] = i18n.localize_findings(rec.get("findings", []), lang)
                if rec.get("reason"):
                    rec["reason"] = TR(rec["reason"], lang)
                rec["language"] = lang
            return self._json(200, rec)
        return self._json(404, {"error": T("msg.not_found", lang)})

    def _receive_upload(self, query: dict) -> None:
        name = os.path.basename((query.get("name", ["sample.pkl"])[0]) or "sample.pkl")
        fmt = query.get("fmt", ["pickle"])[0]
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return self._json(400, {"error": T("msg.empty_body_cl", self._lang(query))})
        if n > MAX_UPLOAD:
            return self._json(413, {"error": f"artifact too large ({n} > {MAX_UPLOAD})"})
        scan_id = uuid.uuid4().hex
        os.makedirs(DATA_TMP, exist_ok=True)
        tmp = os.path.join(DATA_TMP, "up-" + scan_id + "-" + name)
        h = hashlib.sha256()
        got = 0
        with open(tmp, "wb") as fh:
            while got < n:
                chunk = self.rfile.read(min(1 << 20, n - got))
                if not chunk:
                    break
                fh.write(chunk)
                h.update(chunk)
                got += len(chunk)
        sha = h.hexdigest()
        token = uuid.uuid4().hex
        rec = {"scan_id": scan_id, "name": name, "format": fmt, "size": got,
               "sha256": sha, "artifact_token": token,
               "state": "queued", "stage": "queued", "progress": 0,
               "created": time.strftime("%Y-%m-%dT%H:%M:%S")}
        local = tmp
        if S3_ENABLED and _s3 is not None:
            key = f"{sha}/{name}"
            try:
                if not _s3.exists(key):
                    with open(tmp, "rb") as fh:
                        if got >= S3_MULTIPART_THRESHOLD:
                            res = _s3.put_stream_multipart(
                                key, fh, got, sha, part_size=S3_PART_SIZE,
                                workers=S3_PART_WORKERS, content_type="application/octet-stream")
                            if res["status"] not in (200, 201):
                                raise RuntimeError(f"s3 multipart status {res['status']}")
                            rec["s3_parts"] = res["parts"]
                            rec["s3_multipart"] = True
                        else:
                            st, _, _ = _s3.put_stream(key, fh, got, sha, "application/octet-stream")
                            if st not in (200, 201):
                                raise RuntimeError(f"s3 put status {st}")
                rec["s3_key"] = key
                rec["dedup"] = _s3.exists(key)
            except Exception as exc:  # noqa: BLE001
                rec["s3_error"] = f"{type(exc).__name__}: {exc}"
                try:
                    d = os.path.join(ARTIFACTS_DIR, scan_id)
                    os.makedirs(d, exist_ok=True)
                    local = os.path.join(d, name)
                    os.replace(tmp, local)
                    rec["local_path"] = local
                except OSError:
                    rec["local_error"] = "локальный фолбэк недоступен (RO FS)"
        else:
            d = os.path.join(ARTIFACTS_DIR, scan_id)
            os.makedirs(d, exist_ok=True)
            local = os.path.join(d, name)
            os.replace(tmp, local)
            rec["local_path"] = local
        save_scan(rec)
        if DB_ENABLED:
            rows = db_query(
                "INSERT INTO artifacts(sha256,size,format,filename,s3_key) VALUES "
                f"({_lit(sha)},{int(got)},{_lit(fmt)},{_lit(name)},{_lit(rec.get('s3_key'))}) "
                "ON CONFLICT (sha256) DO UPDATE SET size=EXCLUDED.size, "
                "filename=EXCLUDED.filename, s3_key=EXCLUDED.s3_key RETURNING id")
            art_id = rows[0][0] if rows else None
            if art_id is not None:
                rec["artifact_id"] = art_id
                save_scan(rec)
            db_exec("INSERT INTO scans(scan_id,artifact_id,status,stage,progress) VALUES "
                    f"({_lit(scan_id)},{art_id if art_id is not None else 'NULL'},"
                    f"'queued','queued',0) "
                    "ON CONFLICT (scan_id) DO UPDATE SET artifact_id=EXCLUDED.artifact_id")
            db_exec("INSERT INTO uploads(artifact_id,request_id,bytes,status,finished_at) "
                    f"SELECT id,{_lit(scan_id)},{int(got)},'received',now() FROM artifacts WHERE sha256={_lit(sha)}")
        if authz is not None:
            try:
                authz.audit(getattr(self, "_subject", "anonymous"), "upload", "artifact", sha,
                            getattr(self, "_rid", scan_id), self.client_address[0],
                            {"name": name, "size": got, "s3_key": rec.get("s3_key")})
            except Exception:  # noqa: BLE001
                pass
        threading.Thread(target=process_scan, args=(scan_id, name, fmt, local), daemon=True).start()
        return self._json(202, {"scan_id": scan_id, "state": "queued", "size": got,
                                "sha256": sha, "s3_key": rec.get("s3_key")})

    # --- Прямая presigned-multipart загрузка (P0-2) -------------------------
    def _tenant(self) -> str:
        subj = getattr(self, "_subject", "") or "shared"
        t = re.sub(r"[^A-Za-z0-9._-]+", "-", subj).strip("-.")[:64]
        return t or "shared"

    def _uploads_initiate(self) -> None:
        if not (S3_ENABLED and _s3 is not None):
            return self._json(503, {"error": "S3 не сконфигурирован"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        name = os.path.basename((body.get("name") or "sample.pkl"))
        fmt = body.get("fmt") or "pickle"
        sha = (body.get("sha256") or "").lower()
        try:
            size = int(body.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            return self._json(400, {"error": "sha256 обязателен (64 hex)"})
        if size <= 0:
            return self._json(400, {"error": "size обязателен (>0)"})
        if size > MAX_UPLOAD:
            return self._json(413, {"error": f"artifact too large ({size} > {MAX_UPLOAD})"})
        tenant = self._tenant()
        key = f"tenant/{tenant}/{sha}/{name}"
        if _s3.exists(key):
            return self._json(200, {"dedup": True, "key": key, "sha256": sha,
                                    "size": size, "tenant": tenant})
        part = DIRECT_PART_SIZE
        n_parts = (size + part - 1) // part
        if n_parts > 10000:                    # лимит числа частей S3
            part = (size + 9999) // 10000
            n_parts = (size + part - 1) // part
        try:
            uid = _s3.create_multipart(key)
            parts = [{"part_number": i, "size": min(part, size - (i - 1) * part),
                      "url": _s3.presign_upload_part(key, uid, i, expires=DIRECT_URL_TTL)}
                     for i in range(1, n_parts + 1)]
        except Exception as exc:  # noqa: BLE001
            return self._json(502, {"error": f"S3: {type(exc).__name__}: {exc}"})
        with _pending_lock:
            _pending_uploads[uid] = {"key": key, "name": name, "fmt": fmt, "sha256": sha,
                                     "size": size, "tenant": tenant, "created": time.time(),
                                     "subject": getattr(self, "_subject", "")}
        return self._json(200, {"upload_id": uid, "key": key, "part_size": part,
                                "count": n_parts, "parts": parts, "dedup": False,
                                "tenant": tenant, "expires_in": DIRECT_URL_TTL})

    def _scans_complete(self) -> None:
        if not (S3_ENABLED and _s3 is not None):
            return self._json(503, {"error": "S3 не сконфигурирован"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        uid = body.get("upload_id") or ""
        with _pending_lock:
            info = _pending_uploads.get(uid)
        if not info:
            return self._json(404, {"error": "unknown upload_id"})
        parts_in = body.get("parts") or []
        if parts_in:
            try:
                parts = [(int(p["part_number"]), str(p["etag"]).strip('"')) for p in parts_in]
            except (KeyError, TypeError, ValueError) as exc:
                return self._json(400, {"error": f"bad parts: {exc}"})
            try:
                st, _, data = _s3.complete_multipart(info["key"], uid, parts)
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"S3 complete: {type(exc).__name__}: {exc}"})
            if st not in (200, 201):
                return self._json(502, {"error": f"S3 complete status {st}"})
        elif not _s3.exists(info["key"]):
            return self._json(400, {"error": "parts обязателен"})
        size = info["size"]
        try:
            hs, hh, _ = _s3.head(info["key"])
            if hs == 200 and hh.get("Content-Length"):
                size = int(hh["Content-Length"])
        except Exception:  # noqa: BLE001
            pass
        scan_id = uuid.uuid4().hex
        token = uuid.uuid4().hex
        rec = {"scan_id": scan_id, "name": info["name"], "format": info["fmt"], "size": size,
               "sha256": info["sha256"], "artifact_token": token, "s3_key": info["key"],
               "tenant": info["tenant"], "direct": True,
               "state": "queued", "stage": "queued", "progress": 0,
               "created": time.strftime("%Y-%m-%dT%H:%M:%S")}
        save_scan(rec)
        if DB_ENABLED:
            rows = db_query(
                "INSERT INTO artifacts(sha256,size,format,filename,s3_key) VALUES "
                f"({_lit(info['sha256'])},{int(size)},{_lit(info['fmt'])},{_lit(info['name'])},"
                f"{_lit(info['key'])}) ON CONFLICT (sha256) DO UPDATE SET size=EXCLUDED.size, "
                "filename=EXCLUDED.filename, s3_key=EXCLUDED.s3_key RETURNING id")
            art_id = rows[0][0] if rows else None
            if art_id is not None:
                rec["artifact_id"] = art_id
                save_scan(rec)
            db_exec("INSERT INTO scans(scan_id,artifact_id,status,stage,progress) VALUES "
                    f"({_lit(scan_id)},{art_id if art_id is not None else 'NULL'},'queued','queued',0) "
                    "ON CONFLICT (scan_id) DO UPDATE SET artifact_id=EXCLUDED.artifact_id")
            db_exec("INSERT INTO uploads(artifact_id,request_id,bytes,status,finished_at) "
                    f"SELECT id,{_lit(scan_id)},{int(size)},'received',now() FROM artifacts "
                    f"WHERE sha256={_lit(info['sha256'])}")
        if authz is not None:
            try:
                authz.audit(getattr(self, "_subject", "anonymous"), "upload_direct", "artifact",
                            info["sha256"], getattr(self, "_rid", scan_id), self.client_address[0],
                            {"name": info["name"], "size": size, "s3_key": info["key"],
                             "tenant": info["tenant"]})
            except Exception:  # noqa: BLE001
                pass
        with _pending_lock:
            _pending_uploads.pop(uid, None)
        threading.Thread(target=_materialize_and_scan,
                         args=(scan_id, info["name"], info["fmt"], info["key"], size),
                         daemon=True).start()
        return self._json(202, {"scan_id": scan_id, "state": "queued", "size": size,
                                "sha256": info["sha256"], "s3_key": info["key"],
                                "tenant": info["tenant"]})

    def do_POST(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if self._require() is None:
            return
        if u.path == "/uploads/initiate":
            return self._uploads_initiate()
        if u.path == "/scans/complete":
            return self._scans_complete()
        if u.path in ("/scans", "/scans/upload", "/upload"):
            ident = getattr(self, "_subject", "") or (self.client_address[0] if self.client_address else "?")
            ok, retry = rate_allow(ident)
            if not ok:
                self.send_response(429)
                self.send_header("Retry-After", str(retry))
                return self._json(429, {"error": f"слишком много загрузок: повторите через {retry} с",
                                        "retry_after": retry})
            if not INTEGRITY_OK:
                print(f"[testing] CRITICAL: код/конфигурация не совпадают с ожидаемым digest "
                      f"({INTEGRITY_DIGEST} != {INTEGRITY_ENV}) — приём артефактов заблокирован", file=sys.stderr)
                return self._json(503, {"error": "integrity check failed", "actual": INTEGRITY_DIGEST,
                                        "expected": INTEGRITY_ENV})
            inflight = inflight_scans()
            if inflight >= MAX_INFLIGHT_SCANS:
                return self._json(429, {"error": f"слишком много проверок в работе ({inflight})",
                                        "max_inflight": MAX_INFLIGHT_SCANS})
            return self._receive_upload(q)
        return self._json(404, {"error": "not found"})



# Защита от шторма загрузок/скан-флуда (docs/14, P0-5)
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "30"))
MAX_INFLIGHT_SCANS = int(os.environ.get("MAX_INFLIGHT_SCANS", "5"))
_rate: dict = {}
_rate_lock = threading.Lock()



MAX_FINDINGS = int(os.environ.get("MAX_FINDINGS", "500"))   # лимит находок (docs/14, P1-7)


def cap_findings(findings):
    """Ограничивает число находок (защита БД/UI), возвращает (список, сколько усечено)."""
    if len(findings) <= MAX_FINDINGS:
        return findings, 0
    return findings[:MAX_FINDINGS], len(findings) - MAX_FINDINGS


def rate_allow(ident: str) -> tuple[bool, int]:
    """Скользящее окно: не больше RATE_LIMIT_PER_MIN запросов в минуту на клиента."""
    now = time.time()
    with _rate_lock:
        hits = [t for t in _rate.get(ident, []) if now - t < 60.0]
        if len(hits) >= RATE_LIMIT_PER_MIN:
            return False, max(1, int(60.0 - (now - hits[0])))
        hits.append(now)
        _rate[ident] = hits
    return True, 0


def inflight_scans() -> int:
    """Сканы, которые ещё выполняются (ограничение параллелизма = защита кластера)."""
    return sum(1 for r in list_scans() if r.get("state") in ("queued", "running", "submitted"))



# Контроль целостности кода/конфигурации анализа (docs/14, P0-6).
# Digest ожидаемых файлов вычисляется при применении манифестов и передаётся в env;
# при расхождении сервис работает fail-closed (не принимает артефакты) и громко алертит.
INTEGRITY_ENV = os.environ.get("MLSCAN_CM_DIGEST", "")
INTEGRITY_PATHS = ("/opt/mlscan/mlscan_poc.py", "/opt/svc/mlscan_testing.py", "/opt/formats/detector.py",
                   "/opt/auth/authz.py", "/opt/pg/pgclient.py", "/opt/i18n/i18n.py")


def compute_integrity_digest() -> str:
    import hashlib as _h
    d = _h.sha256()
    for path in INTEGRITY_PATHS:
        try:
            with open(path, "rb") as fh:
                d.update(fh.read())
        except Exception:  # noqa: BLE001
            d.update(f"missing:{path}".encode())
    return "sha256:" + d.hexdigest()


INTEGRITY_DIGEST = compute_integrity_digest()
INTEGRITY_OK = (not INTEGRITY_ENV) or (INTEGRITY_ENV == INTEGRITY_DIGEST)


def reap_stale_scans() -> int:
    """Помечает прерванные сканы (queued/running) как error.

    Очереди нет: обработка идёт в потоке процесса, поэтому после перезапуска пода
    такие сканы остаются «вечно в процессе». При старте переводим их в error
    (файл + зеркало в PostgreSQL), чтобы список и статистика были корректны.
    """
    n = 0
    for fn in os.listdir(store_dir()):
        if not fn.endswith(".json"):
            continue
        sid = fn[:-5]
        rec = load_scan(sid)
        if not rec or rec.get("state") not in ("queued", "running"):
            continue
        update(sid, state="error", stage="error", progress=100, verdict="Inconclusive",
               reason="проверка прервана (перезапуск сервиса тестирования)")
        n += 1
    if n:
        print(f"[testing] прерванных сканов помечено error: {n}", flush=True)
    return n


def main() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(DATA_TMP, exist_ok=True)
    if not S3_ENABLED:
        os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    threading.Thread(target=lambda: ThreadingHTTPServer(("0.0.0.0", ARTIFACT_PORT),
                                                        ArtifactHandler).serve_forever(),
                     daemon=True).start()
    try:
        reap_stale_scans()
    except Exception as exc:  # noqa: BLE001
        print(f"[testing] housekeeping: {type(exc).__name__}: {exc}", file=sys.stderr)
    port = int(os.environ.get("PORT", "8080"))
    print(f"[testing] api :{port}, artifacts :{ARTIFACT_PORT}, artifacts_dir={ARTIFACTS_DIR}",
          flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
