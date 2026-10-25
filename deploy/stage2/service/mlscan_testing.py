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

import hashlib
import http.client
import base64
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
# P1-7: предел динамики. Модели выше — «static-only + выборочная динамика»:
# полная динамика невозможна (не влезает в лимиты песочницы), поэтому анализируется
# статика по префиксу, а динамика честно помечается как неприменимая.
SANDBOX_DYNAMIC_MAX_BYTES = int(os.environ.get("SANDBOX_DYNAMIC_MAX_BYTES",
                                               str(6 * 1024 ** 3)))
# v3 (P1): квоты ingest (0 = без лимита)
MAX_OBJECT_BYTES = int(os.environ.get("MAX_OBJECT_BYTES", "0"))
MAX_BYTES_PER_DAY = int(os.environ.get("MAX_BYTES_PER_DAY", "0"))
MAX_CONCURRENT_UPLOADS = int(os.environ.get("MAX_CONCURRENT_UPLOADS", "8"))
# L1a: разрешённые реестры образов (через запятую; пусто = любой, но всё равно только по digest)
REGISTRY_ALLOWLIST = [r.strip() for r in os.environ.get("REGISTRY_ALLOWLIST", "").split(",") if r.strip()]
# L1: ёмкость LLM-пула для ресурсного планировщика (0/пусто = без ограничений в этом измерении)
ATTEST_KEY = os.environ.get("ATTEST_KEY", "mlscan-dev-attest")
LLM_POOL = {"gpu": int(os.environ.get("LLM_POOL_GPU", "8") or 0),
            "ram_gb": int(os.environ.get("LLM_POOL_RAM_GB", "1024") or 0),
            "disk_gb": int(os.environ.get("LLM_POOL_DISK_GB", "8192") or 0)}
_pending_uploads: dict = {}
_pending_lock = threading.Lock()


def _save_session(info: dict, status: str) -> None:
    if not DB_ENABLED:
        return
    db_exec("INSERT INTO upload_sessions(upload_id,s3_key,name,fmt,sha256,size,tenant,"
            "part_size,status,subject) VALUES "
            f"({_lit(info.get('upload_id'))},{_lit(info.get('key'))},{_lit(info.get('name'))},"
            f"{_lit(info.get('fmt'))},{_lit(info.get('sha256'))},{int(info.get('size') or 0)},"
            f"{_lit(info.get('tenant'))},{int(info.get('part_size') or 0)},"
            f"{_lit(status)},{_lit(info.get('subject'))}) "
            "ON CONFLICT (upload_id) DO UPDATE SET status=EXCLUDED.status, updated_at=now(), "
            "s3_key=EXCLUDED.s3_key, part_size=EXCLUDED.part_size")


def _daily_bytes(subject: str) -> int:
    if not DB_ENABLED:
        return 0
    rows = db_query("SELECT COALESCE(SUM(size),0) FROM upload_sessions WHERE subject="
                    + _lit(subject) + " AND created::date = current_date")
    try:
        return int(rows[0][0]) if rows else 0
    except Exception:  # noqa: BLE001
        return 0


def _upsert_model_profile(sha: str, profile: dict, source: str = "auto") -> None:
    if not DB_ENABLED or not sha:
        return
    try:
        db_exec("INSERT INTO model_profiles(sha256,is_llm,family,confidence,evidence,"
                "suggested_engines,source) VALUES ("
                f"{_lit(sha)},{'true' if profile.get('is_llm') else 'false'},"
                f"{_lit(profile.get('family',''))},{float(profile.get('confidence') or 0)},"
                f"{_lit(json.dumps(profile.get('evidence') or [], ensure_ascii=False))},"
                f"{_lit(json.dumps(profile.get('suggested_engines') or [], ensure_ascii=False))},"
                f"{_lit(source)}) ON CONFLICT (sha256) DO UPDATE SET "
                "is_llm=EXCLUDED.is_llm, family=EXCLUDED.family, confidence=EXCLUDED.confidence, "
                "evidence=EXCLUDED.evidence, suggested_engines=EXCLUDED.suggested_engines, "
                "source=EXCLUDED.source, updated=now()")
    except Exception as exc:  # noqa: BLE001
        print(f"[testing] model_profile failed: {type(exc).__name__}: {exc}", file=sys.stderr)


def _classify_and_record(name: str, fmt: str, size: int, family: str = "",
                         source: str = "auto", path: str = "") -> dict | None:
    if v3classifier is None:
        return None
    cfg = {"model_type": family} if family else None
    gguf_meta = None
    # U2: авто-классификация GGUF без подсказки — читаем префикс и парсим metadata
    if not family and fmt.lower() == "gguf" and v3gguf is not None and path and os.path.exists(path):
        try:
            with open(path, "rb") as fh:
                head = fh.read(4 * 1024 * 1024)
            gguf_meta = v3gguf.parse_gguf_meta(head).get("meta") or None
        except Exception:  # noqa: BLE001
            gguf_meta = None
    return v3classifier.classify(filenames=[name], config=cfg, gguf_meta=gguf_meta, size_bytes=size)


def _task_priority(subject: str) -> str:
    if v3pq is None:
        return "interactive"
    return v3pq.CLASS_CI if (subject or "").startswith("ci") else v3pq.CLASS_INTERACTIVE


def _enqueue_scan_task(rec: dict, subject: str) -> str | None:
    """Поставить скан в персистентную очередь (P2). Возвращает task_id или None."""
    if v3tasks is None or not DB_ENABLED:
        return None
    try:
        strategy = "static"
        if v3orch is not None:
            strategy = v3orch.choose_strategy(kind="model", fmt=rec.get("format", ""),
                                              size=int(rec.get("size") or 0),
                                              dynamic_max_bytes=SANDBOX_DYNAMIC_MAX_BYTES)["strategy"]
        priority = _task_priority(subject)
        rank = v3pq.RANK.get(priority, 1) if v3pq is not None else 1
        task_id = rec["scan_id"]
        payload = json.dumps({"scan_id": rec["scan_id"], "name": rec.get("name", ""),
                              "fmt": rec.get("format", ""), "size": rec.get("size", 0),
                              "strategy": strategy}, ensure_ascii=False)
        db_exec(v3tasks.enqueue_sql(task_id, subject or "shared", priority, rank, payload))
        rec["strategy"] = strategy
        rec["task_id"] = task_id
        save_scan(rec)
        return task_id
    except Exception as exc:  # noqa: BLE001
        print(f"[testing] enqueue task failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return None


def _task_set_running(task_id: str) -> None:
    if v3tasks is None or not DB_ENABLED or not task_id:
        return
    try:
        db_exec("UPDATE tasks SET status='running', started_at=now() WHERE task_id="
                + _lit(task_id))
    except Exception:  # noqa: BLE001
        pass


def _run_scan_with_task(scan_id: str, name: str, fmt: str, path: str,
                        task_id: str | None = None) -> None:
    _task_set_running(task_id)
    try:
        process_scan(scan_id, name, fmt, path)
        _task_status(task_id, True)
    except Exception as exc:  # noqa: BLE001
        _task_status(task_id, False, f"{type(exc).__name__}: {exc}"[:200])
        raise


def _run_direct_with_task(scan_id: str, name: str, fmt: str, key: str, size: int,
                          task_id: str | None = None) -> None:
    _task_set_running(task_id)
    try:
        _materialize_and_scan(scan_id, name, fmt, key, size)
        _task_status(task_id, True)
    except Exception as exc:  # noqa: BLE001
        _task_status(task_id, False, f"{type(exc).__name__}: {exc}"[:200])
        raise


def _task_status(task_id: str, ok: bool = True, error: str = "") -> None:
    if v3tasks is None or not DB_ENABLED or not task_id:
        return
    try:
        db_exec(v3tasks.complete_sql(task_id, ok, error))
    except Exception:  # noqa: BLE001
        pass


def _quota_ok(subject: str, size: int) -> tuple[bool, str, int]:
    """Проверить квоту загрузки. Возвращает (ok, code, http_status)."""
    if v3quota is None:
        return True, "ok", 200
    qu = v3quota.Quota(max_bytes_per_day=MAX_BYTES_PER_DAY, max_object_bytes=MAX_OBJECT_BYTES,
                       max_concurrent_uploads=MAX_CONCURRENT_UPLOADS)
    with _pending_lock:
        conc = len(_pending_uploads)
    ok, code = v3quota.check_upload(qu, size=size, used_bytes_today=_daily_bytes(subject),
                                    concurrent_uploads=conc)
    if ok:
        return True, code, 200
    return False, code, (429 if code == v3quota.DENY_DAILY else 403)


def _load_session_from_db(upload_id: str) -> dict | None:
    rows = db_query("SELECT upload_id,s3_key,name,fmt,sha256,size,tenant,part_size,status,subject "
                    f"FROM upload_sessions WHERE upload_id={_lit(upload_id)}")
    if not rows:
        return None
    r = rows[0]
    return {"upload_id": r[0], "key": r[1], "name": r[2], "fmt": r[3], "sha256": r[4],
            "size": int(r[5] or 0), "tenant": r[6], "part_size": int(r[7] or 0),
            "status": r[8], "subject": r[9]}

# --- PostgreSQL (dual-write; не критично для работы сервиса) ---
PG_HOST = os.environ.get("PGHOST", "")
DB_ENABLED = bool(PG_HOST)
_Pg = None
if DB_ENABLED:
    sys.path.insert(0, "/opt/pg")
    from pgclient import Pg as _Pg  # noqa: E402


# P2-9: метрики пути данных (приём / запись в Garage / регистрация).
_pipe = {"uploads": 0, "bytes": 0, "receive_s": 0.0, "garage_s": 0.0, "register_s": 0.0,
         "last_mbps": 0.0, "last_multipart": False}
_pipe_lock = threading.Lock()


def pipe_add(receive_s: float, garage_s: float, register_s: float, nbytes: int,
             multipart: bool = False) -> None:
    total_time = receive_s + garage_s
    with _pipe_lock:
        _pipe["uploads"] += 1
        _pipe["bytes"] += int(nbytes)
        _pipe["receive_s"] = round(_pipe["receive_s"] + receive_s, 3)
        _pipe["garage_s"] = round(_pipe["garage_s"] + garage_s, 3)
        _pipe["register_s"] = round(_pipe["register_s"] + register_s, 3)
        _pipe["last_mbps"] = round(nbytes / total_time / 1e6, 1) if total_time > 0 else 0.0
        _pipe["last_multipart"] = multipart


def pipe_snapshot() -> dict:
    with _pipe_lock:
        d = dict(_pipe)
    total_time = d["receive_s"] + d["garage_s"]
    d["avg_mbps"] = round(d["bytes"] / total_time / 1e6, 1) if total_time > 0 else 0.0
    return d


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

# v3 (P1): квоты ingest + общий пул/refs (модули монтируются в /opt/v3ingest)
sys.path.insert(0, "/opt/v3ingest")
try:
    import quota as v3quota  # noqa: E402
except Exception:  # noqa: BLE001
    v3quota = None  # type: ignore
try:
    import pool as v3pool  # noqa: E402
    import objectrefs as v3refs  # noqa: E402
except Exception:  # noqa: BLE001
    v3pool = None  # type: ignore
    v3refs = None  # type: ignore

sys.path.insert(0, "/opt/v3obs")
try:  # v3 (P7): метрики/SLO
    import metrics as v3metrics  # noqa: E402
    import slo as v3slo  # noqa: E402
except Exception:  # noqa: BLE001
    v3metrics = None  # type: ignore
    v3slo = None  # type: ignore

sys.path.insert(0, "/opt/v3registry")
try:  # v3 (L1a): реестр образов — валидация ссылок/подпись
    import images as v3images  # noqa: E402
    import sbom as v3sbom  # noqa: E402
except Exception:  # noqa: BLE001
    v3images = None  # type: ignore
    v3sbom = None  # type: ignore

sys.path.insert(0, "/opt/v3llm")
try:  # v3 (L0): классификатор LLM + binding/bundle
    import classifier as v3classifier  # noqa: E402
    import binding as v3binding  # noqa: E402
    import llm_env as v3llmenv  # noqa: E402
    import tetragon as v3tetragon  # noqa: E402
    import gguf as v3gguf  # noqa: E402
    import promptset as v3promptset  # noqa: E402
    import evaluators as v3evaluators  # noqa: E402
except Exception:  # noqa: BLE001
    v3classifier = None  # type: ignore
    v3binding = None  # type: ignore
    v3llmenv = None  # type: ignore
    v3tetragon = None  # type: ignore
    v3gguf = None  # type: ignore
    v3promptset = None  # type: ignore
    v3evaluators = None  # type: ignore

sys.path.insert(0, "/opt/v3control")
try:  # v3 (P2): персистентная очередь + orchestrator + тенанты
    import pq as v3pq  # noqa: E402
    import tasks_sql as v3tasks  # noqa: E402
    import orchestrator as v3orch  # noqa: E402
    import tenants as v3tenants  # noqa: E402
    import attest as v3attest  # noqa: E402
    _v3q = v3tenants.TenantRegistry()
except Exception:  # noqa: BLE001
    v3pq = v3tasks = v3orch = v3tenants = None  # type: ignore
    v3attest = None  # type: ignore
    _v3q = None  # type: ignore


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
    "s.kind, "
    "to_char(s.created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS'), "
    "to_char(COALESCE(s.finished_at, s.created_at), 'YYYY-MM-DD\"T\"HH24:MI:SS') "
    "FROM scans s LEFT JOIN artifacts a ON a.id = s.artifact_id "
    "ORDER BY s.created_at DESC")


def list_scans() -> list[dict]:
    # Основной путь — PostgreSQL (метаданные сканов и артефактов), без чтения тысяч файлов.
    rows = db_query(_LIST_SQL)
    if rows:
        keys = ("scan_id", "name", "size", "sha256", "state", "stage", "progress",
                "verdict", "kind", "created", "updated")
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
                                          "stage", "progress", "verdict", "kind", "created", "updated")})
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
                "total_bytes": total_bytes, "distinct_sha256": len(hashes),
                "pipeline": pipe_snapshot()}
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
            "total_bytes": total_bytes, "distinct_sha256": len(hashes),
            "pipeline": pipe_snapshot()}


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
    materialize_max = min(DIRECT_MATERIALIZE_MAX, SANDBOX_DYNAMIC_MAX_BYTES)
    if size <= materialize_max:
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
    # Крупный объект: потоковая статика по префиксу (P1-6) — без полной загрузки.
    prefix_bytes = int(os.environ.get("STATIC_PREFIX_BYTES", str(64 * 1024 ** 2)))
    try:
        blob = _s3.read_prefix(key, min(prefix_bytes, size))
        tmp = os.path.join(DATA_TMP, "pfx-" + scan_id + "-" + name)
        os.makedirs(DATA_TMP, exist_ok=True)
        with open(tmp, "wb") as fh:
            fh.write(blob)
        rec = load_scan(scan_id) or {}
        static = mlscan_poc.static_stage(Path(tmp), total_size=size)
        if format_adapter is not None and "adapter_format" not in static:
            try:
                fa = format_adapter.static_scan(Path(tmp), total_size=size)
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
        static["static_prefix_bytes"] = len(blob)
        dynamic = {"status": "skipped", "reason": "объект больше лимита локальной материализации"}
        findings = normalize(scan_id, rec.get("sha256", ""), static, dynamic)
        findings, _tr = cap_findings(findings)
        verdict, reason = mlscan_poc.decide(static, dynamic)
        coverage = mlscan_poc.coverage_of(static, dynamic)
        reason = f"{reason}; статика по префиксу {len(blob)} из {size} Б (P1-6)"
        update(scan_id, state="done", stage="done", progress=100, verdict=verdict, reason=reason,
               findings=findings, static=static, sandbox=dynamic, coverage=coverage)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return
    except Exception as exc:  # noqa: BLE001
        print(f"[testing] {scan_id}: потоковая статика не удалась: {type(exc).__name__}: {exc}",
              file=sys.stderr)
    update(scan_id, state="done", stage="done", progress=100, verdict="Inconclusive",
           reason="объект больше лимита локальной материализации, потоковая статика недоступна",
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

    def _raw(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

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
        if u.path == "/v3/metrics":
            return self._v3_metrics()
        if u.path == "/v3/slo":
            return self._v3_slo()
        if u.path == "/prompt-sets/active":
            return self._prompt_sets_active()
        if u.path.startswith("/llm/events/"):
            return self._llm_events_get(u.path.split("/", 3)[3])
        if u.path == "/images/verify":
            return self._images_verify((q.get("ref", [""])[0]))
        if u.path.startswith("/images/"):
            return self._images_get(u.path.split("/", 2)[2])
        if u.path == "/gate":
            return self._gate(q)
        if u.path.startswith("/bundles/") and u.path.endswith("/verdict"):
            return self._bundle_verdict_get(u.path.split("/", 3)[2])
        if u.path.startswith("/bundles/"):
            return self._bundles_get(u.path.split("/", 2)[2])
        if u.path.startswith("/uploads/") and u.path.endswith("/parts"):
            return self._uploads_parts(u.path.split("/")[2])
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
        kind = query.get("kind", ["model"])[0]
        fam_hint = query.get("family", [""])[0]
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return self._json(400, {"error": T("msg.empty_body_cl", self._lang(query))})
        if n > MAX_UPLOAD:
            return self._json(413, {"error": f"artifact too large ({n} > {MAX_UPLOAD})"})
        scan_id = uuid.uuid4().hex
        t0 = time.monotonic()
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
        t_recv = time.monotonic()
        token = uuid.uuid4().hex
        prof = (_classify_and_record(name, fmt, got, fam_hint, path=tmp)
                if (kind == "model" and v3classifier is not None) else None)
        rec = {"scan_id": scan_id, "name": name, "format": fmt, "size": got, "kind": kind,
               "model_profile": prof,
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
            db_exec("INSERT INTO scans(scan_id,artifact_id,status,stage,progress,kind) VALUES "
                    f"({_lit(scan_id)},{art_id if art_id is not None else 'NULL'},"
                    f"'queued','queued',0,{_lit(kind)}) "
                    "ON CONFLICT (scan_id) DO UPDATE SET artifact_id=EXCLUDED.artifact_id, "
                    "kind=EXCLUDED.kind")
            db_exec("INSERT INTO uploads(artifact_id,request_id,bytes,status,finished_at) "
                    f"SELECT id,{_lit(scan_id)},{int(got)},'received',now() FROM artifacts WHERE sha256={_lit(sha)}")
        if authz is not None:
            try:
                authz.audit(getattr(self, "_subject", "anonymous"), "upload", "artifact", sha,
                            getattr(self, "_rid", scan_id), self.client_address[0],
                            {"name": name, "size": got, "s3_key": rec.get("s3_key")})
            except Exception:  # noqa: BLE001
                pass
        pipe_add(t_recv - t0, max(time.monotonic() - t_recv, 0.0), 0, got,
                 bool(rec.get("s3_multipart")))
        if prof is not None:
            _upsert_model_profile(sha, prof, "manual" if fam_hint else "auto")
        _tid = _enqueue_scan_task(rec, getattr(self, "_subject", ""))
        save_scan(rec)
        threading.Thread(target=_run_scan_with_task, args=(scan_id, name, fmt, local, _tid),
                         daemon=True).start()
        return self._json(202, {"scan_id": scan_id, "state": "queued", "size": got,
                                "sha256": sha, "s3_key": rec.get("s3_key"),
                                "multipart": bool(rec.get("s3_multipart")),
                                "parts": rec.get("s3_parts"), "kind": rec.get("kind", "model"),
                                "model_profile": rec.get("model_profile")})

    # --- Прямая presigned-multipart загрузка (P0-2) -------------------------
    def _tenant(self) -> str:
        subj = getattr(self, "_subject", "") or "shared"
        t = re.sub(r"[^A-Za-z0-9._-]+", "-", subj).strip("-.")[:64]
        return t or "shared"

    def _session(self, upload_id: str) -> dict | None:
        with _pending_lock:
            info = _pending_uploads.get(upload_id)
        if info:
            return info
        return _load_session_from_db(upload_id)

    def _uploads_parts(self, upload_id: str) -> None:
        if not (S3_ENABLED and _s3 is not None):
            return self._json(503, {"error": "S3 не сконфигурирован"})
        info = self._session(upload_id)
        if not info:
            return self._json(404, {"error": "unknown upload_id"})
        try:
            parts = _s3.list_parts(info["key"], upload_id)
        except Exception as exc:  # noqa: BLE001
            return self._json(502, {"error": f"S3 list_parts: {type(exc).__name__}: {exc}"})
        part_size = int(info.get("part_size") or DIRECT_PART_SIZE)
        size = int(info.get("size") or 0)
        count = (size + part_size - 1) // part_size if size else len(parts)
        urls = {}
        for i in range(1, count + 1):
            try:
                urls[i] = _s3.presign_upload_part(info["key"], upload_id, i, expires=DIRECT_URL_TTL)
            except Exception:  # noqa: BLE001
                pass
        return self._json(200, {"upload_id": upload_id, "status": info.get("status", "active"),
                                "part_size": part_size, "size": size, "count": count,
                                "parts": [{"part_number": n, "etag": et} for n, et in parts],
                                "urls": {str(k): v for k, v in urls.items()}})

    def _uploads_abort(self, upload_id: str) -> None:
        info = self._session(upload_id)
        if not info:
            return self._json(404, {"error": "unknown upload_id"})
        if S3_ENABLED and _s3 is not None:
            try:
                _s3.abort_multipart(info["key"], upload_id)
            except Exception:  # noqa: BLE001
                pass
        with _pending_lock:
            _pending_uploads.pop(upload_id, None)
        info["upload_id"] = upload_id
        _save_session(info, "aborted")
        return self._json(200, {"upload_id": upload_id, "status": "aborted"})

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
        ok_q, code_q, http_q = _quota_ok(tenant, size)
        if not ok_q:
            return self._json(http_q, {"error": code_q, "limit": "quota"})
        key = f"tenant/{tenant}/{sha}/{name}"
        if _s3.exists(key):
            uid = "dedup-" + uuid.uuid4().hex
            info = {"upload_id": uid, "key": key, "name": name, "fmt": fmt, "sha256": sha,
                    "size": size, "tenant": tenant, "part_size": DIRECT_PART_SIZE,
                    "status": "dedup", "created": time.time(),
                    "subject": getattr(self, "_subject", "")}
            with _pending_lock:
                _pending_uploads[uid] = info
            _save_session(info, "dedup")
            return self._json(200, {"dedup": True, "upload_id": uid, "key": key, "sha256": sha,
                                    "size": size, "tenant": tenant, "count": 0, "parts": []})
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
        info = {"upload_id": uid, "key": key, "name": name, "fmt": fmt, "sha256": sha,
                "size": size, "tenant": tenant, "part_size": part, "status": "active",
                "created": time.time(), "subject": getattr(self, "_subject", "")}
        with _pending_lock:
            _pending_uploads[uid] = info
        _save_session(info, "active")
        return self._json(200, {"upload_id": uid, "key": key, "part_size": part,
                                "count": n_parts, "parts": parts, "dedup": False,
                                "tenant": tenant, "expires_in": DIRECT_URL_TTL})

    def _scans_complete(self) -> None:
        if not (S3_ENABLED and _s3 is not None):
            return self._json(503, {"error": "S3 не сконфигурирован"})
        t0 = time.monotonic()
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        uid = body.get("upload_id") or ""
        info = self._session(uid)
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
            db_exec("INSERT INTO scans(scan_id,artifact_id,status,stage,progress,kind) VALUES "
                    f"({_lit(scan_id)},{art_id if art_id is not None else 'NULL'},'queued','queued',0,"
                    f"{_lit(rec.get('kind', 'model'))}) "
                    "ON CONFLICT (scan_id) DO UPDATE SET artifact_id=EXCLUDED.artifact_id, "
                    "kind=EXCLUDED.kind")
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
        info["upload_id"] = uid
        _save_session(info, "completed")
        pipe_add(0.0, round(time.monotonic() - t0, 3), 0.0, size, True)
        if prof is not None:
            _upsert_model_profile(sha, prof, "manual" if fam_hint else "auto")
        _tid = _enqueue_scan_task(rec, getattr(self, "_subject", ""))
        save_scan(rec)
        threading.Thread(target=_run_direct_with_task,
                         args=(scan_id, info["name"], info["fmt"], info["key"], size, _tid),
                         daemon=True).start()
        return self._json(202, {"scan_id": scan_id, "state": "queued", "size": size,
                                "sha256": info["sha256"], "s3_key": info["key"],
                                "tenant": info["tenant"]})

    def _prompt_sets_upload(self) -> None:
        """L3: загрузка набора тестов XLSX (админ) → парсинг → БД/версия (активная до новой)."""
        if v3promptset is None:
            return self._json(503, {"error": "v3 promptset module unavailable"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        name = os.path.basename(body.get("name") or "questions.xlsx")
        content = body.get("content_b64") or ""
        if not content:
            return self._json(400, {"error": "content_b64 обязателен"})
        try:
            raw = base64.b64decode(content)
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad base64: {exc}"})
        try:
            parsed = v3promptset.parse_xlsx(raw, version=body.get("version", ""))
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"parse: {type(exc).__name__}: {exc}"})
        if parsed.get("errors") and not parsed.get("cases"):
            return self._json(400, {"error": "нет валидных кейсов", "errors": parsed["errors"]})
        ver = parsed["version"]
        if DB_ENABLED:
            try:
                db_exec("UPDATE prompt_sets SET active=false WHERE active")
                db_exec("INSERT INTO prompt_sets(version,name,cases,warnings,errors,active) VALUES ("
                        f"{_lit(ver)},{_lit(name)},"
                        f"{_lit(json.dumps(parsed['cases'], ensure_ascii=False))},"
                        f"{_lit(json.dumps(parsed['warnings'], ensure_ascii=False))},"
                        f"{_lit(json.dumps(parsed['errors'], ensure_ascii=False))},true) "
                        "ON CONFLICT (version) DO UPDATE SET active=true, name=EXCLUDED.name, "
                        "cases=EXCLUDED.cases, warnings=EXCLUDED.warnings, errors=EXCLUDED.errors")
                for c in parsed["cases"]:
                    db_exec("INSERT INTO llm_prompts(prompt_set,id,domain,prompt,reference,criticality,"
                            "severity,weight,tolerance,policy_class,class_reviewed) VALUES ("
                            f"{_lit(ver)},{_lit(str(c['id']))},{_lit(c['domain'])},{_lit(c['prompt'])},"
                            f"{_lit(c['reference'])},{int(c['criticality'])},{_lit(c['severity'])},"
                            f"{int(c['weight'])},{float(c['tolerance'])},{_lit(c['policy_class'])},"
                            f"{'true' if c['class_reviewed'] else 'false'}) "
                            "ON CONFLICT (prompt_set,id) DO UPDATE SET domain=EXCLUDED.domain, "
                            "prompt=EXCLUDED.prompt, reference=EXCLUDED.reference, "
                            "criticality=EXCLUDED.criticality, severity=EXCLUDED.severity, "
                            "weight=EXCLUDED.weight, tolerance=EXCLUDED.tolerance, "
                            "policy_class=EXCLUDED.policy_class, class_reviewed=EXCLUDED.class_reviewed")
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"db: {type(exc).__name__}: {exc}"})
        return self._json(201, {"version": ver, "cases": len(parsed["cases"]),
                                "warnings": parsed["warnings"], "errors": parsed["errors"]})

    def _prompt_sets_active(self) -> None:
        if v3promptset is None:
            return self._json(503, {"error": "v3 promptset module unavailable"})
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        rows = db_query("SELECT version,name,cases,warnings,errors FROM prompt_sets WHERE active "
                        "ORDER BY created DESC LIMIT 1")
        if not rows:
            return self._json(404, {"error": "нет активного набора"})
        r = rows[0]
        cases = json.loads(r[2] or "[]")
        reviewed = sum(1 for c in cases if c.get("class_reviewed"))
        return self._json(200, {"version": r[0], "name": r[1], "cases": len(cases),
                                "class_reviewed": reviewed,
                                "warnings": json.loads(r[3] or "[]"),
                                "errors": json.loads(r[4] or "[]")})

    def _llm_score(self) -> None:
        """L3: оценка ответов (правила; опц. judge) с допуском по критичности + агрегация."""
        if v3evaluators is None or v3promptset is None:
            return self._json(503, {"error": "v3 evaluators module unavailable"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        responses = body.get("responses") or {}
        ver = body.get("version") or ""
        if not ver and DB_ENABLED:
            rows = db_query("SELECT version,cases FROM prompt_sets WHERE active ORDER BY created DESC LIMIT 1")
            if rows:
                ver, cases = rows[0][0], json.loads(rows[0][1] or "[]")
            else:
                cases = []
        else:
            cases = json.loads(db_query("SELECT cases FROM prompt_sets WHERE version=" + _lit(ver))[0][0]) if DB_ENABLED else []
        results = []
        for c in cases:
            key = str(c["id"])
            if key not in responses and key not in {str(k) for k in responses}:
                continue
            answers = responses.get(key) or responses.get(int(c["id"]) if str(c["id"]).isdigit() else key) or []
            results.append(v3evaluators.evaluate_case(c, answers))
        agg = v3evaluators.aggregate(results)
        agg.update({"version": ver})
        if DB_ENABLED and body.get("scan_id"):
            try:
                db_exec("INSERT INTO llm_scores(scan_id,prompt_set,passed,total,safety_fail,pass_rate,details) "
                        "VALUES (" + ",".join([_lit(body["scan_id"]), _lit(ver), str(int(agg["passed"])),
                                               str(int(agg["total"])), str(int(agg["safety_fail"])),
                                               str(float(agg["pass_rate"])),
                                               _lit(json.dumps(results, ensure_ascii=False))]) + ")")
            except Exception:  # noqa: BLE001
                pass
        return self._json(200, agg)

    def _llm_events(self) -> None:
        """L2: принять события eBPF/Tetragon, смапить в findings (LLM-B-*), сохранить и вернуть."""
        if v3tetragon is None:
            return self._json(503, {"error": "v3 tetragon module unavailable"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        scan_id = body.get("scan_id") or ""
        nonce = body.get("nonce") or ""
        events = body.get("events") or []
        findings, rejected = v3tetragon.map_findings(events, nonce)
        if DB_ENABLED and scan_id:
            for f in findings:
                try:
                    db_exec("INSERT INTO llm_events(scan_id,check_id,severity,phase,probe_id,evidence,nonce) "
                            "VALUES (" + ",".join([
                                _lit(scan_id), _lit(f.get("check_id", "")), _lit(f.get("severity", "")),
                                _lit(f.get("phase", "")), _lit(f.get("probe_id", "")),
                                _lit(f.get("evidence", "")), _lit(nonce)]) + ")")
                except Exception:  # noqa: BLE001
                    pass
        return self._json(200, {"findings": findings, "rejected": rejected,
                                "max_severity": v3tetragon.max_severity(findings),
                                "count": len(findings)})

    def _llm_events_get(self, scan_id: str) -> None:
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        rows = db_query("SELECT check_id,severity,phase,probe_id,evidence FROM llm_events WHERE scan_id="
                        + _lit(scan_id) + " ORDER BY id")
        return self._json(200, {"scan_id": scan_id, "count": len(rows or []),
                                "findings": [{"check_id": r[0], "severity": r[1], "phase": r[2],
                                              "probe_id": r[3], "evidence": r[4]} for r in (rows or [])]})

    def _bundle_verdict_set(self, bundle_id: str) -> None:
        """L4: вердикт на уровне bundle + подписанная аттестация (in-toto-подобная)."""
        if v3attest is None:
            return self._json(503, {"error": "v3 attest module unavailable"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        verdict = body.get("verdict") or "Inconclusive"
        safety_fail = int(body.get("safety_fail") or 0)
        pass_rate = float(body.get("pass_rate", 1.0))
        action, reason = v3attest.gate_decision(verdict, safety_fail=safety_fail, pass_rate=pass_rate)
        image = body.get("engine_image") or ""
        model = body.get("model_sha256") or ""
        if (not image or not model) and DB_ENABLED:
            rows = db_query("SELECT engine_image,model_sha256 FROM bundles WHERE bundle_id=" + _lit(bundle_id))
            if rows:
                image = image or rows[0][0]; model = model or rows[0][1]
        st = v3attest.make_statement(bundle_id=bundle_id, engine_image=image, model_sha256=model,
                                     verdict=verdict, action=action, coverage=body.get("coverage") or {},
                                     metrics=body.get("metrics") or {},
                                     versions=body.get("versions") or {})
        digest = v3attest.statement_digest(st)
        sig = v3attest.sign(st, ATTEST_KEY)
        if DB_ENABLED:
            try:
                db_exec("INSERT INTO bundle_verdicts(bundle_id,verdict,action,coverage,metrics,statement,"
                        "attestation_digest,signature) VALUES ("
                        f"{_lit(bundle_id)},{_lit(verdict)},{_lit(action)},"
                        f"{_lit(json.dumps(body.get('coverage') or {}, ensure_ascii=False))},"
                        f"{_lit(json.dumps(body.get('metrics') or {}, ensure_ascii=False))},"
                        f"{_lit(json.dumps(st, ensure_ascii=False))},{_lit(digest)},{_lit(sig)}) "
                        "ON CONFLICT (bundle_id) DO UPDATE SET verdict=EXCLUDED.verdict, "
                        "action=EXCLUDED.action, coverage=EXCLUDED.coverage, metrics=EXCLUDED.metrics, "
                        "statement=EXCLUDED.statement, attestation_digest=EXCLUDED.attestation_digest, "
                        "signature=EXCLUDED.signature")
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"db: {type(exc).__name__}: {exc}"})
        return self._json(200, {"bundle_id": bundle_id, "verdict": verdict, "action": action,
                                "reason": reason, "attestation_digest": digest, "signature": sig,
                                "statement": st})

    def _bundle_verdict_get(self, bundle_id: str) -> None:
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        rows = db_query("SELECT verdict,action,attestation_digest,signature,statement FROM bundle_verdicts "
                        "WHERE bundle_id=" + _lit(bundle_id))
        if not rows:
            return self._json(404, {"error": "verdict not found"})
        r = rows[0]
        return self._json(200, {"bundle_id": bundle_id, "verdict": r[0], "action": r[1],
                                "attestation_digest": r[2], "signature": r[3],
                                "statement": json.loads(r[4] or "{}")})

    def _gate(self, q: dict) -> None:
        """L4: CI-gate по паре (image digest, model sha) — решение + аттестация."""
        image = q.get("image", [""])[0]
        model = q.get("model", [""])[0]
        if not image or not model:
            return self._json(400, {"error": "нужны image и model"})
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        rows = db_query("SELECT bundle_id FROM bundles WHERE engine_image=" + _lit(image)
                        + " AND model_sha256=" + _lit(model) + " LIMIT 1")
        if not rows:
            return self._json(404, {"error": "bundle not found", "decision": "unknown"})
        bid = rows[0][0]
        vr = db_query("SELECT verdict,action,attestation_digest,signature FROM bundle_verdicts "
                      "WHERE bundle_id=" + _lit(bid))
        if not vr:
            return self._json(200, {"bundle_id": bid, "decision": "unknown", "reason": "нет вердикта"})
        return self._json(200, {"bundle_id": bid, "decision": vr[0][1], "verdict": vr[0][0],
                                "attestation_digest": vr[0][2], "signature": vr[0][3]})

    def _v3_metrics(self) -> None:
        """P7: Prometheus-метрики v3 (per-tenant ingest/tasks/refs + фазы пайплайна)."""
        if v3metrics is None:
            return self._json(503, {"error": "v3 metrics module unavailable"})
        reg = v3metrics.Registry()
        if DB_ENABLED:
            for r in (db_query("SELECT COALESCE(subject,'shared'), COALESCE(SUM(size),0), COUNT(*) "
                               "FROM upload_sessions GROUP BY 1") or []):
                reg.inc("mlscan_v3_upload_bytes_total", {"tenant": r[0]}, int(r[1] or 0))
                reg.inc("mlscan_v3_uploads_total", {"tenant": r[0]}, int(r[2] or 0))
            for r in (db_query("SELECT tenant, status, COUNT(*) FROM tasks GROUP BY 1,2") or []):
                reg.set("mlscan_v3_tasks", int(r[2] or 0), {"tenant": r[0], "status": r[1]})
            for r in (db_query("SELECT tenant_id, COALESCE(SUM(size),0), COALESCE(SUM(refcount),0) "
                               "FROM object_refs GROUP BY 1") or []):
                reg.set("mlscan_v3_refs_bytes", int(r[1] or 0), {"tenant": r[0]})
                reg.set("mlscan_v3_refs", int(r[2] or 0), {"tenant": r[0]})
            qd = db_query("SELECT COUNT(*) FROM tasks WHERE status='queued'")
            reg.set("mlscan_v3_queue_depth", int((qd[0][0] if qd else 0)))
        pipe = pipe_snapshot()
        reg.set("mlscan_v3_upload_mbps", float(pipe.get("avg_mbps") or 0))
        reg.set("mlscan_v3_upload_receive_seconds", float(pipe.get("receive_s") or 0))
        reg.set("mlscan_v3_upload_garage_seconds", float(pipe.get("garage_s") or 0))
        return self._raw(200, reg.render().encode(), "text/plain; version=0.0.4; charset=utf-8")

    def _v3_slo(self) -> None:
        if v3slo is None:
            return self._json(503, {"error": "v3 slo module unavailable"})
        pipe = pipe_snapshot()
        samples = {"ingest_gbps": float(pipe.get("avg_mbps") or 0) * 8 / 1000.0}
        if DB_ENABLED:
            qd = db_query("SELECT COUNT(*) FROM tasks WHERE status='queued'")
            samples["queue_depth"] = int((qd[0][0] if qd else 0))
        return self._json(200, {"slo": v3slo.SLO, "samples": samples,
                                "alerts": v3slo.evaluate(samples)})

    def _llm_precheck(self) -> None:
        """L1: ресурсный планировщик — хватает ли ресурсов LLM-пула для запуска инференса."""
        if v3llmenv is None:
            return self._json(503, {"error": "v3 llm_env module unavailable"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        required = body.get("resources") or {}
        ok, why = v3llmenv.resource_check(required, LLM_POOL)
        return self._json(200, {"ok": ok, "reason": why, "required": required,
                                "available": LLM_POOL,
                                "decision": "accept" if ok else "rejected"})

    def _images_import(self) -> None:
        """L1a: регистрация образа движка (по digest) + server-side copy OCI-архива в registry/."""
        if v3images is None:
            return self._json(503, {"error": "v3 registry module unavailable"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        ref = (body.get("ref") or "").strip()
        digest = (body.get("digest") or "").strip()
        if not digest and ref:
            digest = v3images.parse_ref(ref)["digest"]
        ref_full = ref if "@" in ref else (f"{ref}@{digest}" if ref else digest)
        if not v3images.is_valid_digest(digest):
            return self._json(400, {"error": "digest обязателен (sha256:<64hex>)"})
        ok, why = v3images.validate_ref(ref_full, allowlist=REGISTRY_ALLOWLIST or None)
        if not ok:
            return self._json(403, {"error": why})
        stored_key = ""
        oci_key = body.get("oci_tar_key") or ""
        if oci_key:
            if not (S3_ENABLED and _s3 is not None):
                return self._json(503, {"error": "S3 не сконфигурирован"})
            stored_key = v3images.storage_key(digest)
            if not _s3.exists(stored_key):
                try:
                    st, _, _ = _s3.copy_object(oci_key, stored_key)
                except Exception as exc:  # noqa: BLE001
                    return self._json(502, {"error": f"S3 copy: {type(exc).__name__}: {exc}"})
                if st not in (200, 201):
                    return self._json(502, {"error": f"S3 copy status {st}"})
        rec = v3sbom.make_image_record(digest=digest, ref=ref_full, source=body.get("source", "import"),
                                       size=int(body.get("size") or 0),
                                       signature=body.get("signature", ""), sbom=body.get("sbom", ""))
        if DB_ENABLED:
            try:
                db_exec("INSERT INTO registry_images(digest,ref,source,size,signature,sbom,stored_key,"
                        "status) VALUES ("
                        f"{_lit(digest)},{_lit(ref_full)},{_lit(rec['source'])},{int(rec['size'])},"
                        f"{_lit(rec['signature'])},{_lit(rec['sbom'])},{_lit(stored_key)},'registered') "
                        "ON CONFLICT (digest) DO UPDATE SET ref=EXCLUDED.ref, size=EXCLUDED.size, "
                        "signature=EXCLUDED.signature, sbom=EXCLUDED.sbom, "
                        "stored_key=COALESCE(NULLIF(EXCLUDED.stored_key,''),registry_images.stored_key)")
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"db: {type(exc).__name__}: {exc}"})
        return self._json(201, {"digest": digest, "ref": ref_full, "stored_key": stored_key,
                                "status": "registered"})

    def _images_get(self, digest: str) -> None:
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        rows = db_query("SELECT digest,ref,source,size,signature,sbom,stored_key,status FROM registry_images "
                        "WHERE digest=" + _lit(digest))
        if not rows:
            return self._json(404, {"error": "image not found"})
        r = rows[0]
        return self._json(200, {"digest": r[0], "ref": r[1], "source": r[2], "size": r[3],
                                "signature": r[4], "sbom": r[5], "stored_key": r[6], "status": r[7]})

    def _images_verify(self, ref: str) -> None:
        if v3images is None:
            return self._json(503, {"error": "v3 registry module unavailable"})
        ok, why = v3images.validate_ref(ref, allowlist=REGISTRY_ALLOWLIST or None)
        return self._json(200, {"allowed": ok, "reason": why})

    def _bundles_create(self) -> None:
        """L0/L4: создать неизменяемый bundle (образ движка + модель + версии)."""
        if v3binding is None:
            return self._json(503, {"error": "v3 llm module unavailable"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        b = v3binding.make_bundle(
            image_digest=(body.get("engine_image") or "").strip(),
            model_sha256=(body.get("model_sha256") or "").lower(),
            engine_manifest=body.get("engine_manifest") or {},
            prompt_set=body.get("prompt_set", ""), detectors=body.get("detectors", ""),
            policy=body.get("policy", ""), tenant=self._tenant())
        ok, why = v3binding.validate_bundle(b)
        if not ok:
            return self._json(400, {"error": why})
        if DB_ENABLED:
            try:
                db_exec("INSERT INTO bundles(bundle_id,engine_image,model_sha256,engine_manifest,"
                        "prompt_set,detectors,policy,tenant) VALUES ("
                        f"{_lit(b['bundle_id'])},{_lit(b['engine_image'])},{_lit(b['model_sha256'])},"
                        f"{_lit(json.dumps(b['engine_manifest'], ensure_ascii=False))},"
                        f"{_lit(b['prompt_set'])},{_lit(b['detectors'])},{_lit(b['policy'])},"
                        f"{_lit(b['tenant'])}) ON CONFLICT (bundle_id) DO NOTHING")
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"db: {type(exc).__name__}: {exc}"})
        return self._json(201, b)

    def _bundles_get(self, bundle_id: str) -> None:
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        rows = db_query("SELECT bundle_id,engine_image,model_sha256,engine_manifest,prompt_set,"
                        "detectors,policy,tenant FROM bundles WHERE bundle_id=" + _lit(bundle_id))
        if not rows:
            return self._json(404, {"error": "bundle not found"})
        r = rows[0]
        return self._json(200, {"bundle_id": r[0], "engine_image": r[1], "model_sha256": r[2],
                                "engine_manifest": json.loads(r[3] or "{}"), "prompt_set": r[4],
                                "detectors": r[5], "policy": r[6], "tenant": r[7]})

    def _objects_import(self) -> None:
        """v3 (P1): server-side copy объекта в общий пул (import) без перекачки."""
        if not (S3_ENABLED and _s3 is not None):
            return self._json(503, {"error": "S3 не сконфигурирован"})
        if v3pool is None:
            return self._json(503, {"error": "v3 pool module unavailable"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        src_key = body.get("src_key") or ""
        sha = (body.get("sha256") or "").lower()
        try:
            size = int(body.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        name = os.path.basename(body.get("name") or os.path.basename(src_key) or "imported.bin")
        if not src_key:
            return self._json(400, {"error": "src_key обязателен"})
        if not v3pool.is_sha256(sha):
            return self._json(400, {"error": "sha256 обязателен (64 hex)"})
        if size <= 0:
            return self._json(400, {"error": "size обязателен (>0)"})
        tenant = self._tenant()
        ok_q, code_q, http_q = _quota_ok(tenant, size)
        if not ok_q:
            return self._json(http_q, {"error": code_q, "limit": "quota"})
        key = v3pool.pool_key(sha)
        dedup = _s3.exists(key)
        if not dedup:
            try:
                st, _, data = _s3.copy_object(src_key, key)
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"S3 copy: {type(exc).__name__}: {exc}"})
            if st not in (200, 201):
                return self._json(502, {"error": f"S3 copy status {st}: {data[:120]!r}"})
        if v3refs is not None and DB_ENABLED:
            try:
                db_exec(v3refs.ref_add_sql(tenant, sha, name, size))
            except Exception:  # noqa: BLE001
                pass
        if authz is not None:
            try:
                authz.audit(getattr(self, "_subject", "anonymous"), "object_import", "object", sha,
                            getattr(self, "_rid", ""), self.client_address[0],
                            {"src_key": src_key, "dst_key": key, "tenant": tenant, "size": size})
            except Exception:  # noqa: BLE001
                pass
        return self._json(200, {"key": key, "sha256": sha, "size": size, "tenant": tenant,
                                "dedup": dedup})

    def do_DELETE(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        if self._require() is None:
            return
        if u.path.startswith("/uploads/"):
            return self._uploads_abort(u.path.split("/")[2])
        return self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if self._require() is None:
            return
        if u.path == "/uploads/initiate":
            return self._uploads_initiate()
        if u.path == "/scans/complete":
            return self._scans_complete()
        if u.path == "/objects/import":
            return self._objects_import()
        if u.path == "/bundles":
            return self._bundles_create()
        if u.path.startswith("/bundles/") and u.path.endswith("/verdict"):
            return self._bundle_verdict_set(u.path.split("/", 3)[2])
        if u.path == "/images/import":
            return self._images_import()
        if u.path == "/llm/precheck":
            return self._llm_precheck()
        if u.path == "/llm/events":
            return self._llm_events()
        if u.path == "/prompt-sets":
            return self._prompt_sets_upload()
        if u.path == "/llm/score":
            return self._llm_score()
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
