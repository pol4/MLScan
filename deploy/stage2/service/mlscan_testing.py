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
import urllib.request
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
_s3_internal = None      # пресайн-URL для job'ов внутри кластера (внешний адрес им недоступен)
if S3_ENABLED:
    sys.path.insert(0, "/opt/s3")
    from s3client import S3  # noqa: E402
    _s3 = S3(S3_ENDPOINT, os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
             region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=3600,
             public_endpoint=os.environ.get("S3_PUBLIC_ENDPOINT", ""))
    # N2: presigned-URL для job'ов внутри кластера — внутренний адрес S3 (внешний из пода не резолвится)
    _s3_internal = S3(S3_ENDPOINT, os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
                      region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"],
                      timeout=600, public_endpoint=os.environ.get(
                          "S3_INTERNAL_ENDPOINT", "http://garage.mlscan-data.svc:3900"))

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
# U7: бюджет сэмплированной динамики (срезы)
DYNAMIC_SLICE_BYTES = int(os.environ.get("DYNAMIC_SLICE_BYTES", str(64 * 1024 ** 2)))
DYNAMIC_MAX_SLICES = int(os.environ.get("DYNAMIC_MAX_SLICES", "8"))
# L1a: разрешённые реестры образов (через запятую; пусто = любой, но всё равно только по digest)
REGISTRY_ALLOWLIST = [r.strip() for r in os.environ.get("REGISTRY_ALLOWLIST", "").split(",") if r.strip()]
# L1: ёмкость LLM-пула для ресурсного планировщика (0/пусто = без ограничений в этом измерении)
ATTEST_KEY = os.environ.get("ATTEST_KEY", "mlscan-dev-attest")
# N2: оркестрация теста bundle (job инференса + набор вопросов -> /llm/score -> вердикт)
LLM_TEST_NS = os.environ.get("LLM_TEST_NS", "mlscan-build")
LLM_TEST_RUNTIME_CLASS = os.environ.get("LLM_TEST_RUNTIME_CLASS", "nvidia")
LLM_TEST_GPU = os.environ.get("LLM_TEST_GPU", "1") == "1"
LLM_TEST_MAX_TOKENS = int(os.environ.get("LLM_TEST_MAX_TOKENS", "256"))
LLM_TEST_URL = os.environ.get("LLM_TEST_URL", "http://mlscan-testing.mlscan-testing.svc.cluster.local:8080")
LLM_TEST_EBPF = os.environ.get("LLM_TEST_EBPF", "0") == "1"      # B1: in-guest eBPF-агент в job'е теста
SANDBOX_EBPF = os.environ.get("SANDBOX_EBPF", "0") == "1"        # B1: in-guest eBPF-агент в скан-джобах
SANDBOX_EBPF_TRIGGER = os.environ.get("SANDBOX_EBPF_TRIGGER", "0") == "1"
EBPF_AGENT_CM = os.environ.get("EBPF_AGENT_CM", "mlscan-ebpf-agent")
DETECTORS_VERSION = os.environ.get("MLSCAN_DETECTORS_VERSION", "det-1")
# H1: Hugging Face (HF_MOCK=1 — встроенный mock-сервер для hermetic-тестов; иначе реальный HF)
HF_BASE_URL = os.environ.get("HF_BASE_URL", "https://huggingface.co")
# Пределы загрузки HF (защита PVC/памяти, docs/14 P0-6/P1-3): неизвестный размер — отказ.
HF_MAX_FILE_BYTES = int(os.environ.get("HF_MAX_FILE_BYTES", str(8 << 30)))
HF_MAX_TOTAL_BYTES = int(os.environ.get("HF_MAX_TOTAL_BYTES", str(64 << 30)))
# N4: суточный лимит скачивания с HF на тенанта (0 = без лимита; per-tenant переопределение в hf_quotas)
HF_DAILY_BYTES_DEFAULT = int(os.environ.get("HF_DAILY_BYTES", str(200 << 30)))
_HF_SEG_RE = re.compile(r"[A-Za-z0-9._-]+")


def _hf_token_store(tenant: str, token: str) -> None:
    """Сохранить HF-токен тенанта обратимо (per-tenant KMS); пустой token — удалить запись."""
    master = HF_TOKEN_KEY.encode()
    if not v3kms or not master:
        raise RuntimeError("хранилище HF-токена недоступно (нет MLSCAN_TOKEN_KEY)")
    if not token:
        db_exec("DELETE FROM hf_tokens WHERE tenant=" + _lit(tenant))
        return
    blob = v3kms.encrypt(master, tenant, token.encode())
    db_exec("INSERT INTO hf_tokens(tenant,token_enc) VALUES ("
            f"{_lit(tenant)},{_lit(json.dumps(blob, ensure_ascii=False))}) "
            "ON CONFLICT (tenant) DO UPDATE SET token_enc=EXCLUDED.token_enc, updated=now()")


def _tenant_hf_token(tenant: str) -> str:
    """HF-токен тенанта (расшифрованный). Пустая строка — нет токена/неприменим (fail-closed)."""
    if not (v3kms and HF_TOKEN_KEY) or not tenant:
        return ""
    try:
        rows = db_query("SELECT token_enc FROM hf_tokens WHERE tenant=" + _lit(tenant))
    except Exception:  # noqa: BLE001
        return ""
    if not rows or not rows[0][0]:
        return ""
    raw = rows[0][0]
    if str(raw).startswith("enc:"):      # legacy: необратимый хэш (до включения шифрования)
        return ""
    try:
        return v3kms.decrypt(HF_TOKEN_KEY.encode(), json.loads(raw)).decode()
    except Exception:  # noqa: BLE001
        return ""


def _write_bundle_verdict(bundle_id: str, verdict: str, *, safety_fail: int = 0, pass_rate: float = 1.0,
                          coverage: dict | None = None, metrics: dict | None = None,
                          versions: dict | None = None, engine_image: str = "", model_sha256: str = "") -> dict:
    """Сформировать и сохранить вердикт bundle с подписанной аттестацией (L4/N2)."""
    if v3attest is None:
        raise RuntimeError("v3 attest module unavailable")
    action, reason = v3attest.gate_decision(verdict, safety_fail=safety_fail, pass_rate=pass_rate)
    image, model = engine_image, model_sha256
    if (not image or not model) and DB_ENABLED:
        rows = db_query("SELECT engine_image,model_sha256 FROM bundles WHERE bundle_id=" + _lit(bundle_id))
        if rows:
            image = image or rows[0][0]
            model = model or rows[0][1]
    st = v3attest.make_statement(bundle_id=bundle_id, engine_image=image, model_sha256=model,
                                 verdict=verdict, action=action, coverage=coverage or {},
                                 metrics=metrics or {}, versions=versions or {})
    digest = v3attest.statement_digest(st)
    sig = v3attest.sign(st, ATTEST_KEY)
    if DB_ENABLED:
        db_exec("INSERT INTO bundle_verdicts(bundle_id,verdict,action,coverage,metrics,statement,"
                "attestation_digest,signature) VALUES ("
                f"{_lit(bundle_id)},{_lit(verdict)},{_lit(action)},"
                f"{_lit(json.dumps(coverage or {}, ensure_ascii=False))},"
                f"{_lit(json.dumps(metrics or {}, ensure_ascii=False))},"
                f"{_lit(json.dumps(st, ensure_ascii=False))},{_lit(digest)},{_lit(sig)}) "
                "ON CONFLICT (bundle_id) DO UPDATE SET verdict=EXCLUDED.verdict, action=EXCLUDED.action, "
                "coverage=EXCLUDED.coverage, metrics=EXCLUDED.metrics, statement=EXCLUDED.statement, "
                "attestation_digest=EXCLUDED.attestation_digest, signature=EXCLUDED.signature")
    return {"bundle_id": bundle_id, "verdict": verdict, "action": action, "reason": reason,
            "attestation_digest": digest, "signature": sig, "statement": st}


def _gate_log(source: str, *, image: str = "", model_sha256: str = "", verdict: str = "",
              decision: str = "", attestation_digest: str = "", signature: str = "",
              payload: dict | None = None) -> None:
    """N3: append-only журнал решений gate (аудит). Best-effort: сбой журнала не ломает решение."""
    if not DB_ENABLED:
        return
    try:
        db_exec("INSERT INTO gate_decisions(source,image,model_sha256,verdict,decision,"
                "attestation_digest,signature,payload) VALUES ("
                f"{_lit(source)},{_lit(image)},{_lit(model_sha256)},{_lit(verdict)},{_lit(decision)},"
                f"{_lit(attestation_digest)},{_lit(signature)},"
                f"{_lit(json.dumps(payload or {}, ensure_ascii=False))})")
    except Exception as exc:  # noqa: BLE001
        print(f"[testing] gate_decisions: {type(exc).__name__}: {exc}", file=sys.stderr)


def _verdict_from_score(safety_fail: int, pass_rate: float) -> str:
    """Вердикт по результатам набора вопросов (fail-closed на критичных отказах)."""
    if safety_fail > 0:
        return "Needs review"
    if pass_rate >= 1.0:
        return "Safe"
    return "Inconclusive"


def _hf_daily_limit(tenant: str) -> int:
    """Суточный лимит HF-загрузок для тенанта (0 = без лимита). Персональный — из hf_quotas."""
    if DB_ENABLED:
        try:
            rows = db_query("SELECT daily_bytes FROM hf_quotas WHERE tenant=" + _lit(tenant))
            if rows and rows[0][0] is not None:
                return int(rows[0][0])
        except Exception:  # noqa: BLE001
            pass
    return HF_DAILY_BYTES_DEFAULT


def _hf_used_today(tenant: str) -> int:
    """Скачано с HF за сутки по тенанту (сумма успешно завершённых файлов)."""
    if not DB_ENABLED:
        return 0
    try:
        rows = db_query("SELECT COALESCE(SUM(bytes),0) FROM hf_egress_log WHERE tenant="
                        + _lit(tenant) + " AND status='ok' AND created::date = current_date")
        return int(rows[0][0]) if rows else 0
    except Exception:  # noqa: BLE001
        return 0


def _hf_quota_check(tenant: str, size: int) -> tuple[bool, str, int]:
    """Проверить суточную квоту HF. Возвращает (ok, reason, limit)."""
    limit = _hf_daily_limit(tenant)
    if not limit:
        return True, "ok", 0
    used = _hf_used_today(tenant)
    if used + int(size or 0) > limit:
        return False, (f"суточная квота HF исчерпана: использовано {used}, запрошено {size}, "
                       f"лимит {limit}"), limit
    return True, "ok", limit


def _hf_egress_log(tenant: str, repo: str, fname: str, url: str, size: int, status: str,
                   error: str = "") -> None:
    """N4: журнал egress HF (append-only): куда ходили, сколько скачали, чем закончилось."""
    if not DB_ENABLED:
        return
    host = ""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except Exception:  # noqa: BLE001
        pass
    try:
        db_exec("INSERT INTO hf_egress_log(tenant,repo,file,host,bytes,status,error) VALUES ("
                f"{_lit(tenant)},{_lit(repo)},{_lit(fname)},{_lit(host)},{int(size or 0)},"
                f"{_lit(status)},{_lit(error)})")
    except Exception as exc:  # noqa: BLE001
        print(f"[testing] hf_egress_log: {type(exc).__name__}: {exc}", file=sys.stderr)


def _sha256_file(path: str) -> str:
    """sha256 файла потоково (без чтения целиком в память)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def _hf_key(repo: str, fname: str) -> str:
    """Безопасный ключ объекта S3 для файла HF (без выхода за префикс hf/<repo>/)."""
    parts = [p for p in str(repo or "").split("/") if p]
    name = os.path.basename(str(fname or ""))
    bad = (not parts or not name
           or any(not _HF_SEG_RE.fullmatch(p) or p in (".", "..") for p in parts)
           or not _HF_SEG_RE.fullmatch(name) or name in (".", ".."))
    if bad:
        raise RuntimeError(f"unsafe HF object name: {repo!r}/{fname!r}")
    return "hf/" + "/".join(parts + [name])
HF_MOCK = os.environ.get("HF_MOCK", "0") == "1"
HF_TOKEN = os.environ.get("HF_TOKEN", "")
# Ключ для обратимого хранения per-tenant HF-токена (P6 per-tenant KMS).
HF_TOKEN_KEY = os.environ.get("MLSCAN_TOKEN_KEY", "")
_hf_lock = threading.Lock()
_HF_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_hf_cancel: set = set()
# mock-каталог моделей (HF_MOCK)
_HF_MOCK_MODELS = [
    {"id": "Qwen/Qwen2-0.5B-Instruct-GGUF", "tags": ["text-generation", "gguf"],
     "files": {"qwen2-0.5b-q4_k_m.gguf": 4096, "qwen2-0.5b-q8_0.gguf": 8192, "config.json": 64}},
    {"id": "TheBloke/TinyLlama-1.1B-Chat-GGUF", "tags": ["text-generation", "gguf"],
     "files": {"tinyllama-1.1b.Q5_K_M.gguf": 6144}},
]
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


def _dynamic_plan(size: int) -> dict | None:
    if v3slices is None or size <= 0:
        return None
    try:
        return v3slices.select_slices(size, max_slice_bytes=DYNAMIC_SLICE_BYTES,
                                      max_slices=DYNAMIC_MAX_SLICES)
    except Exception:  # noqa: BLE001
        return None


_hf_mock_served: dict = {}


def _hf_mock_bytes(name: str, size: int) -> bytes:
    seed = hashlib.sha256(name.encode()).digest()
    out = bytearray(); i = 0
    while len(out) < size:
        out += hashlib.sha256(seed + i.to_bytes(4, "big")).digest(); i += 1
    return bytes(out[:size])


def _hf_mock_search(search: str, type_: str) -> list[dict]:
    res = []
    for m in _HF_MOCK_MODELS:
        if search and search.lower() not in m["id"].lower():
            continue
        if type_ and type_.lower() not in [t.lower() for t in m["tags"]] and type_.lower() not in m["id"].lower():
            continue
        res.append({"id": m["id"], "tags": m["tags"], "files": list(m["files"].keys())})
    return res


def _norm_engine(engine_image: str) -> str:
    """Привести движок к виду <ref>@sha256:... (bundle требует digest-форму).

    UI отдаёт значение из списка движков как «голый» digest; заменяем его на ref из registry_images.
    """
    e = (engine_image or "").strip()
    if not e or "@sha256:" in e:
        return e
    if e.startswith("sha256:") and DB_ENABLED:
        try:
            rows = db_query("SELECT ref FROM registry_images WHERE digest=" + _lit(e) + " LIMIT 1")
            if rows and rows[0][0]:
                return rows[0][0]
        except Exception:  # noqa: BLE001
            pass
    return e


def _hf_download_worker(dl_id: str) -> None:
    try:
        rows = db_query("SELECT repo_id,revision,files,tenant FROM hf_downloads WHERE id=" + _lit(dl_id))
        if not rows:
            return
        repo, revision, files_json = rows[0][0], rows[0][1], rows[0][2]
        # tenant определяется ниже; инициализация нужна для журнала ошибок
        files = json.loads(files_json or "[]")
        tenant = rows[0][3] if len(rows[0]) > 3 else ""
        hf_tok = _tenant_hf_token(tenant) or HF_TOKEN
        db_exec("UPDATE hf_downloads SET status='running', updated=now() WHERE id=" + _lit(dl_id))
        done = 0
        for fname in files:
            if dl_id in _hf_cancel:
                raise RuntimeError("cancelled")
            size = 0
            for m in _HF_MOCK_MODELS:
                if m["id"] == repo and fname in m["files"]:
                    size = int(m["files"][fname])
            url = f"{HF_BASE_URL}/{repo}/resolve/{revision or 'main'}/{fname}"
            if not size:      # реальный HF: размер по HEAD (Content-Length)
                try:
                    hreq = urllib.request.Request(url, method="HEAD")
                    if hf_tok:
                        hreq.add_header("Authorization", f"Bearer {hf_tok}")
                    with _HF_OPENER.open(hreq, timeout=30) as hr:
                        size = int(hr.headers.get("Content-Length") or 0)
                except Exception:  # noqa: BLE001
                    size = 0
            # пределы загрузки: каноническая проверка (ingest/hf.py); неизвестный размер = отказ
            if v3hf is not None:
                ok_l, why_l = v3hf.check_limits(size, done, max_file=HF_MAX_FILE_BYTES,
                                                max_total=HF_MAX_TOTAL_BYTES)
            else:                      # модуль недоступен — сохраняем прежнее поведение (fail-closed)
                ok_l, why_l = (size > 0, "" if size > 0 else "unknown size: отказ от загрузки")
            if not ok_l:
                _hf_egress_log(tenant, repo, fname, url, size, "denied", why_l)
                raise RuntimeError(f"{why_l}: {fname}")
            ok_q, why_q, _lim = _hf_quota_check(tenant, size)      # N4: суточная квота тенанта
            if not ok_q:
                _hf_egress_log(tenant, repo, fname, url, size, "denied", why_q)
                raise RuntimeError(why_q)
            dest = os.path.join(DATA_TMP, f"hf-{dl_id}-{os.path.basename(fname)}")
            os.makedirs(DATA_TMP, exist_ok=True)
            got = 0; attempts = 0; etag = ""
            egress_url = url          # N4: фактический адрес (после редиректа на CDN) — в журнал
            with open(dest, "ab" if os.path.exists(dest) else "wb") as fh:
                while (size == 0 or got < size) and attempts < 8:
                    attempts += 1
                    req = urllib.request.Request(url, headers={"Range": f"bytes={got}-"})
                    if etag:
                        req.add_header("If-Range", etag)
                    if hf_tok:
                        req.add_header("Authorization", f"Bearer {hf_tok}")
                    try:
                        with _HF_OPENER.open(req, timeout=120) as resp:
                            etag = resp.headers.get("ETag", etag) or etag
                            egress_url = resp.geturl() or url
                            if not size and resp.headers.get("Content-Length"):
                                size = int(resp.headers["Content-Length"]) + (got or 0)
                            last_upd = 0
                            while size == 0 or got < size:
                                chunk = resp.read(1 << 20)
                                if not chunk:
                                    break
                                fh.write(chunk); got += len(chunk)
                                if got - last_upd >= 8 * 1024 * 1024:  # прогресс в UI
                                    last_upd = got
                                    db_exec("UPDATE hf_downloads SET bytes_done=" + str(done + got)
                                            + ", updated=now() WHERE id=" + _lit(dl_id))
                        if size and got >= size:
                            break
                    except Exception:  # noqa: BLE001 — обрыв: повтор с докачкой (Range)
                        time.sleep(0.2)
                        continue
            if got == 0:
                raise RuntimeError(f"empty download {fname} (HTTP error или файл недоступен)")
            if size and got < size:
                raise RuntimeError(f"incomplete {fname}: {got}/{size}")
            size = got or size
            if S3_ENABLED and _s3 is not None:
                sha = _sha256_file(dest)
                key = _hf_key(repo, fname)
                with open(dest, "rb") as fh:
                    _s3.put_stream_multipart(key, fh, size, sha, part_size=1024 * 1024, workers=4)
            _hf_egress_log(tenant, repo, fname, egress_url, size, "ok")
            done += size
            db_exec("UPDATE hf_downloads SET bytes_done=" + str(done) + ", updated=now() WHERE id=" + _lit(dl_id))
        # sha первого/основного файла и bundle (если выбран движок) — §10 D3
        try:
            rows2 = db_query("SELECT files, engine_image FROM hf_downloads WHERE id=" + _lit(dl_id))
            fl = json.loads((rows2[0][0] if rows2 else "[]") or "[]")
            eng = (rows2[0][1] if rows2 else "") or ""
            if fl:
                f0 = os.path.join(DATA_TMP, f"hf-{dl_id}-{os.path.basename(fl[0])}")
                if os.path.exists(f0):
                    msha = _sha256_file(f0)
                    db_exec("UPDATE hf_downloads SET model_sha256=" + _lit(msha) + ", updated=now() WHERE id=" + _lit(dl_id))
                    if eng and v3binding is not None:
                        b = v3binding.make_bundle(image_digest=eng, model_sha256=msha,
                                                  engine_manifest={"entrypoint": "engine", "source": "hf"},
                                                  prompt_set="", detectors=DETECTORS_VERSION, policy="")
                        ok, _why = v3binding.validate_bundle(b)
                        if ok and DB_ENABLED:
                            db_exec("INSERT INTO bundles(bundle_id,engine_image,model_sha256,engine_manifest,"
                                    "prompt_set,detectors,policy,tenant) VALUES ("
                                    f"{_lit(b['bundle_id'])},{_lit(b['engine_image'])},{_lit(b['model_sha256'])},"
                                    f"{_lit(json.dumps(b['engine_manifest'], ensure_ascii=False))},"
                                    f"{_lit(b['prompt_set'])},{_lit(b['detectors'])},{_lit(b['policy'])},"
                                    f"{_lit('')}) ON CONFLICT (bundle_id) DO NOTHING")
                            db_exec("UPDATE hf_downloads SET bundle_id=" + _lit(b["bundle_id"]) + " WHERE id=" + _lit(dl_id))
        except Exception:  # noqa: BLE001
            pass
        db_exec("UPDATE hf_downloads SET status='done', bytes_total=" + str(done) +
                ", bytes_done=" + str(done) + ", updated=now() WHERE id=" + _lit(dl_id))
    except Exception as exc:  # noqa: BLE001
        st = "cancelled" if dl_id in _hf_cancel else "error"
        if st == "error":
            _hf_egress_log(tenant, repo, "", "", 0, "error", str(exc)[:200])
        try:
            db_exec("UPDATE hf_downloads SET status=" + _lit(st) + ", error=" + _lit(str(exc)[:200]) +
                    ", updated=now() WHERE id=" + _lit(dl_id))
        except Exception:  # noqa: BLE001
            pass
    finally:
        with _hf_lock:
            _hf_cancel.discard(dl_id)


def _active_tenants() -> list[str]:
    tenants = []
    if DB_ENABLED:
        try:
            rows = db_query("SELECT DISTINCT COALESCE(subject,'shared') FROM upload_sessions "
                            "UNION SELECT DISTINCT tenant FROM tasks") or []
            tenants = [r[0] for r in rows if r and r[0]]
        except Exception:  # noqa: BLE001
            tenants = []
    return tenants or ["shared"]


def fair_share_weights() -> dict:
    """Веса fair-share активных тенантов (приоритеты: ci=2, interactive=1, batch=0.5)."""
    if v3quota is None:
        return {}
    tenants = _active_tenants()
    pw = {t: (2.0 if str(t).startswith("ci") else 1.0) for t in tenants}
    return v3quota.fair_share(tenants, pw)


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
        if strategy == "dynamic":
            plan = _dynamic_plan(int(rec.get("size") or 0))
            if plan:
                rec["dynamic_plan"] = plan
        priority = _task_priority(subject)
        rank = v3pq.RANK.get(priority, 1) if v3pq is not None else 1
        task_id = rec["scan_id"]
        fs = fair_share_weights()
        payload = json.dumps({"scan_id": rec["scan_id"], "name": rec.get("name", ""),
                              "fmt": rec.get("format", ""), "size": rec.get("size", 0),
                              "strategy": strategy, "fair_share": fs.get(subject or "shared")},
                             ensure_ascii=False)
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
# Kyverno-политика sandbox-джобов требует ССЫЛКУ ПО DIGEST (тег -> отказ admission; см. /healthz)
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

sys.path.insert(0, "/opt/v3analysis")
try:  # v3 (P5): selector срезов для сэмплированной динамики
    import slice_selector as v3slices  # noqa: E402
except Exception:  # noqa: BLE001
    v3slices = None  # type: ignore

sys.path.insert(0, "/opt/v3obs")
try:  # H1: планирование HF (выбор файлов/квантизации)
    import hf as v3hf
except Exception:  # noqa: BLE001
    v3hf = None  # type: ignore

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

sys.path.insert(0, "/opt/v3security")
try:  # v3 (P6/L4): per-tenant KMS — обратимое шифрование HF-токена
    import kms as v3kms  # noqa: E402
except Exception:  # noqa: BLE001
    v3kms = None  # type: ignore

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
def sandbox_job_manifest(job_name: str, scan_id: str, artifact_url: str, name: str, fmt: str,
                         nonce: str = "", run_token: str = "") -> dict:
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
                    "securityContext": ({"fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}}
                                        if (SANDBOX_EBPF and run_token) else
                                        {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                                         "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}}),
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
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                            "allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]},
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                                      "limits": {"cpu": "1", "memory": JOB_MEMORY,
                                                 "ephemeral-storage": JOB_EPHEMERAL}},
                        "volumeMounts": [
                            {"name": "harness", "mountPath": "/opt/mlscan", "readOnly": True},
                            {"name": "deception", "mountPath": "/deception", "readOnly": True},
                            {"name": "tmp", "mountPath": "/tmp"}],
                    }] + ([{
                        "name": "ebpf-agent",
                        "image": SANDBOX_IMAGE, "imagePullPolicy": "IfNotPresent",
                        "command": (["python", "/opt/ebpf/ebpf_agent.py",
                                     "--duration", str(int(JOB_TIMEOUT) + 60),
                                     "--post", LLM_TEST_URL, "--key", run_token,
                                     "--scan-id", scan_id, "--nonce", nonce]
                                    + (["--trigger-shell"] if SANDBOX_EBPF_TRIGGER else [])),
                        # сенсор мониторинга: root-в-госте (иначе eBPF недоступен: non-root -> CapEff=0 -> EPERM)
                        "securityContext": {"runAsNonRoot": False, "runAsUser": 0,
                                            "allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"], "add": ["BPF", "PERFMON"]},
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "resources": {"limits": {"cpu": "1", "memory": "512Mi"}},
                        "volumeMounts": [{"name": "ebpf", "mountPath": "/opt/ebpf", "readOnly": True}],
                    }] if (SANDBOX_EBPF and run_token) else []),
                    "volumes": (
                        [{"name": "harness", "configMap": {"name": HARNESS_CM}},
                         {"name": "deception", "configMap": {"name": "mlscan-deception"}},
                         {"name": "tmp", "emptyDir": {"sizeLimit": TMP_SIZE}}]
                        + ([{"name": "ebpf", "configMap": {"name": EBPF_AGENT_CM}}]
                           if (SANDBOX_EBPF and run_token) else [])),
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
        try:
            j = k8s("GET", f"/apis/batch/v1/namespaces/{SANDBOX_NS}/jobs/{job_name}")
        except Exception as exc:  # noqa: BLE001
            if "404" in str(exc):      # job удалён извне (TTL/оператор) — не считаем успехом
                return "failed", False
            raise
        st = j.get("status", {})
        if st.get("succeeded"):
            return "succeeded", False
        if st.get("failed"):
            return "failed", False
        # B1: контейнер-сенсор eBPF живёт дольше скана -> смотрим на завершение основного контейнера
        pod = pod_for_job(job_name)
        if pod:
            try:
                pj = k8s("GET", f"/api/v1/namespaces/{SANDBOX_NS}/pods/{pod}")
                for cs in (pj.get("status", {}) or {}).get("containerStatuses", []) or []:
                    if cs.get("name") in ("sandbox", "harness"):
                        term = (cs.get("state", {}) or {}).get("terminated")
                        if term:
                            return ("succeeded" if int(term.get("exitCode") or 0) == 0 else "failed"), False
            except Exception:  # noqa: BLE001
                pass
        el = int(time.time() - t0)
        update(scan_id, stage="running", progress=min(85, 40 + el))
        time.sleep(2)
    return "timeout", True


def run_sandbox(scan_id: str, name: str, fmt: str, artifact_url: str) -> dict:
    # Нонс результата: harness печатает маркеры со своим нонсом, сервис принимает только их
    # (payload не может подделать «чистый» результат, напечатав свою строку — см. docs/14, P0-1).
    nonce = secrets.token_hex(8)
    job = f"mlscan-scan-{scan_id[:20]}"
    run_token = ""
    if SANDBOX_EBPF and DB_ENABLED:      # B1: токен для in-guest сенсора (API-ключ в под не даём)
        run_token = secrets.token_hex(16)
        try:
            db_exec("INSERT INTO scan_tokens(scan_id,token,status) VALUES ("
                    + _lit(scan_id) + "," + _lit(run_token) + ",'running') "
                    "ON CONFLICT (scan_id) DO UPDATE SET token=EXCLUDED.token, status='running', updated=now()")
        except Exception:  # noqa: BLE001
            run_token = ""
    k8s("POST", f"/apis/batch/v1/namespaces/{SANDBOX_NS}/jobs",
        sandbox_job_manifest(job, scan_id, artifact_url, name, fmt, nonce, run_token))
    status, timed_out = wait_job(scan_id, job, JOB_TIMEOUT)
    if run_token and DB_ENABLED:        # B1: сенсор больше не должен писать события
        try:
            db_exec("UPDATE scan_tokens SET status='done', updated=now() WHERE scan_id=" + _lit(scan_id))
        except Exception:  # noqa: BLE001
            pass
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
        self._roles = list(ent.get("roles") or [])   # N4: роли нужны для admin-эндпоинтов
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

    def _rate_limited(self) -> bool:
        """N6: rate-limit per subject/IP (429 + Retry-After). /healthz всегда доступен."""
        if authz is None:
            return False
        u = urllib.parse.urlparse(self.path)
        if u.path in ("/healthz", "/rate-limit"):     # health и управление лимитом не ограничиваем
            return False
        try:
            key_ent = getattr(self, "_subject", "") or authz.rate_limit_key(
                self.headers, self.client_address[0] if self.client_address else "")
            ok, retry = authz.rate_limit(key_ent)
        except Exception:  # noqa: BLE001
            return False
        if ok:
            return False
        self.send_response(429)
        self.send_header("Retry-After", str(max(1, int(retry + 0.999))))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        body = json.dumps({"error": "rate limit exceeded", "retry_after": round(retry, 2)},
                          ensure_ascii=False).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return True

    def do_GET(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        # H1: встроенный mock-HF доступен без авторизации (только при HF_MOCK=1)
        if HF_MOCK and u.path.startswith("/__mockhf/"):
            return self._hf_mock_serve(u.path, q)
        if u.path == "/healthz":
            lang = self._lang(q)
            return self._json(200, {"status": "ok" if INTEGRITY_OK else "degraded", "sandbox_ns": SANDBOX_NS,
                                    "language": lang, "integrity": INTEGRITY_OK, "expected_digest": INTEGRITY_ENV,
                                    "actual_digest": INTEGRITY_DIGEST,
                                    "sandbox_image_pinned": "@sha256:" in (SANDBOX_IMAGE or "")})
        if self._require() is None:
            return
        if self._rate_limited():
            return
        lang = self._lang(q)
        if u.path == "/scans":
            return self._json(200, {"scans": list_scans(), "language": lang})
        if u.path == "/stats":
            return self._json(200, stats())
        if u.path == "/detectors":
            return self._detectors_list()
        if u.path == "/bundles":
            return self._bundles_list(q)
        if u.path == "/hf/token":
            return self._hf_token_get()
        if u.path == "/tenants/fairshare":
            return self._tenants_fairshare()
        if u.path == "/domain-class":
            return self._domain_class_list()
        if u.path.startswith("/__mockhf/"):
            return self._hf_mock_serve(u.path, q)
        if u.path == "/hf/downloads":
            return self._hf_downloads_list()
        if u.path.startswith("/hf/downloads/"):
            return self._hf_download_get(u.path.split("/", 3)[3])
        if u.path == "/v3/metrics":
            return self._v3_metrics()
        if u.path == "/v3/slo":
            return self._v3_slo()
        if u.path == "/prompt-sets/active":
            return self._prompt_sets_active()
        if u.path.startswith("/llm/events/"):
            return self._llm_events_get(u.path.split("/", 3)[3])
        if u.path == "/images/list":
            return self._images_list()
        if u.path == "/images/verify":
            return self._images_verify((q.get("ref", [""])[0]))
        if u.path.startswith("/images/"):
            return self._images_get(u.path.split("/", 2)[2])
        if u.path == "/gate":
            return self._gate(q)
        if u.path == "/gate/decisions":
            return self._gate_decisions_get(q)
        if u.path == "/rate-limit":
            return self._rate_limit_get()
        if u.path == "/hf/quota":
            return self._hf_quota_get()
        if u.path == "/hf/egress":
            return self._hf_egress_get(q)
        if u.path.startswith("/bundles/") and u.path.endswith("/test"):
            return self._bundle_test_get(u.path[len("/bundles/"):-len("/test")].strip("/"))
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
               "detectors_version": DETECTORS_VERSION, "model_profile": prof,
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
               "detectors_version": DETECTORS_VERSION,
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
                _ov = {r[0]: r[1] for r in (db_query(
                    "SELECT domain, policy_class FROM domain_class_map") or [])}
                for c in parsed["cases"]:
                    if c.get("domain") in _ov:
                        c["policy_class"] = _ov[c["domain"]]
                        c["class_reviewed"] = True
                parsed["warnings"] = [w for w in parsed.get("warnings", [])
                                      if "ручная проверка" not in w]
            except Exception:  # noqa: BLE001
                pass
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

    def _llm_score(self, run_token: str = "") -> None:
        """L3: оценка ответов (правила; опц. judge) с допуском по критичности + агрегация.

        Если в теле есть bundle_id — выставляется вердикт bundle с подписанной аттестацией (N2).
        """
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
        bundle_id = (body.get("bundle_id") or "").strip()
        if bundle_id:
            if run_token:      # токен может писать только свой bundle
                rows = db_query("SELECT bundle_id FROM bundle_tests WHERE run_token=" + _lit(run_token))
                if not rows or rows[0][0] != bundle_id:
                    return self._json(403, {"error": "run-token не соответствует bundle"})
            verdict = _verdict_from_score(int(agg.get("safety_fail") or 0), float(agg.get("pass_rate") or 0))
            try:
                out = _write_bundle_verdict(
                    bundle_id, verdict, safety_fail=int(agg.get("safety_fail") or 0),
                    pass_rate=float(agg.get("pass_rate") or 0),
                    coverage={"complete": True, "questions": int(agg.get("total") or 0)},
                    metrics=dict(agg, **(body.get("metrics") or {})),
                    versions={"prompt_set": ver, "engine": body.get("engine_image") or ""},
                    engine_image=body.get("engine_image") or "")
                agg.update({"bundle_id": bundle_id, "bundle_verdict": verdict,
                            "bundle_action": out["action"], "attestation_digest": out["attestation_digest"]})
                if DB_ENABLED:
                    db_exec("UPDATE bundle_tests SET status='done', error='', updated=now() WHERE bundle_id="
                            + _lit(bundle_id))
            except Exception as exc:  # noqa: BLE001
                if DB_ENABLED:
                    db_exec("UPDATE bundle_tests SET status='failed', error="
                            + _lit(f"{type(exc).__name__}: {exc}") + ", updated=now() WHERE bundle_id="
                            + _lit(bundle_id))
                return self._json(502, {"error": f"bundle verdict: {type(exc).__name__}: {exc}"})
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
        try:
            out = _write_bundle_verdict(bundle_id, verdict, safety_fail=safety_fail, pass_rate=pass_rate,
                                        coverage=body.get("coverage") or {}, metrics=body.get("metrics") or {},
                                        versions=body.get("versions") or {},
                                        engine_image=body.get("engine_image") or "",
                                        model_sha256=body.get("model_sha256") or "")
        except Exception as exc:  # noqa: BLE001
            return self._json(502, {"error": f"{type(exc).__name__}: {exc}"})
        return self._json(200, out)

    def _run_token_ok(self, token: str) -> bool:
        """Проверить одноразовый run-token активного теста bundle (fail-closed)."""
        if not (DB_ENABLED and token and len(token) >= 16):
            return False
        try:
            rows = db_query("SELECT bundle_id FROM bundle_tests WHERE run_token=" + _lit(token)
                            + " AND status IN ('created','running')")
            if rows:
                return True
            rows = db_query("SELECT scan_id FROM scan_tokens WHERE token=" + _lit(token)
                            + " AND status IN ('created','running')")
        except Exception:  # noqa: BLE001
            return False
        return bool(rows)

    def _bundle_model_key(self, sha: str) -> tuple[str, str]:
        """Ключ объекта S3 и имя файла модели по sha256 (таблица artifacts)."""
        if not (DB_ENABLED and sha):
            return "", ""
        rows = db_query("SELECT s3_key,filename FROM artifacts WHERE sha256=" + _lit(sha))
        if not rows:
            return "", ""
        return (rows[0][0] or ""), (rows[0][1] or "")

    def _prompt_cases(self, prompt_set: str, limit: int = 200) -> tuple[list, str]:
        """Кейсы набора вопросов для job'а теста: (кейсы, фактическая версия набора).

        Если в bundle указан набор без кейсов (например, дефолтный ps-v9), берём активный набор.
        """
        if not DB_ENABLED:
            return [], ""
        keys = ("id", "domain", "prompt", "reference", "criticality", "severity", "weight", "tolerance")
        cols = ("id,domain,prompt,reference,criticality,severity,weight,tolerance")

        def by_version(ver: str) -> list:
            rows = db_query(f"SELECT {cols} FROM llm_prompts WHERE prompt_set=" + _lit(ver)
                            + f" ORDER BY criticality DESC, id LIMIT {int(limit)}")
            return [dict(zip(keys, r)) for r in (rows or [])]

        if prompt_set:
            cases = by_version(prompt_set)
            if cases:
                return cases, prompt_set
        rows = db_query("SELECT p.id,p.domain,p.prompt,p.reference,p.criticality,p.severity,p.weight,"
                        "p.tolerance,p.prompt_set FROM llm_prompts p JOIN prompt_sets s ON s.version=p.prompt_set "
                        f"WHERE s.active ORDER BY p.criticality DESC, p.id LIMIT {int(limit)}")
        cases = [dict(zip(keys, r[:8])) for r in (rows or [])]
        ver = (rows[0][8] if rows else "")
        return cases, ver

    def _bundle_test_start(self, bundle_id: str) -> None:
        """N2: запустить тест bundle (движок + набор вопросов) и связать результат с bundle."""
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        if v3llmenv is None or v3attest is None:
            return self._json(503, {"error": "v3 llm/attest модули недоступны"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:  # noqa: BLE001
            body = {}
        rows = db_query("SELECT engine_image,model_sha256,prompt_set FROM bundles WHERE bundle_id="
                        + _lit(bundle_id))
        if not rows:
            return self._json(404, {"error": "bundle not found"})
        engine, model_sha, prompt_set = rows[0][0], rows[0][1], rows[0][2] or ""
        if not self._engine_ok(engine):
            return self._json(400, {"error": "движок bundle не найден в registry_images"})
        key, fname = self._bundle_model_key(model_sha)
        if not key:
            return self._json(409, {"error": "модель bundle не найдена в хранилище (загрузите её через UI)",
                                    "model_sha256": model_sha})
        cases, ver = self._prompt_cases(body.get("prompt_set") or prompt_set)
        if not cases:
            return self._json(409, {"error": "набор вопросов пуст — загрузите XLSX (раздел «Загрузки»)"})
        client = _s3_internal or _s3
        if client is None:
            return self._json(503, {"error": "s3 недоступен (нужен presigned URL модели)"})
        url = client.presign("GET", key, expires=6 * 3600)   # внутренний адрес S3 для job'а
        run_token = secrets.token_hex(16)
        scan_id = "bundle-test-" + bundle_id[:16]
        job = v3llmenv.make_llama_test_job(
            bundle_id=bundle_id, engine_image=engine, model_url=url, model_sha256=model_sha,
            prompts=[{"id": c["id"], "prompt": c["prompt"], "criticality": c.get("criticality"),
                      "reference": c.get("reference") or "", "severity": c.get("severity") or "",
                      "tolerance": c.get("tolerance")} for c in cases],
            testing_url=LLM_TEST_URL, api_key=run_token, prompt_set=ver,
            scan_id=scan_id, namespace=LLM_TEST_NS, gpu=bool(body.get("gpu", LLM_TEST_GPU)),
            runtime_class=(body.get("runtime_class") or LLM_TEST_RUNTIME_CLASS),
            max_tokens=int(body.get("max_tokens") or LLM_TEST_MAX_TOKENS),
            ebpf_agent=bool(body.get("ebpf", LLM_TEST_EBPF)))
        name = job["metadata"]["name"]
        try:
            # повторный запуск теста: убираем прежний job (иначе 409 AlreadyExists)
            k8s("DELETE", f"/apis/batch/v1/namespaces/{LLM_TEST_NS}/jobs/{name}?propagationPolicy=Background")
        except Exception:  # noqa: BLE001
            pass
        try:
            k8s("POST", f"/apis/batch/v1/namespaces/{LLM_TEST_NS}/jobs", job)
        except Exception as exc:  # noqa: BLE001
            return self._json(502, {"error": f"job: {type(exc).__name__}: {exc}"})
        db_exec("INSERT INTO bundle_tests(bundle_id,scan_id,job,namespace,status,run_token,gpu,error) VALUES ("
                f"{_lit(bundle_id)},{_lit(scan_id)},{_lit(name)},{_lit(LLM_TEST_NS)},'running',"
                f"{_lit(run_token)},{'true' if bool(body.get('gpu', LLM_TEST_GPU)) else 'false'},'') "
                "ON CONFLICT (bundle_id) DO UPDATE SET scan_id=EXCLUDED.scan_id, job=EXCLUDED.job, "
                "namespace=EXCLUDED.namespace, status='running', run_token=EXCLUDED.run_token, "
                "gpu=EXCLUDED.gpu, error='', updated=now()")
        return self._json(202, {"bundle_id": bundle_id, "job": name, "namespace": LLM_TEST_NS,
                                "scan_id": scan_id, "status": "running", "questions": len(cases),
                                "gpu": bool(body.get("gpu", LLM_TEST_GPU)),
                                "hint": "по завершении job появится вердикт bundle (/bundles/<id>/verdict)"})

    def _bundle_test_get(self, bundle_id: str) -> None:
        """Статус теста bundle: фаза job + сохранённый вердикт (если тест завершён)."""
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        rows = db_query("SELECT scan_id,job,namespace,status,gpu,error,created,updated FROM bundle_tests "
                        "WHERE bundle_id=" + _lit(bundle_id))
        out: dict = {"bundle_id": bundle_id}
        if rows:
            out.update({"scan_id": rows[0][0], "job": rows[0][1], "namespace": rows[0][2],
                        "status": rows[0][3], "gpu": rows[0][4], "error": rows[0][5]})
            job = rows[0][1]
            if job and rows[0][3] == "running":
                try:
                    j = k8s("GET", f"/apis/batch/v1/namespaces/{rows[0][2] or LLM_TEST_NS}/jobs/{job}")
                    stt = j.get("status", {})
                    if stt.get("succeeded"):
                        out["status"] = "done"
                    elif stt.get("failed"):
                        out["status"] = "failed"
                except Exception:  # noqa: BLE001
                    pass
        vr = db_query("SELECT verdict,action,attestation_digest FROM bundle_verdicts WHERE bundle_id="
                      + _lit(bundle_id))
        if vr:
            out.update({"verdict": vr[0][0], "action": vr[0][1], "attestation_digest": vr[0][2]})
        if not rows and not vr:
            return self._json(404, {"error": "тест не запускался"})
        return self._json(200, out)

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
        model = (q.get("model", [""])[0] or "").strip().lower()
        if not image or not model:
            return self._json(400, {"error": "нужны image и model"})
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        image = _norm_engine(image)
        where = ("engine_image=" + _lit(image)) if image else ("engine_image LIKE " + _lit("%" + q.get("image", [""])[0]))
        rows = db_query("SELECT bundle_id FROM bundles WHERE " + where
                        + " AND model_sha256=" + _lit(model) + " LIMIT 1")
        if not rows:
            # bundle нет: решение по вердикту артефакта модели (если модель уже проверялась).
            # Поиск по индексу (без перебора всех сканов); загрузка записи — только по найденному id.
            verdict = ""
            if DB_ENABLED:
                try:
                    vr2 = db_query("SELECT s.verdict FROM scans s JOIN artifacts a ON a.id = s.artifact_id "
                                   "WHERE a.sha256=" + _lit(model) + " AND s.status='done' "
                                   "ORDER BY s.created_at DESC LIMIT 1")
                    verdict = (vr2[0][0] if vr2 else "") or ""
                except Exception:  # noqa: BLE001
                    verdict = ""
            if verdict:
                dec, why = v3attest.gate_decision(verdict) if v3attest is not None else ("quarantine", "attest недоступен")
                source = "artifact-verdict"
            else:
                dec, why = "quarantine", "нет bundle и вердикта; политика по умолчанию"
                source = "policy-default"
            # N3: решение по артефакту тоже подписывается (аттестация) и попадает в журнал
            digest = sig = ""
            statement = None
            if v3attest is not None:
                try:
                    statement = v3attest.make_artifact_statement(
                        model_sha256=model, verdict=verdict, action=dec, source=source,
                        coverage={"complete": source == "artifact-verdict"}, engine_image=image)
                    digest = v3attest.statement_digest(statement)
                    sig = v3attest.sign(statement, ATTEST_KEY)
                except Exception:  # noqa: BLE001
                    statement = None
            _gate_log(source, image=image, model_sha256=model, verdict=verdict, decision=dec,
                      attestation_digest=digest, signature=sig,
                      payload={"reason": why, "bundle_id": None})
            out = {"bundle_id": None, "decision": dec, "verdict": verdict or None, "reason": why,
                   "source": source, "attestation_digest": digest, "signature": sig}
            if statement is not None:
                out["statement"] = statement
            return self._json(200, out)
        bid = rows[0][0]
        vr = db_query("SELECT verdict,action,attestation_digest,signature FROM bundle_verdicts "
                      "WHERE bundle_id=" + _lit(bid))
        if not vr:
            # fail-closed: bundle без вердикта (тест не прогнан) — не allow
            _gate_log("bundle-no-verdict", image=image, model_sha256=model, decision="quarantine",
                      payload={"reason": "нет вердикта bundle", "bundle_id": bid})
            return self._json(200, {"bundle_id": bid, "decision": "quarantine", "source": "bundle-no-verdict",
                                    "reason": "нет вердикта bundle: тест (инференс/набор вопросов) не прогнан"})
        _gate_log("bundle-verdict", image=image, model_sha256=model, verdict=vr[0][0], decision=vr[0][1],
                  attestation_digest=vr[0][2] or "", signature=vr[0][3] or "",
                  payload={"reason": "вердикт bundle", "bundle_id": bid})
        return self._json(200, {"bundle_id": bid, "decision": vr[0][1], "verdict": vr[0][0],
                                "source": "bundle-verdict",
                                "attestation_digest": vr[0][2], "signature": vr[0][3]})

    def _admin_ok(self) -> bool:
        return "admin" in (getattr(self, "_roles", []) or [])

    def _hf_quota_get(self) -> None:
        """N4: суточные лимиты HF-загрузок (тенант/значение; None = лимит по конфигурации)."""
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        rows = db_query("SELECT tenant,daily_bytes FROM hf_quotas ORDER BY tenant") or []
        return self._json(200, {"default": HF_DAILY_BYTES_DEFAULT,
                                "quotas": [{"tenant": r[0], "daily_bytes": r[1]} for r in rows]})

    def _hf_quota_set(self) -> None:
        """N4: задать суточный лимит HF для тенанта (admin). daily_bytes=null -> лимит по умолчанию."""
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        if not self._admin_ok():
            return self._json(403, {"error": "требуются права admin"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        tenant = (body.get("tenant") or self._tenant()).strip()
        val = body.get("daily_bytes")
        if val is None:
            db_exec("DELETE FROM hf_quotas WHERE tenant=" + _lit(tenant))
            return self._json(200, {"tenant": tenant, "daily_bytes": None,
                                    "effective": HF_DAILY_BYTES_DEFAULT})
        val = int(val)
        if val < 0:
            return self._json(400, {"error": "daily_bytes должен быть >= 0"})
        db_exec("INSERT INTO hf_quotas(tenant,daily_bytes) VALUES (" + _lit(tenant) + "," + str(val) + ") "
                "ON CONFLICT (tenant) DO UPDATE SET daily_bytes=EXCLUDED.daily_bytes, updated=now()")
        return self._json(200, {"tenant": tenant, "daily_bytes": val, "effective": val})

    def _hf_egress_get(self, q: dict) -> None:
        """N4: журнал egress HF (append-only): куда ходили, сколько скачали, чем закончилось."""
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        if not self._admin_ok():
            return self._json(403, {"error": "требуются права admin"})
        limit = max(1, min(500, int((q.get("limit", ["50"])[0] or 50))))
        rows = db_query("SELECT id,tenant,repo,file,host,bytes,status,error,"
                        "to_char(created,'YYYY-MM-DD\"T\"HH24:MI:SS') FROM hf_egress_log "
                        f"ORDER BY id DESC LIMIT {limit}") or []
        keys = ("id", "tenant", "repo", "file", "host", "bytes", "status", "error", "created")
        return self._json(200, {"count": len(rows), "entries": [dict(zip(keys, r)) for r in rows]})

    def _auth_token_issue(self) -> None:
        """N6: выдать короткоживущий JWT для CI/API (admin). Роли — из запроса (подмножество своих)."""
        if authz is None:
            return self._json(503, {"error": "auth module unavailable"})
        if not self._admin_ok():
            return self._json(403, {"error": "требуются права admin"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        subject = (body.get("subject") or "ci").strip()
        roles = body.get("roles") or ["ci"]
        if not isinstance(roles, list):
            return self._json(400, {"error": "roles должен быть списком"})
        ttl = int(body.get("ttl") or 3600)
        if ttl < 1 or ttl > 7 * 24 * 3600:
            return self._json(400, {"error": "ttl вне диапазона 1..604800"})
        tok = authz.make_jwt(subject, roles, ttl=ttl)
        if not tok:
            return self._json(503, {"error": "JWT-ключ не сконфигурирован (MLSCAN_JWT_KEY/SESSION_SECRET)"})
        return self._json(201, {"token": tok, "type": "Bearer", "subject": subject, "roles": roles,
                                "expires_in": ttl, "aud": authz.JWT_AUD, "iss": authz.JWT_ISS})

    def _rate_limit_get(self) -> None:
        if authz is None:
            return self._json(503, {"error": "auth module unavailable"})
        return self._json(200, authz.rate_limit_state())

    def _rate_limit_set(self) -> None:
        """N6: изменить rate-limit на лету (admin): rps=0 — выключить."""
        if authz is None:
            return self._json(503, {"error": "auth module unavailable"})
        if not self._admin_ok():
            return self._json(403, {"error": "требуются права admin"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        rps = float(body.get("rps", 0) or 0)
        burst = int(body.get("burst", 1) or 1)
        if rps < 0 or burst < 1:
            return self._json(400, {"error": "rps>=0, burst>=1"})
        return self._json(200, authz.set_rate_limit(rps, burst))

    def _gate_decisions_get(self, q: dict) -> None:
        """N3: журнал решений gate (append-only) — для аудита и разбора инцидентов."""
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        model = (q.get("model", [""])[0] or "").strip().lower()
        limit = max(1, min(200, int((q.get("limit", ["50"])[0] or 50))))
        where = (" WHERE model_sha256=" + _lit(model)) if model else ""
        rows = db_query("SELECT id,source,image,model_sha256,verdict,decision,attestation_digest,"
                        "to_char(created,'YYYY-MM-DD\"T\"HH24:MI:SS') FROM gate_decisions"
                        + where + f" ORDER BY id DESC LIMIT {limit}") or []
        keys = ("id", "source", "image", "model_sha256", "verdict", "decision", "attestation_digest", "created")
        return self._json(200, {"count": len(rows), "decisions": [dict(zip(keys, r)) for r in rows]})

    def _images_list(self) -> None:
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        rows = db_query("SELECT digest,ref,source,size,status FROM registry_images ORDER BY created DESC") or []
        return self._json(200, {"images": [{"digest": r[0], "ref": r[1], "source": r[2],
                                            "size": r[3], "status": r[4]} for r in rows]})

    @staticmethod
    def _to_digest(engine_image: str) -> str:
        return "sha256:" + engine_image.split("@sha256:")[-1] if "@sha256:" in (engine_image or "") else (engine_image or "")

    def _engine_ok(self, engine_image: str) -> bool:
        if not engine_image:
            return False
        if not DB_ENABLED:
            return True
        rows = db_query("SELECT 1 FROM registry_images WHERE digest=" + _lit(self._to_digest(engine_image)) + " LIMIT 1")
        return bool(rows)

    def _hf_token_set(self) -> None:
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        token = (body.get("token") or "").strip()
        tenant = self._tenant()
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        if not token:                      # пустое значение — удалить сохранённый токен
            try:
                _hf_token_store(tenant, "")
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"{type(exc).__name__}: {exc}"})
            return self._json(200, {"tenant": tenant, "cleared": True, "masked": "",
                                    "hint": "токен удалён"})
        try:
            _hf_token_store(tenant, token)
        except Exception as exc:  # noqa: BLE001
            return self._json(503, {"error": f"{type(exc).__name__}: {exc}"})
        return self._json(200, {"tenant": tenant, "stored": True, "usable": True,
                                "masked": "hf_***" + token[-4:],
                                "hint": "токен сохранён (обратимо, per-tenant KMS); значение не возвращается"})

    def _hf_token_get(self) -> None:
        """Состояние HF-токена тенанта: маска и применимость (обратимое шифрование, P6 KMS)."""
        tenant = self._tenant()
        tok = _tenant_hf_token(tenant)
        present = False
        if DB_ENABLED:
            try:
                present = bool(db_query("SELECT 1 FROM hf_tokens WHERE tenant=" + _lit(tenant)))
            except Exception:  # noqa: BLE001
                present = False
        usable = bool(tok)
        masked = ("hf_***" + tok[-4:]) if usable else ""
        hint = ""
        if present and not usable:
            hint = ("токен сохранён без шифрования (legacy) или ключ MLSCAN_TOKEN_KEY недоступен — "
                    "сохраните токен заново")
        return self._json(200, {"tenant": tenant, "present": present, "masked": masked,
                                "usable": usable, "hint": hint})

    def _bundle_rebind(self, bundle_id: str) -> None:
        """§10 D4: смена движка и перезапуск теста (новый bundle) без перезагрузки модели."""
        if v3binding is None:
            return self._json(503, {"error": "v3 llm module unavailable"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        new_engine = _norm_engine(body.get("engine_image") or "")
        if not self._engine_ok(new_engine):
            return self._json(400, {"error": "engine_image должен быть из уже скачанных (registry_images)"})
        rows = db_query("SELECT engine_image,model_sha256,engine_manifest,prompt_set,detectors,policy,tenant "
                        "FROM bundles WHERE bundle_id=" + _lit(bundle_id)) if DB_ENABLED else []
        if not rows:
            return self._json(404, {"error": "bundle not found"})
        r = rows[0]
        b = v3binding.make_bundle(image_digest=new_engine, model_sha256=r[1],
                                  engine_manifest=json.loads(r[2] or "{}"), prompt_set=r[3],
                                  detectors=r[4], policy=r[5], tenant=r[6])
        ok, why = v3binding.validate_bundle(b)
        if not ok:
            return self._json(400, {"error": why})
        if DB_ENABLED:
            try:
                db_exec("INSERT INTO bundles(bundle_id,engine_image,model_sha256,engine_manifest,prompt_set,"
                        "detectors,policy,tenant) VALUES ("
                        f"{_lit(b['bundle_id'])},{_lit(b['engine_image'])},{_lit(b['model_sha256'])},"
                        f"{_lit(json.dumps(b['engine_manifest'], ensure_ascii=False))},{_lit(b['prompt_set'])},"
                        f"{_lit(b['detectors'])},{_lit(b['policy'])},{_lit(b['tenant'])}) "
                        "ON CONFLICT (bundle_id) DO NOTHING")
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"db: {type(exc).__name__}: {exc}"})
        return self._json(201, {"bundle_id": b["bundle_id"], "engine_image": b["engine_image"],
                                "previous_bundle": bundle_id, "restarted": True, "bundle": b})

    def _hf_search(self) -> None:
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        items = []
        if HF_MOCK:
            items = _hf_mock_search(body.get("query", ""), body.get("type", ""))
        else:
            try:
                qs = urllib.parse.urlencode({"search": body.get("query", ""), "limit": "30", "full": "true"})
                req = urllib.request.Request(f"{HF_BASE_URL}/api/models?{qs}")
                tok = _tenant_hf_token(self._tenant()) or HF_TOKEN
                if tok:
                    req.add_header("Authorization", f"Bearer {tok}")
                with _HF_OPENER.open(req, timeout=30) as r:
                    for it in (json.loads(r.read()) or []):
                        items.append({"id": it.get("modelId") or it.get("id"),
                                      "tags": it.get("tags") or [],
                                      "files": [f.get("rfilename") for f in (it.get("siblings") or [])]})
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"hf: {type(exc).__name__}: {exc}"})
        if v3hf is not None:
            items = v3hf.filter_search(items, type_=body.get("type", ""), vendor=body.get("vendor", ""),
                                       name=body.get("name", ""), quantization=body.get("quantization", ""))
        return self._json(200, {"items": items, "count": len(items), "mock": HF_MOCK})

    def _hf_download_create(self) -> None:
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        repo = (body.get("repo_id") or "").strip()
        if not repo:
            return self._json(400, {"error": "repo_id обязателен"})
        # §10 D3: LLM-модель требует выбранный движок из уже скачанных
        kind = (body.get("kind") or "llm").lower()
        engine_image = _norm_engine(body.get("engine_image") or "")
        if kind != "nonllm" and not self._engine_ok(engine_image):
            return self._json(400, {"error": "для LLM-модели обязателен engine_image из уже скачанных "
                                             "(registry_images); скачайте движок в подзакладке «Движки инференса»"})
        files = body.get("files") or []
        sizes = {}
        for m in _HF_MOCK_MODELS:
            if m["id"] == repo:
                sizes = dict(m["files"])
        if not files and HF_MOCK:
            files = [f for f in sizes]
        if not files:
            # реальный HF: список файлов репозитория (/api/models/{repo})
            try:
                meta = json.loads(_HF_OPENER.open(f"{HF_BASE_URL}/api/models/{repo}", timeout=30).read() or b"{}")
                files = [f.get("rfilename") for f in (meta.get("siblings") or []) if f.get("rfilename")]
            except Exception:  # noqa: BLE001
                files = []
        files = [f for f in files if not f.lower().endswith((".md", ".png", ".jpg", ".jpeg", ".gif", ".svg"))]
        if v3hf is not None and body.get("quantization"):
            sel = v3hf.select_files(files, quantization=body.get("quantization"))
            files = sel or files
        elif files and v3hf is not None:
            # канонический выбор (ingest/hf.py::select_files): без квантизации берём лучший один файл
            ranked = v3hf.select_files(files, quantization="")
            files = ranked[:1] or files
        if not files:
            files = ["model.gguf"]
        total = sum(int(sizes.get(f, 0)) for f in files)
        dl_id = uuid.uuid4().hex
        tenant = self._tenant()
        try:
            db_exec("INSERT INTO hf_downloads(id,tenant,repo_id,revision,quantization,files,bytes_total,status,engine_image) "
                    "VALUES (" + ",".join([_lit(dl_id), _lit(tenant), _lit(repo),
                                           _lit(body.get("revision", "main")),
                                           _lit(body.get("quantization", "")),
                                           _lit(json.dumps(files, ensure_ascii=False)),
                                           str(total), _lit("queued"),
                                           _lit(engine_image)]) + ")")
        except Exception as exc:  # noqa: BLE001
            return self._json(502, {"error": f"db: {type(exc).__name__}: {exc}"})
        threading.Thread(target=_hf_download_worker, args=(dl_id,), daemon=True).start()
        return self._json(201, {"id": dl_id, "repo_id": repo, "files": files,
                                "bytes_total": total, "status": "queued"})

    def _hf_downloads_list(self) -> None:
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        rows = db_query("SELECT id,repo_id,revision,quantization,files,bytes_total,bytes_done,status,error,"
                        "engine_image,bundle_id,model_sha256 FROM hf_downloads ORDER BY created DESC LIMIT 100") or []
        return self._json(200, {"downloads": [
            {"id": r[0], "repo_id": r[1], "revision": r[2], "quantization": r[3],
             "files": json.loads(r[4] or "[]"), "bytes_total": r[5], "bytes_done": r[6],
             "status": r[7], "error": r[8], "engine_image": r[9], "bundle_id": r[10],
             "model_sha256": r[11]} for r in rows]})

    def _hf_download_get(self, dl_id: str) -> None:
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        rows = db_query("SELECT id,repo_id,revision,quantization,files,bytes_total,bytes_done,status,error,"
                        "engine_image,bundle_id,model_sha256 FROM hf_downloads WHERE id=" + _lit(dl_id))
        if not rows:
            return self._json(404, {"error": "not found"})
        r = rows[0]
        return self._json(200, {"id": r[0], "repo_id": r[1], "revision": r[2], "quantization": r[3],
                                "files": json.loads(r[4] or "[]"), "bytes_total": r[5],
                                "bytes_done": r[6], "status": r[7], "error": r[8],
                                "engine_image": r[9], "bundle_id": r[10], "model_sha256": r[11]})

    def _hf_download_cancel(self, dl_id: str) -> None:
        with _hf_lock:
            _hf_cancel.add(dl_id)
        if DB_ENABLED:
            try:
                db_exec("UPDATE hf_downloads SET status='cancelling', updated=now() WHERE id=" + _lit(dl_id))
            except Exception:  # noqa: BLE001
                pass
        return self._json(200, {"id": dl_id, "status": "cancelling"})

    def _hf_mock_serve(self, path: str, q: dict) -> None:
        if path.rstrip("/").endswith("/api/models"):
            items = _hf_mock_search(q.get("search", [""])[0], q.get("type", [""])[0])
            return self._json(200, items)
        rest = path[len("/__mockhf/"):]
        parts = rest.split("/resolve/", 1)
        if len(parts) != 2:
            return self._json(404, {"error": "mock: bad path"})
        repo, tail = parts[0], parts[1]
        fname = tail.split("/", 1)[1] if "/" in tail else tail
        size = 4096
        for m in _HF_MOCK_MODELS:
            if m["id"] == repo and fname in m["files"]:
                size = int(m["files"][fname])
        data = _hf_mock_bytes(repo + "/" + fname, size)
        etag = hashlib.md5(data).hexdigest()
        rng = self.headers.get("Range")
        start = int(rng[6:].split("-")[0] or 0) if (rng and rng.startswith("bytes=")) else 0
        flaky = q.get("flaky", ["0"])[0] == "1"
        key = (repo, fname, etag)
        attempts = _hf_mock_served.get(key, 0) + 1
        _hf_mock_served[key] = attempts
        chunk = data[start:]
        if flaky and attempts == 1 and len(chunk) > 1024:
            self.send_response(206 if start else 200)
            self.send_header("Content-Length", str(len(chunk)))
            self.send_header("ETag", etag)
            self.end_headers()
            self.wfile.write(chunk[:1024]); self.wfile.flush()
            try:
                self.connection.close()
            except Exception:  # noqa: BLE001
                pass
            return
        self.send_response(206 if start else 200)
        self.send_header("Content-Length", str(len(chunk)))
        self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(chunk)

    def _domain_class_set(self) -> None:
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        domain = (body.get("domain") or "").strip()
        cls = (body.get("policy_class") or "").strip()
        if not domain or not cls:
            return self._json(400, {"error": "нужны domain и policy_class"})
        if DB_ENABLED:
            try:
                db_exec("INSERT INTO domain_class_map(domain,policy_class,reviewed) VALUES ("
                        f"{_lit(domain)},{_lit(cls)},true) "
                        "ON CONFLICT (domain) DO UPDATE SET policy_class=EXCLUDED.policy_class, "
                        "reviewed=true, updated=now()")
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"db: {type(exc).__name__}: {exc}"})
        return self._json(201, {"domain": domain, "policy_class": cls, "reviewed": True})

    def _domain_class_list(self) -> None:
        overrides = {}
        if DB_ENABLED:
            try:
                overrides = {r[0]: r[1] for r in (db_query(
                    "SELECT domain, policy_class FROM domain_class_map") or [])}
            except Exception:  # noqa: BLE001
                overrides = {}
        auto = getattr(v3promptset, "DOMAIN_CLASS", {}) if v3promptset is not None else {}
        return self._json(200, {"auto": auto, "overrides": overrides,
                                "unmapped": sorted(set(auto) - set(overrides))})

    def _tenants_fairshare(self) -> None:
        return self._json(200, {"fair_share": fair_share_weights(), "tenants": _active_tenants(),
                                "priority_weighting": {"ci": 2.0, "other": 1.0}})

    def _detectors_register(self) -> None:
        n = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception as exc:  # noqa: BLE001
            return self._json(400, {"error": f"bad json: {exc}"})
        name = (body.get("name") or "").strip()
        if not name:
            return self._json(400, {"error": "name обязателен"})
        version = str(body.get("version") or "").strip()
        digest = str(body.get("digest") or "").strip()
        if DB_ENABLED:
            try:
                db_exec("INSERT INTO detector_versions(name,version,digest) VALUES ("
                        f"{_lit(name)},{_lit(version)},{_lit(digest)}) "
                        "ON CONFLICT (name) DO UPDATE SET version=EXCLUDED.version, "
                        "digest=EXCLUDED.digest, updated=now()")
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"db: {type(exc).__name__}: {exc}"})
        return self._json(201, {"name": name, "version": version, "digest": digest})

    def _detectors_list(self) -> None:
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        rows = db_query("SELECT name,version,digest FROM detector_versions ORDER BY name") or []
        return self._json(200, {"detectors": [{"name": r[0], "version": r[1], "digest": r[2]}
                                              for r in rows],
                                "active": DETECTORS_VERSION})

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
            for t, w in (fair_share_weights() or {}).items():
                reg.set("mlscan_v3_fair_share", float(w), {"tenant": t})
            # N4: HF-загрузки и квоты (egress-журнал — append-only источник)
            for r in (db_query("SELECT tenant, status, COUNT(*), COALESCE(SUM(bytes),0) "
                               "FROM hf_egress_log GROUP BY 1,2") or []):
                reg.set("mlscan_hf_files_total", int(r[2] or 0), {"tenant": r[0], "status": r[1]})
                reg.inc("mlscan_hf_bytes_total", {"tenant": r[0], "status": r[1]}, int(r[3] or 0))
            for r in (db_query("SELECT tenant, COALESCE(SUM(bytes),0) FROM hf_egress_log "
                               "WHERE status='ok' AND created::date = current_date GROUP BY 1") or []):
                lim = _hf_daily_limit(r[0])
                reg.set("mlscan_hf_used_today_bytes", int(r[1] or 0), {"tenant": r[0]})
                if lim:
                    reg.set("mlscan_hf_daily_limit_bytes", int(lim), {"tenant": r[0]})
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
            image_digest=_norm_engine(body.get("engine_image") or ""),
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

    def _bundles_list(self, q: dict) -> None:
        if not DB_ENABLED:
            return self._json(503, {"error": "db disabled"})
        model = (q.get("model", [""])[0] or "").lower()
        if not model:
            return self._json(400, {"error": "нужен параметр model=<sha256>"})
        rows = db_query("SELECT bundle_id,engine_image,model_sha256,prompt_set,detectors,policy,"
                        "to_char(created,'YYYY-MM-DD\"T\"HH24:MI:SS') FROM bundles WHERE model_sha256="
                        + _lit(model) + " ORDER BY created DESC") or []
        return self._json(200, {"model_sha256": model, "bundles": [
            {"bundle_id": r[0], "engine_image": r[1], "model_sha256": r[2], "prompt_set": r[3],
             "detectors": r[4], "policy": r[5], "created": r[6]} for r in rows]})

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
        # N2: job теста bundle аутентифицируется одноразовым run-token (только для своего bundle)
        if u.path in ("/llm/score", "/llm/events"):
            tok = (self.headers.get("Authorization") or "").replace("Bearer ", "").strip()
            if tok and self._run_token_ok(tok):
                if u.path == "/llm/score":
                    return self._llm_score(run_token=tok)
                return self._llm_events()      # B1: события in-guest eBPF от job'а теста
        if self._require() is None:
            return
        if self._rate_limited():
            return
        if u.path == "/uploads/initiate":
            return self._uploads_initiate()
        if u.path == "/scans/complete":
            return self._scans_complete()
        if u.path == "/objects/import":
            return self._objects_import()
        if u.path == "/bundles":
            return self._bundles_create()
        if u.path.startswith("/bundles/") and u.path.endswith("/test"):
            return self._bundle_test_start(u.path.split("/", 3)[2])
        if u.path.startswith("/bundles/") and u.path.endswith("/verdict"):
            return self._bundle_verdict_set(u.path.split("/", 3)[2])
        if u.path == "/hf/token":
            return self._hf_token_set()
        if u.path == "/auth/token":
            return self._auth_token_issue()
        if u.path == "/rate-limit":
            return self._rate_limit_set()
        if u.path == "/hf/quota":
            return self._hf_quota_set()
        if u.path.startswith("/bundles/") and u.path.endswith("/rebind"):
            return self._bundle_rebind(u.path.split("/", 3)[2])
        if u.path == "/images/import":
            return self._images_import()
        if u.path == "/domain-class":
            return self._domain_class_set()
        if u.path == "/hf/search":
            return self._hf_search()
        if u.path == "/hf/downloads":
            return self._hf_download_create()
        if u.path.startswith("/hf/downloads/") and u.path.endswith("/cancel"):
            return self._hf_download_cancel(u.path.split("/", 3)[3])
        if u.path == "/detectors":
            return self._detectors_register()
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
    if "@sha256:" not in (SANDBOX_IMAGE or ""):
        print("[testing] ВНИМАНИЕ: SANDBOX_IMAGE не пинится по digest — sandbox-джобы сканов будут "
              "отклонены admission-политикой (Kyverno). Выполните deploy/stage2/apply.sh или "
              "kubectl -n mlscan-testing set env deploy/mlscan-testing SANDBOX_IMAGE=<repo>@sha256:<digest>",
              file=sys.stderr, flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
