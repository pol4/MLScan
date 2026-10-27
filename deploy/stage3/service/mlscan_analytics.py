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
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INTERNAL_KEY = os.environ.get("INTERNAL_KEY", "")
COOKIE_DOMAIN = os.environ.get("MLSCAN_COOKIE_DOMAIN", "")
SESSION_TTL = int(os.environ.get("MLSCAN_SESSION_TTL", str(12 * 3600)))


def _cookie_attr() -> str:
    return f"; Domain={COOKIE_DOMAIN}" if COOKIE_DOMAIN else ""


def _auth_headers() -> dict:
    return {"Authorization": f"Bearer {INTERNAL_KEY}"} if INTERNAL_KEY else {}


TESTING_URL = os.environ.get(
    "TESTING_URL", "http://mlscan-testing.mlscan-testing.svc.cluster.local:8080")
DATA_DIR = os.environ.get("DATA_DIR", "/data")
POLICY_PATH = os.environ.get("POLICY_PATH", "/etc/mlscan/policy.json")
# U3: подпись политики (fail-closed): при заданном POLICY_SIGN_KEY подпись обязательна и проверяется
POLICY_SIGN_KEY = os.environ.get("POLICY_SIGN_KEY", "")
POLICY_SIGNATURE = os.environ.get("POLICY_SIGNATURE", "")
POLICY_OK = True
POLICY_REASON = "ok"
EVIDENCE = os.path.join(DATA_DIR, "evidence.jsonl")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "15"))

SEV_W = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# --- PostgreSQL (dual-write: evidence-цепочка, artifacts/fingerprints/scans/findings) ---
PG_HOST = os.environ.get("PGHOST", "")
DB_ENABLED = bool(PG_HOST)
_Pg = None
if DB_ENABLED:
    sys.path.insert(0, "/opt/pg")
    from pgclient import Pg as _Pg  # noqa: E402


def _db_conn():
    return _Pg(PG_HOST, int(os.environ.get("PGPORT", "5432")),
               os.environ.get("PGUSER", "mlscan"), os.environ.get("PGPASSWORD", ""),
               os.environ.get("PGDATABASE", "mlscan"), timeout=15)


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
        c = _db_conn()
        c.connect()
        c.query(sql)
        c.close()
    except Exception as exc:  # noqa: BLE001
        print(f"[db] {type(exc).__name__}: {exc} | SQL: {sql[:140]}", file=sys.stderr)


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
    """Строка UI по ключу каталога (RU/EN). Без i18n — ключ как есть."""
    return i18n.t(key, lang, **fmt) if i18n else key


def TR(text, lang: str = "ru"):
    """Перевод «свободной» строки (находка, причина, ошибка сервиса)."""
    return i18n.tr(text, lang) if i18n else text

_u = urllib.parse.urlparse(TESTING_URL)
TEST_HOST = _u.hostname
TEST_PORT = _u.port or 80


def _esc(x) -> str:
    s = "" if x is None else str(x)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ----------------------------------------------------------------------------
# HTTP к сервису тестирования
# ----------------------------------------------------------------------------
def http_get_json(url: str, timeout: int = 20):
    req = urllib.request.Request(url, headers=_auth_headers())
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def progress_of(scan_id: str) -> dict | None:
    try:
        return http_get_json(f"{TESTING_URL}/scans/{scan_id}", timeout=10)
    except Exception:  # noqa: BLE001
        return None


def testing_stats() -> dict:
    now = time.time()
    cached = _dash_cache["testing"]
    if cached is not None and (now - _dash_cache["ts"]) < _DASH_TTL:
        return cached
    try:
        st = http_get_json(TESTING_URL + "/stats", timeout=30)
    except Exception:  # noqa: BLE001
        st = {}
    _dash_cache["testing"] = st
    _dash_cache["ts"] = time.time()
    return st


# ----------------------------------------------------------------------------
# Политика
# ----------------------------------------------------------------------------
def _policy_signature(content: dict) -> str:
    import hashlib
    import hmac as _hmac
    canon = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _hmac.new(POLICY_SIGN_KEY.encode(), hashlib.sha256(canon.encode()).hexdigest().encode(),
                     hashlib.sha256).hexdigest()


def load_policy() -> dict:
    global POLICY_OK, POLICY_REASON
    try:
        with open(POLICY_PATH) as fh:
            content = json.load(fh)
    except Exception:  # noqa: BLE001
        POLICY_OK, POLICY_REASON = True, "no-policy-file"
        return {"rules": [], "default": {"action": "quarantine", "verdict": "Needs review"}}
    if POLICY_SIGN_KEY:
        import hmac as _hmac
        want = _policy_signature(content)
        ok = bool(POLICY_SIGNATURE) and _hmac.compare_digest(want, POLICY_SIGNATURE)
        POLICY_OK, POLICY_REASON = ok, ("ok" if ok else "policy signature invalid")
        if not ok:
            return {"rules": [], "default": {"action": "block", "verdict": "Malicious"}}
    else:
        POLICY_OK, POLICY_REASON = True, "unsigned"
    return content


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
    if not POLICY_OK:      # fail-closed: политика не подтверждена — блокируем
        return {"rule_id": "policy-invalid", "action": "block", "verdict": "Malicious",
                "reason": f"policy signature invalid (fail-closed): {POLICY_REASON}"}
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
_last_sig = ""     # HMAC предыдущего звена цепочки evidence (docs/14, P1-5)
EVIDENCE_KEY = (os.environ.get("MLSCAN_EVIDENCE_KEY") or "").encode()
IS_WRITER = True   # single-writer: evidence пишет одна инстанция (PG advisory lock)

# Кэш данных дашборда: /api/overview и /api/stats обращаются к сервису тестирования
# (чтение тысяч файлов сканов), поэтому результаты кэшируются на 5 с; инвалидация —
# при записи нового скана в evidence и по TTL.
_dash_cache: dict = {"ts": 0.0, "overview": None, "testing": None}
_DASH_TTL = 5.0


def _load_store() -> None:
    global _last_hash, _last_sig
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
            _last_sig = e.get("sig", _last_sig)
            if not DB_ENABLED:
                _last_hash = e.get("hash", _last_hash)
            rec = e.get("record", {})
            if rec.get("scan_id"):
                _index[rec["scan_id"]] = rec
    if DB_ENABLED and _Pg is not None:
        try:
            c = _db_conn()
            c.connect()
            _cols, rows = c.query("SELECT hash FROM evidence ORDER BY id DESC LIMIT 1")
            c.close()
            _last_hash = rows[0][0] if rows else "GENESIS"
        except Exception as exc:  # noqa: BLE001
            print(f"[db] chain seed: {exc}", file=sys.stderr)


def _sig(prev_sig: str, h: str) -> str:
    """HMAC-подпись звена цепочки evidence (ключ вне БД/PVC) — детектор подмены (docs/14, P1-5)."""
    if not EVIDENCE_KEY:
        return ""
    import hmac as _hmac
    return _hmac.new(EVIDENCE_KEY, (prev_sig + h).encode(), "sha256").hexdigest()


def _startup_writer_lock() -> None:
    """single-writer: evidence пишет только одна инстанция аналитики (PG advisory lock)."""
    global IS_WRITER
    if not DB_ENABLED or _Pg is None:
        return
    try:
        c = _db_conn()
        c.connect()
        c.query("ALTER TABLE evidence ADD COLUMN IF NOT EXISTS sig TEXT")
        _cols, rows = c.query("SELECT pg_try_advisory_lock(777001)")
        IS_WRITER = bool(rows and rows[0][0])
        c.close()
    except Exception as exc:  # noqa: BLE001
        print(f"[db] writer lock: {exc}", file=sys.stderr)
    if not IS_WRITER:
        print("[analytics] CRITICAL: другая инстанция пишет evidence — режим read-only", file=sys.stderr)


def _append(record: dict) -> dict:
    global _last_hash, _last_sig
    with _lock:
        prev = _last_hash
        payload = json.dumps(record, ensure_ascii=False, sort_keys=True)
        h = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
        sig = _sig(_last_sig, h)
        with open(EVIDENCE, "a") as fh:
            fh.write(json.dumps({"prev": prev, "hash": h, "sig": sig, "record": record},
                                ensure_ascii=False) + "\n")
        _last_hash = h
        _last_sig = sig
        _index[record["scan_id"]] = record
        _dash_cache["overview"] = None
        _db_append(record, prev, h, payload, sig)
        return {"prev": prev, "hash": h}


def _db_append(record: dict, prev: str, h: str, payload: str, sig: str = "") -> None:
    """Зеркалирование записи в PostgreSQL (артефакт, отпечатки, скан, находки, evidence)."""
    if not DB_ENABLED or _Pg is None:
        return
    sid = record.get("scan_id")
    sha = record.get("sha256")
    try:
        c = _db_conn()
        c.connect()
        if sha:
            c.query("INSERT INTO artifacts(sha256,size,format,filename,s3_key) VALUES "
                    f"({_lit(sha)},{int(record.get('size') or 0)},{_lit(record.get('format'))},"
                    f"{_lit(record.get('name'))},{_lit(record.get('s3_key'))}) ON CONFLICT (sha256) DO NOTHING")
            c.query("INSERT INTO artifact_fingerprints(artifact_id,kind,value) "
                    f"SELECT id,'sha256',{_lit(sha)} FROM artifacts WHERE sha256={_lit(sha)} "
                    "ON CONFLICT DO NOTHING")
        c.query("INSERT INTO scans(scan_id,status,stage,progress,verdict,reason,timings,finished_at) VALUES "
                f"({_lit(sid)},'done','done',100,{_lit(record.get('verdict'))},"
                f"{_lit(record.get('service_reason'))},{_lit(json.dumps(record.get('timings') or {}, ensure_ascii=False))},now()) "
                "ON CONFLICT (scan_id) DO UPDATE SET verdict=EXCLUDED.verdict, reason=EXCLUDED.reason, "
                "timings=EXCLUDED.timings, finished_at=now()")
        for f in record.get("findings", []) or []:
            ev = f.get("evidence")
            ev_sql = "NULL" if ev is None else _lit(json.dumps(ev, ensure_ascii=False))
            c.query("INSERT INTO findings(scan_id,level,check_id,category,severity,confidence,title,evidence) VALUES "
                    f"({_lit(sid)},{_lit(f.get('level'))},{_lit(f.get('check_id'))},{_lit(f.get('category'))},"
                    f"{_lit(f.get('severity'))},{f.get('confidence') if f.get('confidence') is not None else 'NULL'},"
                    f"{_lit(f.get('title'))},{ev_sql})")
        c.query("INSERT INTO evidence(scan_id,prev_hash,hash,sig,payload) VALUES "
                f"({_lit(sid)},{_lit(prev)},{_lit(h)},{_lit(sig)},{_lit(payload)})")
        c.close()
    except Exception as exc:  # noqa: BLE001
        print(f"[db] {type(exc).__name__}: {exc}", file=sys.stderr)


def verify_chain() -> dict:
    """Целостность evidence: связность hash-цепочки + HMAC-подписи + сверка вершин файл/БД.

    Цепочка в БД проверяется по фактической связности (baseline задаёт первая строка),
    поэтому «мостовая» строка при первом включении БД не считается разрывом.
    """
    signed = bool(EVIDENCE_KEY)
    if DB_ENABLED and _Pg is not None:
        try:
            c = _db_conn()
            c.connect()
            _cols, rows = c.query("SELECT prev_hash,hash,payload,sig FROM evidence ORDER BY id")
            c.close()
            # Цепочка БД может состоять из нескольких генераций: после сброса БД (или её
            # восстановления) запись начинается заново с prev=GENESIS. Внутри каждой
            # генерации связность и HMAC-подписи обязаны сходиться, а подписи — сквозные.
            prev, prev_sig, n, generations = None, "", 0, 1
            for p_, h, payload, sig in rows:
                if p_ == "GENESIS" and prev is not None:
                    generations += 1
                    prev = None
                base = prev if prev is not None else "GENESIS"
                calc = hashlib.sha256((base + payload).encode("utf-8")).hexdigest()
                if (prev is not None and p_ != prev) or h != calc:
                    return {"ok": False, "entries": n, "broken_at": n + 1, "source": "db",
                            "signed": signed, "generations": generations}
                if signed and sig:
                    expect = _sig(prev_sig, h)
                    if expect and sig != expect:
                        return {"ok": False, "entries": n, "broken_at": n + 1, "source": "db",
                                "signed": signed, "error": "HMAC mismatch", "generations": generations}
                prev, prev_sig, n = h, (sig or ""), n + 1
            file_tip = None
            if os.path.isfile(EVIDENCE):
                with open(EVIDENCE) as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            file_tip = json.loads(line).get("hash")
            if file_tip and prev and file_tip != prev:
                return {"ok": False, "entries": n, "source": "db", "signed": signed,
                        "error": "file tip != db tip", "db_tip": prev, "file_tip": file_tip}
            return {"ok": True, "entries": n, "last_hash": prev, "source": "db", "signed": signed,
                    "generations": generations}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}
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
_MODULE_LABELS = {"static": "статика", "dynamic": "динамика", "behavior": "поведение"}


def _coverage_verdict(verdict: str, coverage: dict, reason: str, lang: str = "ru") -> tuple[str, str]:
    """Учитывает полноту покрытия в вердикте аналитики.

    Если модуль проверки не смог отработать (модель не загрузилась, нет зависимости,
    не хватило ресурсов, таймаут), вывод «Safe»/«Needs review» некорректен: возвращаем
    Inconclusive и поясняем, что проверено не всё. Если частичные данные УЖЕ доказывают
    опасность — вердикт сохраняем, добавив пометку о неполноте.
    """
    if not coverage or coverage.get("complete") is not False:
        return verdict, reason
    failed = coverage.get("failed") or []
    parts = []
    for key in failed:
        mod = (coverage.get("modules") or {}).get(key) or {}
        label = _MODULE_LABELS.get(key, key)
        parts.append(f"{label}: {mod['reason']}" if mod.get("reason") else label)
    detail = "; ".join(parts)
    if verdict in ("Malicious", "Dangerous"):
        return verdict, f"{reason}; проверка неполная ({detail})"
    return "Inconclusive", (f"проверить всеми модулями не получилось ({detail}); "
                            f"частичный результат: {reason}")


def analyze(scan: dict) -> dict:
    findings = scan.get("findings", []) or []
    sc = scoring(findings)
    decision = apply_policy(load_policy(), findings, sc["max_severity"])
    coverage = scan.get("coverage") or {}
    verdict = decision.get("verdict") or scan.get("verdict")
    reason = decision.get("reason") or scan.get("reason") or ""
    verdict, reason = _coverage_verdict(verdict, coverage, reason)
    return {
        "scan_id": scan.get("scan_id"), "name": scan.get("name"), "format": scan.get("format"),
        "sha256": scan.get("sha256"), "size": scan.get("size"), "s3_key": scan.get("s3_key"),
        "timings": scan.get("timings"),
        "created": scan.get("created"), "service_verdict": scan.get("verdict"),
        "service_reason": reason, "service_reason_raw": scan.get("reason"),
        "score": sc, "policy": decision, "coverage": coverage,
        "verdict": verdict,
        "findings": findings, "state": scan.get("state"),
        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def sync_once(backfill: int = 0) -> dict:
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
    # пересчёт записей, проанализированных до внедрения учёта покрытия: их вердикт
    # мог быть «Safe» при неполной проверке. В append-only store добавляем исправленную
    # запись (история не перезаписывается).
    fixed = 0
    if backfill:
        for sid, rec in list(_index.items()):
            if fixed >= backfill:
                break
            if rec.get("coverage") is not None:
                continue
            scan = progress_of(sid)
            if not scan or scan.get("state") != "done":
                continue
            try:
                _append(analyze(scan))
                fixed += 1
            except Exception:  # noqa: BLE001
                continue
    return {"ok": True, "new": new, "reanalyzed": fixed, "total": len(_index)}


def poller() -> None:
    while True:
        try:
            sync_once()
        except Exception:  # noqa: BLE001
            pass
        time.sleep(POLL_INTERVAL)


def overview() -> list[dict]:
    now = time.time()
    cached = _dash_cache["overview"]
    if cached is not None and (now - _dash_cache["ts"]) < _DASH_TTL:
        return cached
    try:
        scans = http_get_json(TESTING_URL + "/scans", timeout=60).get("scans", [])
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
    _dash_cache["overview"] = out
    _dash_cache["ts"] = time.time()
    return out


def stats() -> dict:
    ov = overview()                      # один вызов вместо трёх
    verdicts: dict[str, int] = {}
    total = 0
    for s in ov:
        if s.get("verdict"):
            verdicts[s["verdict"]] = verdicts.get(s["verdict"], 0) + 1
        total += int(s.get("size") or 0)
    return {"scans": len(ov), "by_verdict": verdicts,
            "total_bytes": total, "testing": testing_stats()}


# ----------------------------------------------------------------------------
# Отчёты
# ----------------------------------------------------------------------------
def report_md(rec: dict, lang: str = "ru") -> str:
    L = [f"# {T('report.title', lang, name=rec.get('name'))}", ""]
    L.append(f"- **{T('report.scan_id', lang)}:** `{rec.get('scan_id')}`")
    L.append(f"- **SHA-256:** `{rec.get('sha256')}`")
    L.append(f"- **{T('report.size', lang)}:** {rec.get('size')} {T('art.bytes', lang)}")
    L.append(f"- **{T('report.format', lang)}:** `{rec.get('format')}`")
    L.append(f"- **{T('report.verdict', lang)}:** **{rec.get('verdict')}** "
             f"(policy: {rec['policy'].get('rule_id')} → {rec['policy'].get('action')})")
    L.append(f"- **{T('report.risk', lang)}:** {rec['score'].get('risk_score')} "
             f"(max severity: {rec['score'].get('max_severity')})")
    if rec.get("timings"):
        L.append(f"- **{T('report.timings', lang)}:** {rec['timings']}")
    if rec.get("service_reason"):
        L.append(f"- **{T('art.reason', lang)}:** {TR(rec.get('service_reason'), lang)}")
    cov = rec.get("coverage") or {}
    if cov and cov.get("complete") is False:
        L.append(f"- **{T('art.coverage_incomplete', lang)}:** " + "; ".join(
            f"{TR(_MODULE_LABELS.get(k, k), lang)}: "
            f"{TR((cov.get('modules') or {}).get(k, {}).get('reason'), lang)}"
            for k in (cov.get("failed") or [])))
    L.append("")
    L.append(f"## {T('report.findings', lang)}")
    L.append("")
    L.append(f"| {T('report.col.level', lang)} | {T('report.col.id', lang)} | "
             f"{T('report.col.severity', lang)} | {T('report.col.conf', lang)} | "
             f"{T('report.col.finding', lang)} |")
    L.append("|---------|----|----------|-------------|---------|")
    for f in sorted(rec.get("findings", []), key=lambda x: -SEV_RANK.get(x["severity"], 0)):
        L.append(f"| {f['level']} | {f['check_id']} | {f['severity']} | {f.get('confidence', 0):.2f} | "
                 f"{TR(f['title'], lang)} |")
    if not rec.get("findings"):
        L.append(T("report.no_findings", lang))
    return "\n".join(L)


def report_sarif(rec: dict, lang: str = "ru") -> dict:
    rules, results = {}, []
    for f in rec.get("findings", []):
        title = TR(f["title"], lang)
        rules.setdefault(f["check_id"], {"id": f["check_id"], "name": title,
                                         "shortDescription": {"text": title},
                                         "properties": {"severity": f["severity"], "category": f["category"]}})
        results.append({"ruleId": f["check_id"],
                        "level": {"critical": "error", "high": "error", "medium": "warning",
                                  "low": "note", "info": "note"}.get(f["severity"], "warning"),
                        "message": {"text": title + (f" — {TR(f.get('evidence'), lang)}" if f.get("evidence") else "")},
                        "properties": {"confidence": f.get("confidence"), "level": f["level"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "MLScan", "informationUri": "https://github.com/pol4/MLScan",
                                          "rules": list(rules.values())}},
                      "results": results,
                      "properties": {"verdict": rec.get("verdict"), "risk_score": rec["score"].get("risk_score"),
                                     "language": lang}}]}


def localized_record(rec: dict, lang: str = "ru") -> dict:
    """Копия записи с локализованными находками/причиной (для JSON-отчёта/API)."""
    out = dict(rec)
    out["findings"] = i18n.localize_findings(rec.get("findings", []), lang) if i18n else rec.get("findings", [])
    if rec.get("service_reason"):
        out["service_reason"] = TR(rec["service_reason"], lang)
    out["language"] = lang
    return out


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
.warn{background:#3a2a12;border:1px solid #8a6d1f;border-radius:10px;padding:12px 16px;margin:14px 0;font-size:14px}
table{border-collapse:collapse;width:100%} th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #232a36;font-size:14px}
th{color:#9aa4b2;font-weight:600} code{background:#1d2330;padding:1px 5px;border-radius:4px}
.v-Malicious{color:#ff6b6b}.v-Dangerous{color:#ffb057}.v-Needs{color:#ffd166}.v-Safe{color:#5dd39e}.v-Inconclusive{color:#9aa4b2}
.pbar{background:#232a36;border-radius:5px;height:14px;position:relative;overflow:hidden;min-width:120px}
.pbar>span{display:block;height:100%;background:#3d7dd8}
.tabs{display:flex;gap:6px;margin-bottom:8px}
.tab{background:#1b2130;color:#cfe3ff;border:1px solid #2b3a55;border-radius:8px;padding:6px 10px;cursor:pointer}
.tab.active{background:#2b3a55}
.tabpane{display:none}
.badge{background:#2b3a55;color:#cfe3ff;border-radius:6px;padding:1px 6px;font-size:11px}
form.upload{background:#161a23;border:1px solid #232a36;border-radius:10px;padding:16px;margin-bottom:20px}
input[type=file]{color:#e6e6e6} button{background:#3d7dd8;color:#fff;border:0;border-radius:6px;padding:8px 14px;cursor:pointer}
.uprog{background:#232a36;border-radius:5px;height:12px;margin-top:10px;display:none}
.uprog>span{display:block;height:100%;background:#5dd39e;width:0}
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.controls input[type=search],.controls select{background:#161a23;color:#e6e6e6;border:1px solid #232a36;border-radius:6px;padding:7px 10px;font-size:14px}
.controls input[type=search]{min-width:220px}
</style>"""


def _with_lang(path: str, code: str) -> str:
    """Текущий путь с ЗАМЕНОЙ параметра lang (чтобы не дублировать ?lang=en&lang=ru)."""
    parts = urllib.parse.urlsplit(path or "/")
    q = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
         if k != "lang"]
    q.append(("lang", code))
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/",
                                    urllib.parse.urlencode(q), parts.fragment))


def _lang_switch(lang: str, next_path: str = "/") -> str:
    """Переключатель языка: RU | EN (cookie mlscan_lang + параметр ?lang как фолбэк)."""
    parts = []
    for code in ("ru", "en"):
        label = "RU" if code == "ru" else "EN"
        if code == lang:
            parts.append(f"<b>{label}</b>")
        else:
            nxt = urllib.parse.quote(_with_lang(next_path, code))
            parts.append(f"<a href='/lang?set={code}&next={nxt}'>{label}</a>")
    return (f"<span style='margin-left:auto;color:#9aa4b2;font-size:12px'>"
            f"{T('nav.language', lang)}: " + " | ".join(parts) + "</span>")


def _page(title: str, body: str, script: str = "", lang: str = "ru",
          subject: str = "anonymous", roles: list | None = None, path: str = "/") -> bytes:
    roles = roles or []
    extra = ("<a href='/settings'>" + T("settings.title", lang) + "</a>") if "admin" in roles else ""
    return (f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>"
            f"<title>{title} — MLScan</title>{_STYLE}</head><body>"
            f"<header><h1><a href='/'>MLScan — Analytics</a></h1>"
            f"<a href='/login'>{T('nav.login', lang)}</a> <a href='/logout'>{T('nav.logout', lang)}</a>"
            f"<a href='/api/overview'>{T('nav.json', lang)}</a>"
            f"<a href='/api/evidence/verify'>{T('nav.evidence', lang)}</a>"
            f"<a href='/policy'>{T('nav.policy', lang)}</a>{extra}"
            f"{_lang_switch(lang, path)}</header><main>{body}</main>{script}</body></html>").encode()


def _js(lang: str) -> str:
    """Клиентский скрипт дашборда: таблица рисуется сразу после /api/overview,
    статистика — отдельным (параллельным) запросом /api/stats."""
    labels = {
        "total": T("dash.total", lang),
        "volume": T("dash.volume", lang),
        "shown": T("dash.shown", lang, n="{n}", m="{m}"),
        "empty": T("dash.empty", lang),
        "upload_error": T("dash.upload_error", lang),
        "verdicts": ["Malicious", "Dangerous", "Needs review", "Safe", "Inconclusive"],
    }
    return """<script>
const L = __LABELS__;
let OV=[];
function fmtBytes(b){b=+b||0;const u=['B','KiB','MiB','GiB'];let i=0;while(b>=1024&&i<u.length-1){b/=1024;i++;}return b.toFixed(b<10&&i>0?1:0)+' '+u[i];}
function esc(s){return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function shortDate(s){if(!s)return '—';s=String(s).replace('T',' ');return s.slice(0,16);}
function renderCards(st){
  document.getElementById('cards').innerHTML =
    L.verdicts.map(v=>
      `<div class="card"><div class="n v-${v.replace(' ','')}">${(st.by_verdict||{})[v]||0}</div><div class="l">${v}</div></div>`).join('')
    + `<div class="card"><div class="n">${st.scans||0}</div><div class="l">${esc(L.total)}</div></div>`
    + `<div class="card"><div class="n">${fmtBytes(st.total_bytes)}</div><div class="l">${esc(L.volume)}</div></div>`;
}
function currentRows(){
  const q=(document.getElementById('q').value||'').trim().toLowerCase();
  const vf=document.getElementById('vf').value;
  const sort=document.getElementById('sort').value;
  let rows=OV.filter(r=>{
    if(q && !String(r.name||'').toLowerCase().includes(q)) return false;
    if(vf){const v=r.verdict||'';if(vf==='__none__'){if(v!=='')return false;}else if(v!==vf)return false;}
    return true;
  });
  const dir=sort.endsWith('_asc')?1:-1;
  if(sort.startsWith('size')) rows.sort((a,b)=>((+a.size||0)-(+b.size||0))*dir);
  else rows.sort((a,b)=>String(a.created||a.updated||'').localeCompare(String(b.created||b.updated||''))*dir);
  return rows;
}
function renderRows(){
  const shown=currentRows();
  document.getElementById('rows').innerHTML = shown.length
    ? shown.map(r=>{
        const v=r.verdict||'';
        const badge=(r.kind==='engine_image')?'<span class="badge">Engine image</span> ':'';
        return `<tr><td>${badge}<a href="/artifact/${r.scan_id}">${esc(r.name)}</a></td>`
          +`<td>${shortDate(r.created||r.updated)}</td>`
          +`<td>${fmtBytes(r.size)}</td><td><code>${(r.sha256||'').slice(0,12)}…</code></td>`
          +`<td>${esc(r.state)}${r.stage&&r.stage!=='done'?' / '+esc(r.stage):''}<div class="pbar"><span style="width:${r.progress||0}%"></span></div></td>`
          +`<td class="v-${String(v).replace(' ','')}">${esc(v||'—')}</td>`
          +`<td>${r.risk_score!=null?r.risk_score:'—'}</td><td>${esc(r.policy_action||'—')}</td></tr>`;}).join('')
    : `<tr><td colspan="8" style="color:#9aa4b2">${esc(L.empty)}</td></tr>`;
  document.getElementById('count').textContent=L.shown.replace('{n}',shown.length).replace('{m}',OV.length);
}
async function refresh(){
  // 1) список сканов -> сразу отрисовываем таблицу
  try{
    const r=await fetch('/api/overview',{cache:'no-store'});
    if(r.status===401){ location.href='/login?expired=1'; return; }
    if(r.ok){ OV=(await r.json()).scans||[]; renderRows(); }
  }catch(e){}
  // 2) агрегаты -> отдельно обновляем карточки
  try{
    const r2=await fetch('/api/stats',{cache:'no-store'});
    if(r2.status===401){ location.href='/login?expired=1'; return; }
    if(r2.ok) renderCards(await r2.json());
  }catch(e){}
}
(function(){const k=document.getElementById('kind'),n=document.getElementById('kindnotice');
  if(k){const upd=()=>{n.style.display=(k.value==='engine_image')?'block':'none';};
    k.addEventListener('change',upd);upd();}})();
['q','vf','sort'].forEach(id=>{const e=document.getElementById(id);
  e.addEventListener('input',renderRows);e.addEventListener('change',renderRows);});
document.getElementById('f').addEventListener('submit',e=>{
  e.preventDefault();const file=document.querySelector('input[type=file]').files[0];if(!file)return;
  const ext=(file.name.split('.').pop()||'').toLowerCase();
  const fmt={pt:'torch',pth:'torch',bin:'torch',ckpt:'torch',npy:'numpy',npz:'numpy',
             joblib:'joblib',dill:'dill',cloudpickle:'cloudpickle',
             zip:'zip',tar:'tar',gz:'tar',tgz:'tar'}[ext]||'pickle';
  const kindEl=document.getElementById('kind');
  const kind=kindEl?kindEl.value:'model';
  const xhr=new XMLHttpRequest();
  xhr.open('POST','/upload?name='+encodeURIComponent(file.name)+'&fmt='+fmt+'&kind='+encodeURIComponent(kind));
  const box=document.getElementById('uprog'),bar=document.getElementById('ubar');
  box.style.display='block';
  xhr.upload.onprogress=ev=>{bar.style.width=Math.round(ev.loaded/ev.total*100)+'%';};
  xhr.onload=()=>{setTimeout(()=>{box.style.display='none';bar.style.width='0';},400);refresh();};
  xhr.onerror=()=>{alert(L.upload_error);};
  xhr.send(file);
});
(function(){const dl=document.getElementById('downloads');if(!dl)return;
  const tabs=dl.querySelectorAll('.tab');
  const show=id=>{dl.querySelectorAll('.tabpane').forEach(p=>p.style.display=(p.id===id?'block':'none'));
    tabs.forEach(b=>b.classList.toggle('active',b.dataset.tab===id));};
  tabs.forEach(b=>b.addEventListener('click',()=>show(b.dataset.tab))); show('tab-models');
  const loadEngines=()=>fetch('/images/list').then(r=>r.ok?r.json():null).then(d=>{
    // B4-lite: помечаем состояние подписи/SBOM образа движка прямо в списке
    const opts=((d&&d.images)||[]).map(i=>`<option value="${i.digest}">${(i.ref||i.digest).slice(0,44)} ${i.signed?'[signed]':'[unsigned]'}${i.sbom?' [sbom]':''}</option>`).join('');
    ['englist','hfengine','locengine','rbengine'].forEach(id=>{const el=document.getElementById(id);
      if(el) el.innerHTML='<option value="">engine: (выберите скачанный)</option>'+opts;});}).catch(()=>{});
  loadEngines(); const er=document.getElementById('engrefresh'); er&&er.addEventListener('click',loadEngines);
  const rf=document.getElementById('hfresults');
  rf&&rf.addEventListener('click',ev=>{const b=ev.target.closest('button[data-repo]');if(!b)return;
    if(!(document.getElementById('hfengine')||{}).value){ev.preventDefault();ev.stopImmediatePropagation();
      document.getElementById('hfstatus').textContent='ERR: выберите движок из уже скачанных';}},true);
  const ts=document.getElementById('hftokensave');
  ts&&ts.addEventListener('click',()=>{const t=document.getElementById('hftoken').value.trim();
    fetch('/hf/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t})})
      .then(r=>r.json().then(j=>({ok:r.ok,j}))).then(({ok,j})=>{
        document.getElementById('hftokenstatus').textContent =
          ok ? (j.cleared ? 'token cleared' : ('saved '+j.masked)) : ('ERR '+(j.error||''));});});
  fetch('/hf/token').then(r=>r.ok?r.json():null).then(d=>{
    const st=document.getElementById('hftokenstatus'); if(!d||!st)return;
    if(!d.present){st.textContent='token: не сохранён';return;}
    st.textContent='token: '+(d.usable?d.masked:'не применим — сохраните заново');}).catch(()=>{});
  const bt=document.getElementById('btbtn');
  bt&&bt.addEventListener('click',()=>{
    const st=document.getElementById('btstatus');
    const sha=(document.getElementById('btsha').value||'').trim();
    const bid=(document.getElementById('btbundle').value||'').trim();
    const run=(id)=>{st.textContent='запуск теста…';
      fetch('/bundles/'+id+'/test',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
      .then(r=>r.json().then(j=>({ok:r.ok,j}))).then(({ok,j})=>{
        if(!ok){st.textContent='ERR '+(j.error||'');return;}
        st.textContent='тест запущен: job '+j.job+', вопросов '+j.questions+(j.gpu?', GPU':', CPU');
        const t=setInterval(()=>{fetch('/bundles/'+id+'/test').then(r=>r.ok?r.json():null).then(d=>{
          if(!d)return;
          if(d.status==='done'){clearInterval(t);
            st.textContent='тест завершён: вердикт '+(d.verdict||'—')+', решение '+(d.action||'—')
              +', аттестация '+String(d.attestation_digest||'').slice(0,20)+'…';}
          else if(d.status==='failed'){clearInterval(t);st.textContent='тест не удался: '+(d.error||d.status);}
        }).catch(()=>{});},5000);
      }).catch(e=>{st.textContent='ERR '+e;});};
    if(bid){run(bid);return;}
    if(!sha){st.textContent='ERR укажите bundle_id или sha256 модели';return;}
    st.textContent='поиск bundle для модели…';
    fetch('/bundles?model='+encodeURIComponent(sha)).then(r=>r.ok?r.json():null).then(d=>{
      const b=(d&&d.bundles)||[];
      if(!b.length){st.textContent='ERR нет bundle для этой модели';return;}
      run(b[0].bundle_id);
    }).catch(()=>{st.textContent='ERR не удалось получить список bundle';});
  });
  const lb=document.getElementById('locbtn');
  lb&&lb.addEventListener('click',()=>{const f=document.getElementById('locfile').files[0];const eng=document.getElementById('locengine').value;
    const st=document.getElementById('locstatus');
    if(!f){st.textContent='ERR: выберите файл';return;} if(!eng){st.textContent='ERR: выберите движок из скачанных';return;}
    const xhr=new XMLHttpRequest(); xhr.open('POST','/upload?name='+encodeURIComponent(f.name)+'&fmt=pickle&kind=model');
    xhr.onload=()=>{try{const r=JSON.parse(xhr.responseText); const sha=r.sha256;
      fetch('/bundles',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({model_sha256:sha,engine_image:eng,engine_manifest:{entrypoint:'engine'},prompt_set:'ps-v9'})})
        .then(x=>x.json().then(j=>({ok:x.ok,j}))).then(({ok,j})=>{st.textContent=ok?('bundle '+j.bundle_id+' (тест запущен)'):('ERR '+(j.error||''));});
    }catch(e){st.textContent='ERR';}};
    xhr.onerror=()=>{st.textContent='ERR upload';}; xhr.send(f);});
  const rb=document.getElementById('rbbtn');
  rb&&rb.addEventListener('click',()=>{const sha=(document.getElementById('rbsha').value||'').trim().toLowerCase();
    const eng=document.getElementById('rbengine').value; const st=document.getElementById('rbstatus');
    if(!sha||!eng){st.textContent='ERR: нужны model sha256 и движок';return;}
    fetch('/bundles?model='+encodeURIComponent(sha)).then(r=>r.ok?r.json():null).then(d=>{
      const bs=(d&&d.bundles)||[]; if(!bs.length){st.textContent='ERR: bundle для модели не найден';return;}
      fetch('/bundles/'+bs[0].bundle_id+'/rebind',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({engine_image:eng})}).then(x=>x.json().then(j=>({ok:x.ok,j})))
        .then(({ok,j})=>{st.textContent=ok?('новый bundle '+j.bundle_id+' (тест перезапущен)'):('ERR '+(j.error||''));});});
  });
})();
(function(){const sb=document.getElementById('hfsearch-btn');if(!sb)return;
  const res=document.getElementById('hfresults'), st=document.getElementById('hfstatus');
  const poll=id=>fetch('/hf/downloads/'+id).then(r=>r.ok?r.json():null).then(d=>{if(!d)return;
    st.textContent='download '+id.slice(0,8)+': '+d.status+' '+d.bytes_done+'/'+d.bytes_total;
    if(d.status==='queued'||d.status==='running'||d.status==='cancelling')setTimeout(()=>poll(id),700);}).catch(()=>{});
  sb.addEventListener('click',()=>{const q=document.getElementById('hfquery').value.trim();
    const t=document.getElementById('hftype').value.trim(); const qz=document.getElementById('hfquant').value;
    res.textContent='…';
    fetch('/hf/search',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({query:q,type:t,quantization:qz})})
      .then(r=>r.json().then(j=>({ok:r.ok,j})))
      .then(({ok,j})=>{ if(!ok){res.textContent='ERR '+(j.error||'');return;}
        res.innerHTML=(j.items||[]).map(it=>`<div>${it.id} <button data-repo="${it.id}">download</button></div>`).join('')||'нет результатов';
        res.querySelectorAll('button[data-repo]').forEach(b=>b.addEventListener('click',()=>{
          document.getElementById('hfquant').value=qz||'';
          fetch('/hf/downloads',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({repo_id:b.dataset.repo,quantization:qz,engine_image:(document.getElementById('hfengine')||{}).value||''})})
            .then(r=>r.json()).then(d=>{ if(d.id){st.textContent='queued '+d.id.slice(0,8);poll(d.id);} else st.textContent='ERR '+(d.error||''); });}));})
      .catch(()=>{res.textContent='ERR';});});})();
(function(){const b=document.getElementById('dcsave');if(!b)return;
  const st=document.getElementById('dcstatus');
  const show=t=>{st.textContent=t;};
  const counts=d=>'auto='+Object.keys((d&&d.auto)||{}).length+' overrides='+Object.keys((d&&d.overrides)||{}).length;
  const load=()=>fetch('/domain-class').then(r=>r.ok?r.json():null).then(d=>{if(d)show(counts(d));return d;}).catch(()=>null);
  load();
  b.addEventListener('click',()=>{const domain=document.getElementById('dcdomain').value.trim();
    const cls=document.getElementById('dcclass').value.trim();
    fetch('/domain-class',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({domain:domain,policy_class:cls})})
      .then(r=>r.json().then(j=>({ok:r.ok,j}))).then(({ok,j})=>load().then(()=>show(ok?('saved '+j.domain+'→'+j.policy_class):('ERR '+(j.error||'bad')))) )
      .catch(()=>show('ERR'));});})();
(function(){const sb=document.getElementById('imgsign-btn');
  sb&&sb.addEventListener('click',()=>{
    const st=document.getElementById('imgstatus');
    const ref=(document.getElementById('imgref').value||'').trim();
    const dig=ref.includes('@sha256:')?('sha256:'+ref.split('@sha256:')[1]):ref;
    if(!dig){st.textContent='ERR: укажите образ (ref@sha256:…)';return;}
    fetch('/images/'+encodeURIComponent(dig)+'/sign',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
      .then(r=>r.json().then(j=>({ok:r.ok,j}))).then(({ok,j})=>{
        st.textContent=ok?('подписан '+String(j.signature||'').slice(0,26)+'…'):('ERR '+(j.error||''));});});})();
(function(){const b=document.getElementById('imgimport-btn');if(!b)return;
  const st=document.getElementById('imgstatus');
  b.addEventListener('click',()=>{const ref=document.getElementById('imgref').value.trim();
    const key=document.getElementById('imgtarkey').value.trim();
    fetch('/images/import',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ref:ref,oci_tar_key:key})})
      .then(r=>r.json().then(j=>({ok:r.ok,j})))
      .then(({ok,j})=>{st.textContent=ok?('registered '+j.digest+(j.stored_key?' stored/'+j.stored_key:'')):('ERR '+(j.error||'bad'));})
      .catch(()=>{st.textContent='ERR';});});})();
(function(){const el=document.getElementById('psfile');if(!el)return;
  const st=document.getElementById('psstatus');
  const show=t=>{st.textContent=t;};
  fetch('/prompt-sets').then(r=>r.ok?r.json():null).then(d=>{if(d&&d.version)show('active: '+d.version+' ('+d.cases+')');}).catch(()=>{});
  el.addEventListener('change',()=>{const f=el.files[0];if(!f)return;
    const rd=new FileReader();
    rd.onload=()=>{const b64=String(rd.result).split(',')[1];
      fetch('/prompt-sets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:f.name,content_b64:b64})})
        .then(r=>r.json().then(j=>({ok:r.ok,j}))).then(({ok,j})=>{show(ok?('OK '+j.version+' cases='+j.cases):('ERR '+(j.error||'bad')));})
        .catch(()=>show('ERR'));};
    rd.readAsDataURL(f);});})();
async function loop(){ await refresh(); setTimeout(loop,5000); }
loop();
</script>""".replace("__LABELS__", json.dumps(labels, ensure_ascii=False))


def _login_page(error: str = "", lang: str = "ru", notice: str = "") -> bytes:
    body = (f"<h2>{T('login.heading', lang)}</h2>"
            + (f"<p style='color:#ffcf6b'>{_esc(notice)}</p>" if notice else "")
            + (f"<p style='color:#ff6b6b'>{_esc(error)}</p>" if error else "")
            + "<form method='post' action='/login' style='display:flex;flex-direction:column;gap:8px;max-width:320px'>"
            f"<input name='username' placeholder='{T('login.username', lang)}' autocomplete='username' "
            "style='padding:8px'>"
            f"<input name='password' type='password' placeholder='{T('login.password', lang)}' "
            "autocomplete='current-password' style='padding:8px'>"
            f"<button type='submit'>{T('login.submit', lang)}</button></form>"
            f"<p style='color:#9aa4b2;margin-top:14px'>{T('login.key_hint', lang)}</p>"
            "<form method='post' action='/login' style='display:flex;gap:8px;max-width:320px'>"
            f"<input name='key' type='password' placeholder='{T('login.key', lang)}' style='padding:8px;flex:1'>"
            f"<button type='submit'>{T('login.key_submit', lang)}</button></form>")
    return _page(T("login.title", lang), body, lang=lang)


def ui_index(lang: str = "ru", roles: list | None = None, path: str = "/") -> bytes:
    body = ("<div class='cards' id='cards'></div>"
            + "<div class='dl' id='downloads'><div class='tabs'>"
            + f"<button type='button' class='tab' data-tab='tab-models'>{'Модели (кроме LLM)' if lang=='ru' else 'Models (non-LLM)'}</button>"
            + f"<button type='button' class='tab' data-tab='tab-local'>{'Локальные LLM' if lang=='ru' else 'Local LLMs'}</button>"
            + ("<button type='button' class='tab' data-tab='tab-bundletest'>"
               + ("Тест bundle" if lang == "ru" else "Bundle test") + "</button>"
               if "admin" in (roles or []) else "")
            + f"<button type='button' class='tab' data-tab='tab-engines'>{'Движки инференса' if lang=='ru' else 'Inference engines'}</button>"
            + f"<button type='button' class='tab' data-tab='tab-hf'>{'Модель с HF' if lang=='ru' else 'Model from HF'}</button>"
            + "</div><div class='tabpane' id='tab-models'>"
            + f"<form class='upload' id='f'><b>{T('dash.upload', lang)}</b><br><br>"
            + "<label style='color:#9aa4b2;font-size:12px'>"
            + ("Тип артефакта" if lang == "ru" else "Artifact kind") + ": </label>"
            + "<select id='kind' name='kind'>"
            + ("<option value='model'>Модель</option>"
               "<option value='engine_image'>Образ инференс-движка</option>"
               if lang == "ru" else
               "<option value='model'>Model</option>"
               "<option value='engine_image'>Engine image</option>")
            + "</select><br><br>"
            f"<input type='file' name='file'> <button type='submit'>{T('dash.upload_btn', lang)}</button>"
            "<div class='uprog' id='uprog'><span id='ubar'></span></div>"
            + "<div id='kindnotice' style='display:none;color:#f0c674;font-size:12px;margin-top:6px'>"
            + ("Это контейнерный образ (engine image) — он будет запущен вместе с моделью "
               "в изолированной среде Kata." if lang == "ru" else
               "This is a container image (engine image) — it will be run together with the model "
               "in an isolated Kata environment.")
            + "</div>"
            f"<div style='color:#9aa4b2;font-size:12px;margin-top:6px'>{T('dash.upload_hint', lang)}</div>"
            "</form>"
            + "</div>"  # /tab-models
            + ("<div class='tabpane' id='tab-local' style='display:none'>"
               + "<div class='upload' style='margin-top:0'><b>" + ("Локальная LLM: файл + движок (обязателен)" if lang == "ru" else "Local LLM: file + engine (required)") + "</b><br><br>"
               + "<input type='file' id='locfile'> "
               + "<select id='locengine'><option value=''>engine: (выберите скачанный)</option></select> "
               + "<button id='locbtn' type='button'>" + ("Загрузить и запустить тест" if lang == "ru" else "Upload & run test") + "</button>"
               + "<div id='locstatus' style='color:#9aa4b2;font-size:12px;margin-top:6px'></div></div>"
               + "<div class='upload' style='margin-top:0'><b>" + ("Перепривязка движка (перезапуск теста)" if lang == "ru" else "Engine rebind (re-run test)") + "</b><br><br>"
               + "<input id='rbsha' type='text' placeholder='model sha256' style='width:45%'> "
               + "<select id='rbengine'><option value=''>engine: (выберите скачанный)</option></select> "
               + "<button id='rbbtn' type='button'>" + ("Сменить движок и перезапустить" if lang == "ru" else "Rebind & re-run") + "</button>"
               + "<div id='rbstatus' style='color:#9aa4b2;font-size:12px;margin-top:6px'></div></div>"
               + "</div>")
            + ("<div class='tabpane' id='tab-bundletest' style='display:none'>"
               + "<div class='upload' style='margin-top:0'>"
               + "<b>" + ("Тест bundle (инференс на наборе вопросов)" if lang == "ru"
                          else "Bundle test (inference over prompt set)") + "</b><br><br>"
               + "<input id='btsha' type='text' placeholder='" + ("sha256 модели (необязательно)"
                        if lang == "ru" else "model sha256 (optional)") + "' style='width:38%'> "
               + "<input id='btbundle' type='text' placeholder='bundle_id (опц.)' style='width:22%'> "
               + "<button id='btbtn' type='button'>" + ("Прогнать тест" if lang == "ru" else "Run test") + "</button>"
               + "<div id='btstatus' style='color:#9aa4b2;font-size:12px;margin-top:6px'></div></div></div>"
               + "<div class='tabpane' id='tab-engines' style='display:none'>"
               + "<div class='upload' id='imgs' style='margin-top:0'>"
               + "<b>" + ("Импорт образа движка" if lang == "ru" else "Engine image import") + "</b><br><br>"
               + "<input id='imgref' type='text' placeholder='mlscan-registry/…@sha256:…' style='width:60%'> "
               + "<input id='imgtarkey' type='text' placeholder='oci_tar_key (опц.)' style='width:20%'> "
               + "<button id='imgsign-btn' type='button'>" + ("Подписать" if lang == "ru" else "Sign") + "</button> "
               + "<button id='imgimport-btn' type='button'>" + ("Импорт" if lang == "ru" else "Import") + "</button>"
               + "<div id='imgstatus' style='color:#9aa4b2;font-size:12px;margin-top:6px'></div>"
               + "<div style='margin-top:6px;font-size:12px'>" + ("Скачанные движки:" if lang == "ru" else "Downloaded engines:")
               + " <select id='englist' style='min-width:40%'></select> <button id='engrefresh' type='button'>refresh</button></div>"
               + "</div></div>" if "admin" in (roles or []) else "<div class='tabpane' id='tab-engines' style='display:none'></div>")
            + ("<div class='tabpane' id='tab-hf' style='display:none'>"
               + "<div class='upload' id='hfpanel' style='margin-top:0'>"
               + "<b>" + ("Hugging Face: поиск и загрузка" if lang == "ru" else "Hugging Face: search & download") + "</b><br><br>"
               + "<input id='hfquery' type='text' placeholder='name/query' style='width:22%'> "
               + "<input id='hftype' type='text' placeholder='type (text-generation)' style='width:16%'> "
               + "<select id='hfquant'><option value=''>quant: any</option><option>Q4_K_M</option><option>Q5_K_M</option><option>Q8_0</option><option>F16</option></select> "
               + "<button id='hfsearch-btn' type='button'>" + ("Найти" if lang == "ru" else "Search") + "</button> "
               + "<select id='hfengine'><option value=''>engine: (обязателен из скачанных)</option></select>"
               + "<div id='hfresults' style='margin-top:6px;font-size:12px'></div>"
               + "<div id='hfstatus' style='color:#9aa4b2;font-size:12px'></div>"
               + "</div>"
               + "<div class='upload' style='margin-top:0'><b>HF token</b> "
               + "<input id='hftoken' type='password' placeholder='hf_…' style='width:28%'> "
               + "<button id='hftokensave' type='button'>" + ("Сохранить токен" if lang == "ru" else "Save token") + "</button> "
               + "<span id='hftokenstatus' style='color:#9aa4b2;font-size:12px'></span></div>"
               + "</div>" if "admin" in (roles or []) else "<div class='tabpane' id='tab-hf' style='display:none'></div>")
            + "</div>"  # /downloads
            + ("<div class='upload' id='psset' style='margin-top:0'>"
               + "<b>" + ("Набор тестов (XLSX)" if lang == "ru" else "Prompt set (XLSX)") + "</b><br><br>"
               + "<input type='file' id='psfile' accept='.xlsx' name='psfile'> "
               + "<span id='psstatus' style='color:#9aa4b2;font-size:12px'></span>"
               + "</div>" if "admin" in (roles or []) else "")
            + ("<div class='upload' id='dcpanel' style='margin-top:0'>"
               + "<b>" + ("Домен → класс policy" if lang == "ru" else "Domain → policy class") + "</b><br><br>"
               + "<input id='dcdomain' type='text' placeholder='"
               + ("домен/критерий (напр. Правонарушение)" if lang == "ru" else "domain/criterion") + "' style='width:34%'> "
               + "<input id='dcclass' type='text' placeholder='policy class' style='width:20%'> "
               + "<button id='dcsave' type='button'>" + ("Сохранить" if lang == "ru" else "Save") + "</button>"
               + "<div id='dcstatus' style='color:#9aa4b2;font-size:12px;margin-top:6px'></div></div>"
               if "admin" in (roles or []) else "")
            + "<div class='controls'>"
            f"<input id='q' type='search' placeholder='{T('dash.filter', lang)}'>"
            "<select id='vf'>"
            f"<option value=''>{T('dash.all_verdicts', lang)}</option>"
            "<option value='Malicious'>Malicious</option>"
            "<option value='Dangerous'>Dangerous</option>"
            "<option value='Needs review'>Needs review</option>"
            "<option value='Safe'>Safe</option>"
            "<option value='Inconclusive'>Inconclusive</option>"
            f"<option value='__none__'>{T('dash.no_verdict', lang)}</option>"
            "</select>"
            "<select id='sort'>"
            f"<option value='date_desc'>{T('dash.sort_date_desc', lang)}</option>"
            f"<option value='date_asc'>{T('dash.sort_date_asc', lang)}</option>"
            f"<option value='size_desc'>{T('dash.sort_size_desc', lang)}</option>"
            f"<option value='size_asc'>{T('dash.sort_size_asc', lang)}</option>"
            "</select>"
            "<span id='count' style='color:#9aa4b2;font-size:12px'></span>"
            "</div>"
            f"<table><thead><tr><th>{T('dash.col.artifact', lang)}</th>"
            f"<th>{T('dash.col.date', lang)}</th><th>{T('dash.col.size', lang)}</th><th>SHA-256</th>"
            f"<th>{T('dash.col.progress', lang)}</th><th>{T('dash.col.verdict', lang)}</th>"
            f"<th>{T('dash.col.score', lang)}</th><th>{T('dash.col.action', lang)}</th></tr></thead>"
            f"<tbody id='rows'><tr><td colspan='8' style='color:#9aa4b2'>"
            f"{T('dash.loading', lang)}</td></tr></tbody></table>")
    return _page(T("ui.overview", lang), body, _js(lang), lang=lang, roles=roles, path=path)


def ui_settings(lang: str = "ru", current: str = "ru", message: str = "",
                roles: list | None = None, path: str = "/") -> bytes:
    opts = "".join(
        f"<option value='{c}'{' selected' if c == current else ''}>{T(f'nav.lang_{c}', lang)}</option>"
        for c in ("ru", "en"))
    body = (f"<h2>{T('settings.title', lang)}</h2>"
            f"<p style='color:#9aa4b2'>{T('settings.language_hint', lang)}</p>"
            + (f"<p style='color:#5dd39e'>{_esc(message)}</p>" if message else "")
            + "<form method='post' action='/settings/language' style='display:flex;gap:8px;align-items:center'>"
            f"<b>{T('settings.language', lang)}:</b>"
            f"<select name='lang' style='padding:8px'>{opts}</select>"
            f"<button type='submit'>{T('settings.save', lang)}</button></form>")
    return _page(T("settings.title", lang), body, lang=lang, roles=roles, path=path)


def ui_artifact(sid: str, lang: str = "ru", roles: list | None = None,
                path: str = "/") -> bytes | None:
    rec = _index.get(sid)
    live = progress_of(sid)
    if not rec:
        # Если скан уже завершён, но ещё не синхронизирован — анализируем «на месте».
        if live and live.get("state") == "done":
            try:
                _append(analyze(live))
                rec = _index.get(sid)
            except Exception:  # noqa: BLE001
                rec = None
    if not rec:
        if not live:
            return None
        # «Живая» страница прогресса с автообновлением до появления результата.
        js = ("<script>setInterval(function(){fetch('/api/progress/%s')"
              ".then(function(r){return r.ok?r.json():null;})"
              ".then(function(d){if(d&&(d.state==='done'||d.state==='error'))location.reload();})"
              ".catch(function(){});},3000);</script>") % sid
        return _page("artifact",
                     f"<p><a href='/'>{T('art.back', lang)}</a></p><h2>{_esc(live.get('name'))}</h2>"
                     f"<p>{T('art.running', lang)}: <b>{_esc(live.get('state'))}/{_esc(live.get('stage'))}</b> "
                     f"({live.get('progress')}%)</p>"
                     f"<div class='pbar'><span style='width:{live.get('progress',0)}%'></span></div>"
                     f"<p style='color:#9aa4b2'>{T('art.auto_refresh', lang)}</p>",
                     js, lang=lang, roles=roles, path=path)
    v = rec.get("verdict", "")
    rows = "".join(
        f"<tr><td>{f['level']}</td><td>{f['check_id']}</td><td>{f['severity']}</td>"
        f"<td>{f.get('confidence',0):.2f}</td><td>{_esc(TR(f['title'], lang))}</td>"
        f"<td><code>{_esc(TR(f.get('evidence') or '', lang))[:140]}</code></td></tr>"
        for f in sorted(rec.get("findings", []), key=lambda x: -SEV_RANK.get(x["severity"], 0)))
    body = (f"<p><a href='/'>{T('art.back', lang)}</a></p><h2>{_esc(rec.get('name'))} — "
            f"<span class='v-{v.replace(' ','')}'>{v}</span></h2>"
            f"<p>SHA-256: <code>{rec.get('sha256')}</code><br>"
            f"{T('art.size', lang)}: {rec.get('size')} {T('art.bytes', lang)}<br>"
            f"{T('art.risk', lang)}: <b>{rec['score'].get('risk_score')}</b>, "
            f"{T('art.max_severity', lang)}: {rec['score'].get('max_severity')}<br>"
            f"{T('art.policy', lang)}: <code>{rec['policy'].get('rule_id')}</code> → "
            f"{rec['policy'].get('action')}<br>"
            f"{T('art.timings', lang)}: {rec.get('timings')}<br>"
            f"{T('art.reason', lang)}: {_esc(TR(rec.get('service_reason'), lang))}</p>"
            f"<p>{T('art.reports', lang)}: <a href='/reports/{sid}.json?lang={lang}'>JSON</a> · "
            f"<a href='/reports/{sid}.md?lang={lang}'>Markdown</a> · "
            f"<a href='/reports/{sid}.sarif?lang={lang}'>SARIF</a></p>"
            f"<table><tr><th>{T('art.col.level', lang)}</th><th>{T('art.col.id', lang)}</th>"
            f"<th>Severity</th><th>{T('art.col.conf', lang)}</th><th>{T('art.col.finding', lang)}</th>"
            f"<th>{T('art.col.evidence', lang)}</th></tr>" + rows + "</table>")
    cov = (live or {}).get("coverage") or (rec or {}).get("coverage") or {}
    if cov and cov.get("complete") is False:
        det = "; ".join(
            f"{TR(_MODULE_LABELS.get(k, k), lang)}: {TR((cov.get('modules') or {}).get(k, {}).get('reason'), lang)}"
            if (cov.get("modules") or {}).get(k, {}).get("reason")
            else TR(_MODULE_LABELS.get(k, k), lang)
            for k in (cov.get("failed") or []))
        body += (f"<div class='warn'><b>{T('art.coverage_incomplete', lang)}</b><br>"
                 f"{_esc(det)}<br>"
                 f"<span style='color:#9aa4b2'>{T('art.coverage_hint', lang)}</span></div>")
    sb = (live or {}).get("sandbox") or {}
    if sb:
        load = sb.get("load") or {}
        sm = {k: v for k, v in (sb.get("summary") or {}).items() if k != "imports"}
        errs = load.get("errors") or []
        body += (f"<h3>{T('art.dynamic', lang)}</h3>"
                 f"<p>{T('art.dyn.status', lang)}: <b>{_esc(sb.get('status'))}</b>; "
                 f"{T('art.dyn.load', lang)}: {'ok' if load.get('ok') else 'fail'}; "
                 f"{T('art.dyn.type', lang)}: {_esc(load.get('type'))}</p>"
                 f"<p>{T('art.dyn.signals', lang)}: <code>{_esc(json.dumps(sm, ensure_ascii=False))}</code></p>")
        if errs:
            body += (f"<p>{T('art.dyn.errors', lang)}:<br>"
                     + "".join(f"<code>{_esc(TR(e, lang))}</code><br>" for e in errs[:5]) + "</p>")
    return _page(rec.get("name", "artifact"), body, lang=lang, roles=roles, path=path)


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "MLScanAnalytics/0.6"

    def log_message(self, *a):
        pass

    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie", "") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _lang(self, query: dict | None = None) -> str:
        """Язык запроса: ?lang= → cookie mlscan_lang → X-MLScan-Lang → глобальная настройка."""
        if i18n is None:
            return "ru"
        return i18n.resolve(headers=self.headers, query=query,
                            cookie=self.headers.get("Cookie"))

    def _wants_html(self) -> bool:
        """Похоже ли на навигацию браузера (а не на API-клиент)."""
        accept = self.headers.get("Accept") or ""
        return "text/html" in accept and not self.headers.get("Authorization")

    def _rate_limited(self) -> bool:
        """N6: rate-limit per subject/IP (429 + Retry-After). /healthz всегда доступен."""
        if authz is None:
            return False
        u = urllib.parse.urlparse(self.path)
        if u.path in ("/healthz", "/rate-limit"):
            return False
        # мультичастовая загрузка идёт сотнями запросов part -> лимит не применяем
        # (сессии/квоты/дедлайны загрузки уже контролируются отдельно)
        if u.path.startswith("/uploads/") or u.path.startswith("/api/progress/"):
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

    def _rate_limit_get(self) -> None:
        if authz is None:
            return self._json(503, {"error": "auth module unavailable"})
        return self._json(200, authz.rate_limit_state())

    def _rate_limit_set(self) -> None:
        """N6: настройка rate-limit UI/API на лету (admin; rps=0 — выключить)."""
        if authz is None:
            return self._json(503, {"error": "auth module unavailable"})
        if "admin" not in (getattr(self, "_roles", []) or []):
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

    def _require(self):
        """Аутентификация на входе: API-ключ из заголовка или cookie (после /login)."""
        if authz is None:
            return {"subject": "anonymous"}
        self._rid = authz.request_id(self.headers)
        ent = authz.authenticate(self.headers)
        if ent is None:
            ent = authz.from_cookie(self.headers)
        if ent is None:
            self._subject = "anonymous"
            try:
                authz.audit("anonymous", "auth_denied", "http", self.path, self._rid,
                            self.client_address[0], {"method": self.command})
            except Exception:  # noqa: BLE001
                pass
            if self._wants_html() and self.command == "GET":
                # истёкшая сессия у открытой вкладки: возвращаем на вход с пояснением
                self.send_response(302)
                self.send_header("Location", "/login?expired=1")
                self.end_headers()
                return None
            self._json(401, {"error": T("msg.unauthorized", self._lang()),
                             "request_id": self._rid})
            return None
        self._subject = ent["subject"]
        self._roles = ent.get("roles") or []
        return ent

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        rid = getattr(self, "_rid", None)
        if rid is None and authz is not None:
            rid = authz.new_request_id()
            self._rid = rid
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # страницы и API не кэшируются: иначе переключение языка/данные «залипают»
        self.send_header("Cache-Control", "no-store, must-revalidate")
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

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def _test_request(self, method: str, path: str, body: bytes | None = None,
                      ctype: str = "application/json") -> tuple[int, bytes]:
        cx = http.client.HTTPConnection(TEST_HOST, TEST_PORT, timeout=120)
        cx.putrequest(method, path)
        if body is not None:
            cx.putheader("Content-Length", str(len(body)))
            cx.putheader("Content-Type", ctype)
        if INTERNAL_KEY:
            cx.putheader("Authorization", f"Bearer {INTERNAL_KEY}")
        if getattr(self, "_rid", None):
            cx.putheader("X-Request-ID", self._rid)
        cx.endheaders()
        if body:
            cx.send(body)
        resp = cx.getresponse()
        data = resp.read()
        cx.close()
        return resp.status, data

    def _prompt_sets_proxy(self, q: dict) -> None:
        """Прокси к сервису тестирования: активный набор (GET) и загрузка XLSX (POST)."""
        try:
            if self.command == "GET":
                code, body = self._test_request("GET", "/prompt-sets/active")
                return self._send(code, body, "application/json; charset=utf-8")
            n = int(self.headers.get("Content-Length", "0") or "0")
            data = self.rfile.read(n) if n else b"{}"
            code, body = self._test_request("POST", "/prompt-sets", data)
            return self._send(code, body, "application/json; charset=utf-8")
        except Exception as exc:  # noqa: BLE001
            return self._json(502, {"error": f"testing: {type(exc).__name__}: {exc}"})

    def _proxy_upload(self, q: dict) -> None:
        name = q.get("name", ["sample.pkl"])[0]
        fmt = q.get("fmt", ["pickle"])[0]
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return self._json(400, {"error": T("msg.empty_body_cl", self._lang(q))})
        cx = http.client.HTTPConnection(TEST_HOST, TEST_PORT, timeout=1800)
        kind = q.get("kind", ["model"])[0]
        path = (f"/scans/upload?name={urllib.parse.quote(name)}&fmt={urllib.parse.quote(fmt)}"
                f"&kind={urllib.parse.quote(kind)}")
        cx.putrequest("POST", path)
        cx.putheader("Content-Length", str(n))
        cx.putheader("Content-Type", "application/octet-stream")
        if INTERNAL_KEY:
            cx.putheader("Authorization", f"Bearer {INTERNAL_KEY}")
        if getattr(self, "_rid", None):
            cx.putheader("X-Request-ID", self._rid)
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
        q = urllib.parse.parse_qs(u.query)
        if p == "/healthz":
            lang = self._lang(q)
            try:
                load_policy()   # обновить состояние подписи политики (fail-closed)
            except Exception:  # noqa: BLE001
                pass
            return self._json(200, {"policy_ok": POLICY_OK, "policy_reason": POLICY_REASON, "status": "ok", "scans": len(_index),
                                    "language": i18n.global_lang() if i18n else "ru",
                                    "startup_language": i18n.startup_lang() if i18n else "ru",
                                    "languages": list(i18n.SUPPORTED) if i18n else ["ru"],
                                    "request_language": lang})
        if self._rate_limited():
            return
        if p == "/lang":
            # переключатель языка UI: cookie на год, затем возврат на исходную страницу
            code = (q.get("set", ["ru"])[0] or "ru").lower()
            if i18n is not None and i18n.normalize(code) is None:
                code = "ru"
            nxt = (q.get("next", ["/"])[0] or "/")
            if not nxt.startswith("/") or nxt.startswith("//"):
                nxt = "/"
            self.send_response(302)
            self.send_header("Set-Cookie",
                             f"mlscan_lang={code}; Path=/; Max-Age=31536000; SameSite=Lax")
            self.send_header("Location", nxt)
            self.end_headers()
            return
        if p == "/prompt-sets":
            return self._prompt_sets_proxy(q)
        if p == "/images/list":
            code, body = self._test_request("GET", "/images/list")
            return self._send(code, body, "application/json; charset=utf-8")
        if p == "/hf/token":
            code, body = self._test_request("GET", "/hf/token")
            return self._send(code, body, "application/json; charset=utf-8")
        if p == "/bundles":
            code, body = self._test_request("GET", "/bundles" + (("?" + (u.query or "")) if u.query else ""))
            return self._send(code, body, "application/json; charset=utf-8")
        if p.startswith("/bundles/") and p.endswith("/test"):
            code, body = self._test_request("GET", p)
            return self._send(code, body, "application/json; charset=utf-8")
        if p == "/hf/downloads":
            code, body = self._test_request("GET", "/hf/downloads")
            return self._send(code, body, "application/json; charset=utf-8")
        if p.startswith("/hf/downloads/"):
            code, body = self._test_request("GET", p)
            return self._send(code, body, "application/json; charset=utf-8")
        if p == "/domain-class":
            code, body = self._test_request("GET", "/domain-class")
            return self._send(code, body, "application/json; charset=utf-8")
        if p == "/login":
            notice = T("login.session_expired", self._lang(q)) if q.get("expired") else ""
            return self._send(200, _login_page(lang=self._lang(q), notice=notice),
                              "text/html; charset=utf-8")
        if p == "/logout":
            self.send_response(302)
            self.send_header("Set-Cookie", "mlscan_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
            self.send_header("Set-Cookie", "mlscan_key=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
            self.send_header("Location", "/login")
            self.end_headers()
            return
        if self._require() is None:
            return
        lang = self._lang(q)
        if p == "/settings":
            cur = i18n.global_lang() if i18n else "ru"
            if "admin" not in (getattr(self, "_roles", []) or []):
                return self._send(403, ui_settings(lang, cur, T("settings.admin_only", lang),
                                                   roles=getattr(self, "_roles", [])),
                                  "text/html; charset=utf-8")
            msg = T("settings.saved", lang, lang=cur) if q.get("saved") else ""
            return self._send(200, ui_settings(lang, cur, msg, roles=getattr(self, "_roles", []),
                                               path=self.path), "text/html; charset=utf-8")
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
            if not rec:
                return self._json(404, {"error": T("msg.not_found", lang)})
            return self._json(200, localized_record(rec, lang))
        if p.startswith("/reports/"):
            sid, _, ext = p.split("/", 2)[2].rpartition(".")
            rec = _index.get(sid)
            if not rec:
                return self._json(404, {"error": T("msg.not_found", lang)})
            if ext == "json":
                return self._send(200, json.dumps(localized_record(rec, lang), ensure_ascii=False, indent=2).encode(),
                                  "application/json; charset=utf-8")
            if ext == "md":
                return self._send(200, report_md(rec, lang).encode(), "text/markdown; charset=utf-8")
            if ext == "sarif":
                return self._send(200, json.dumps(report_sarif(rec, lang), ensure_ascii=False, indent=2).encode(),
                                  "application/json; charset=utf-8")
            return self._json(404, {"error": T("msg.unknown_format", lang)})
        if p == "/":
            return self._send(200, ui_index(lang, roles=getattr(self, "_roles", []),
                                           path=self.path), "text/html; charset=utf-8")
        if p.startswith("/artifact/"):
            html = ui_artifact(p.split("/", 2)[2], lang, roles=getattr(self, "_roles", []),
                               path=self.path)
            return self._send(200, html, "text/html; charset=utf-8") if html else self._send(404, b"not found", "text/plain")
        return self._json(404, {"error": T("msg.not_found", lang)})

    def do_POST(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/rate-limit":
            ent = self._require()
            if ent is None:
                return
            if self.command == "POST":
                return self._rate_limit_set()
            return self._rate_limit_get()
        if self._rate_limited():
            return
        lang = self._lang(q)
        if u.path == "/settings/language":
            ent = self._require()
            if ent is None:
                return
            if "admin" not in (getattr(self, "_roles", []) or []):
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
            if "application/json" in (self.headers.get("Accept") or ""):
                return self._json(200, {"language": applied})
            self.send_response(302)
            self.send_header("Set-Cookie",
                             f"mlscan_lang={applied}; Path=/; Max-Age=31536000; SameSite=Lax")
            self.send_header("Location", "/settings?saved=1")
            self.end_headers()
            return
        if u.path == "/login":
            n = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(n).decode() if n else ""
            form = urllib.parse.parse_qs(body)
            rid = authz.request_id(self.headers) if authz else ""
            ip = self.client_address[0]
            username = (form.get("username", [""])[0] or "").strip()
            password = form.get("password", [""])[0] or ""
            key = (form.get("key", [""])[0] or "").strip()
            if username:
                ent = authz.verify_password(username, password) if authz else None
                if not ent:
                    if authz:
                        authz.audit(username, "login_failed", "user", username, rid, ip, {})
                    return self._send(401, _login_page(T("login.err_credentials", lang), lang),
                                      "text/html; charset=utf-8")
                token = authz.make_session(ent["subject"], ent["roles"]) if authz else None
                if authz:
                    authz.audit(ent["subject"], "login", "user", ent["subject"], rid, ip, {"roles": ent["roles"]})
                self.send_response(302)
                if token:
                    self.send_header("Set-Cookie",
                                     f"mlscan_session={token}; HttpOnly; Path=/; SameSite=Lax; "
                                     f"Max-Age={SESSION_TTL}{_cookie_attr()}")
                self.send_header("Location", "/")
                self.end_headers()
                return
            ent = authz.validate_key(key) if authz else None
            if not ent:
                if authz:
                    authz.audit("anonymous", "login_failed", "apikey", "", rid, ip, {})
                return self._send(401, _login_page(T("login.err_key", lang), lang),
                                  "text/html; charset=utf-8")
            if authz:
                authz.audit(ent["subject"], "login", "apikey", ent["subject"], rid, ip, {})
            self.send_response(302)
            self.send_header("Set-Cookie", f"mlscan_key={key}; HttpOnly; Path=/; SameSite=Lax{_cookie_attr()}")
            self.send_header("Location", "/")
            self.end_headers()
            return
        if self._require() is None:
            return
        if u.path == "/sync":
            try:
                limit = int(q.get("backfill", ["0"])[0] or "0")
            except ValueError:
                limit = 0
            res = sync_once(backfill=limit)
            if authz is not None:
                try:
                    authz.audit(getattr(self, "_subject", "?"), "sync", "analytics", "", self._rid,
                                self.client_address[0], res)
                except Exception:  # noqa: BLE001
                    pass
            return self._json(200, res)
        if u.path == "/upload":
            return self._proxy_upload(q)
        if u.path == "/prompt-sets":
            return self._prompt_sets_proxy(q)
        if u.path == "/hf/token":
            n = int(self.headers.get("Content-Length", "0") or "0")
            data = self.rfile.read(n) if n else b"{}"
            code, body = self._test_request("POST", "/hf/token", data)
            return self._send(code, body, "application/json; charset=utf-8")
        if u.path.startswith("/bundles/") and u.path.endswith("/rebind"):
            n = int(self.headers.get("Content-Length", "0") or "0")
            data = self.rfile.read(n) if n else b"{}"
            code, body = self._test_request("POST", u.path, data)
            return self._send(code, body, "application/json; charset=utf-8")
        if u.path in ("/hf/search", "/hf/downloads"):
            n = int(self.headers.get("Content-Length", "0") or "0")
            data = self.rfile.read(n) if n else b"{}"
            code, body = self._test_request("POST", u.path, data)
            return self._send(code, body, "application/json; charset=utf-8")
        if u.path.startswith("/hf/downloads/") and u.path.endswith("/cancel"):
            code, body = self._test_request("POST", u.path, b"{}")
            return self._send(code, body, "application/json; charset=utf-8")
        if u.path == "/domain-class":
            n = int(self.headers.get("Content-Length", "0") or "0")
            data = self.rfile.read(n) if n else b"{}"
            code, body = self._test_request("POST", "/domain-class", data)
            return self._send(code, body, "application/json; charset=utf-8")
        if u.path == "/bundles":
            n = int(self.headers.get("Content-Length", "0") or "0")
            data = self.rfile.read(n) if n else b"{}"
            code, body = self._test_request("POST", "/bundles", data)
            return self._send(code, body, "application/json; charset=utf-8")
        if u.path.startswith("/bundles/") and u.path.endswith("/test"):
            n = int(self.headers.get("Content-Length", "0") or "0")
            data = self.rfile.read(n) if n else b"{}"
            code, body = self._test_request("POST", u.path, data)
            return self._send(code, body, "application/json; charset=utf-8")
        if u.path.startswith("/images/") and (u.path.endswith("/sign") or u.path.endswith("/sbom")):
            n = int(self.headers.get("Content-Length", "0") or "0")
            data = self.rfile.read(n) if n else b"{}"
            code, body = self._test_request("POST", u.path, data)
            return self._send(code, body, "application/json; charset=utf-8")
        if u.path == "/images/import":
            n = int(self.headers.get("Content-Length", "0") or "0")
            data = self.rfile.read(n) if n else b"{}"
            code, body = self._test_request("POST", "/images/import", data)
            return self._send(code, body, "application/json; charset=utf-8")
        return self._json(404, {"error": T("msg.not_found", lang)})


def main() -> None:
    _load_store()
    threading.Thread(target=poller, daemon=True).start()
    _startup_writer_lock()
    port = int(os.environ.get("PORT", "8080"))
    print(f"[analytics] on :{port}; testing={TESTING_URL}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
