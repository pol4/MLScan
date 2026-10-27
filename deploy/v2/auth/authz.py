#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MLScan AuthN/Z + audit (stdlib).

Аутентификация на входе: API-ключ в `Authorization: Bearer <key>` или `X-API-Key`
(ключи задаются окружением `MLSCAN_KEYS` — JSON вида {"<key>": {"subject": "...", "roles": ["..."]}}).

Журнал: подключения (`connections`) и события (`audit_log`, hash-chain) в PostgreSQL,
если доступен клиент (PGHOST). Correlation-id — `X-Request-ID` (или генерируется) и
возвращается в ответе.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import threading
import json
import os
import sys
import time
import uuid

_Pg = None
try:
    sys.path.insert(0, "/opt/pg")
    from pgclient import Pg as _Pg  # noqa: E402
except Exception:  # noqa: BLE001
    _Pg = None

KEYS = {}
try:
    KEYS = json.loads(os.environ.get("MLSCAN_KEYS", "{}"))
except Exception:  # noqa: BLE001
    KEYS = {}
AUTH_ENABLED = os.environ.get("MLSCAN_AUTH", "on").lower() not in ("off", "0", "false")


SESSION_SECRET = os.environ.get("MLSCAN_SESSION_SECRET", "")
PBKDF2_ITER = int(os.environ.get("PBKDF2_ITER", "200000"))


def _roles(v) -> list:
    """TEXT[] из pgclient приходит строкой вида '{admin,analyst}'."""
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        return [r for r in v.strip("{}").split(",") if r]
    return []


def hash_password(password: str, salt: str | None = None, iterations: int = PBKDF2_ITER):
    import hashlib as _h
    import secrets as _s
    if salt is None:
        salt = _s.token_hex(16)
    dk = _h.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations)
    return salt, iterations, dk.hex()


def verify_password(subject: str, password: str):
    """Проверка логина/пароля по таблице users. Возвращает {subject, roles} или None."""
    c = _conn()
    if not c:
        return None
    try:
        _cols, rows = c.query("SELECT subject, roles, salt, iterations, password_hash FROM users "
                              f"WHERE subject = {_lit(subject)}")
    except Exception:  # noqa: BLE001
        return None
    finally:
        c.close()
    if not rows:
        return None
    subj, roles, salt, iters, ph = rows[0]
    if not ph or not salt:
        return None
    import hashlib as _h
    calc = _h.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt),
                          int(iters or PBKDF2_ITER)).hex()
    if hmac.compare_digest(calc, ph):
        return {"subject": subj, "roles": _roles(roles)}
    return None


def make_session(subject: str, roles, ttl: int = 12 * 3600):
    if not SESSION_SECRET:
        return None
    import base64 as _b
    payload = _b.urlsafe_b64encode(json.dumps(
        {"sub": subject, "roles": list(roles or []), "exp": int(__import__("time").time()) + ttl}
    ).encode()).decode()
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig


def verify_session(token: str):
    if not SESSION_SECRET or not token or "." not in token:
        return None
    import base64 as _b
    payload, sig = token.rsplit(".", 1)
    exp = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, exp):
        return None
    try:
        d = json.loads(_b.urlsafe_b64decode(payload))
    except Exception:  # noqa: BLE001
        return None
    if int(d.get("exp", 0)) < int(__import__("time").time()):
        return None
    return {"subject": d.get("sub"), "roles": d.get("roles", [])}


def from_cookie(headers):
    """Сессия/ключ из cookie (mlscan_session — подписанная, mlscan_key — API-ключ)."""
    raw = headers.get("Cookie", "") or ""
    vals = {}
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            vals[k] = v
    if vals.get("mlscan_session"):
        ent = verify_session(vals["mlscan_session"])
        if ent:
            return ent
    if vals.get("mlscan_key"):
        return validate_key(vals["mlscan_key"])
    return None


def new_request_id() -> str:
    return uuid.uuid4().hex


def request_id(headers) -> str:
    rid = headers.get("X-Request-ID") or headers.get("X-Correlation-ID")
    return rid.strip() if rid else new_request_id()


def validate_key(key: str):
    """Проверка «сырого» ключа (для формы логина/UI)."""
    if not key:
        return None
    ent = KEYS.get(key)
    return {"subject": ent.get("subject", "unknown"), "roles": ent.get("roles", [])} if ent else None


def authenticate(headers):
    """Вернёт dict(subject, roles) при успехе, иначе None."""
    if not AUTH_ENABLED:
        return {"subject": "anonymous", "roles": ["admin"]}
    auth = (headers.get("Authorization") or "")
    key = ""
    if auth.lower().startswith("bearer "):
        key = auth[7:].strip()
    if not key:
        key = (headers.get("X-API-Key") or "").strip()
    if not key:
        return None
    ent = KEYS.get(key)
    if not ent:
        # N6: JWT (HS256) — короткоживущий токен CI/API (проверяется строго: alg/exp/aud/iss)
        if key.count(".") == 2:
            return verify_jwt(key)
        return None
    # Срок жизни API-ключа (docs/14, P1-4): expires_at — ISO-8601 или unix-время.
    # Истёкший или нечитаемый срок = ключ недействителен (fail-closed).
    exp = ent.get("expires_at")
    if exp:
        import datetime as _dt
        import time as _time
        try:
            if isinstance(exp, (int, float)) or str(exp).isdigit():
                deadline = float(exp)
            else:
                deadline = _dt.datetime.fromisoformat(str(exp).replace("Z", "+00:00")).timestamp()
        except Exception:  # noqa: BLE001
            return None
        if _time.time() > deadline:
            return None
    return {"subject": ent.get("subject", "unknown"), "roles": ent.get("roles", [])}


def _conn():
    if _Pg is None or not os.environ.get("PGHOST"):
        return None
    try:
        c = _Pg(os.environ["PGHOST"], int(os.environ.get("PGPORT", "5432")),
                os.environ.get("PGUSER", "mlscan"), os.environ.get("PGPASSWORD", ""),
                os.environ.get("PGDATABASE", "mlscan"), timeout=10)
        c.connect()
        return c
    except Exception:  # noqa: BLE001
        return None


def _lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def log_connection(subject: str, request_id: str, ip: str, ua: str,
                   path: str, method: str, status: int) -> None:
    c = _conn()
    if not c:
        return
    try:
        c.query("INSERT INTO connections(request_id,ip,user_agent,path,method,status) VALUES "
                f"({_lit(request_id)},{_lit(ip)},{_lit(ua)},{_lit(path)},{_lit(method)},{int(status)})")
    except Exception:  # noqa: BLE001
        pass
    finally:
        c.close()


def audit(subject: str, action: str, object_type: str, object_id: str,
          request_id: str, ip: str, details) -> None:
    c = _conn()
    if not c:
        return
    try:
        _cols, rows = c.query("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
        prev = rows[0][0] if rows else "GENESIS"
        payload = json.dumps({"subject": subject, "action": action, "object_type": object_type,
                              "object_id": object_id, "request_id": request_id, "ip": ip,
                              "details": details}, ensure_ascii=False, sort_keys=True)
        h = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
        c.query("INSERT INTO audit_log(action,object_type,object_id,request_id,ip,details,prev_hash,hash) VALUES "
                f"({_lit(action)},{_lit(object_type)},{_lit(object_id)},{_lit(request_id)},{_lit(ip)},"
                f"{_lit(payload)},{_lit(prev)},{_lit(h)})")
    except Exception:  # noqa: BLE001
        pass
    finally:
        c.close()

# ---------------------------------------------------------------------------
# N6: JWT (HS256) для API/CI — короткоживущие токены с exp/aud/iss, без внешнего IdP.
# Ключ: MLSCAN_JWT_KEY (или MLSCAN_SESSION_SECRET). Проверка строгая: только HS256.
# ---------------------------------------------------------------------------
JWT_KEY = os.environ.get("MLSCAN_JWT_KEY", "") or SESSION_SECRET
JWT_ISS = os.environ.get("MLSCAN_JWT_ISS", "mlscan")
JWT_AUD = os.environ.get("MLSCAN_JWT_AUD", "mlscan-api")


def _b64u_enc(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64u_dec(txt: str) -> bytes:
    pad = "=" * (-len(txt) % 4)
    return base64.urlsafe_b64decode(txt + pad)


def make_jwt(subject: str, roles, ttl: int = 3600, aud: str = "", iss: str = "", key: str = "") -> str | None:
    """Собрать HS256-JWT. None, если ключ не сконфигурирован (fail-closed)."""
    k = (key or JWT_KEY).encode()
    if not k:
        return None
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": subject, "roles": list(roles or []), "iat": now,
               "exp": now + int(ttl), "aud": aud or JWT_AUD, "iss": iss or JWT_ISS}
    signing = _b64u_enc(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        _b64u_enc(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = _b64u_enc(hmac.new(k, signing.encode(), hashlib.sha256).digest())
    return signing + "." + sig


def verify_jwt(token: str, aud: str = "", iss: str = "", key: str = ""):
    """Проверить HS256-JWT. Возвращает dict(subject, roles) или None (fail-closed)."""
    k = (key or JWT_KEY).encode()
    if not k or not token or token.count(".") != 2:
        return None
    head_b, pay_b, sig_b = token.split(".")
    try:
        header = json.loads(_b64u_dec(head_b))
    except Exception:  # noqa: BLE001
        return None
    if header.get("alg") != "HS256" or header.get("typ", "JWT") != "JWT":
        return None
    want = _b64u_enc(hmac.new(k, f"{head_b}.{pay_b}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(want, sig_b):
        return None
    try:
        d = json.loads(_b64u_dec(pay_b))
    except Exception:  # noqa: BLE001
        return None
    now = int(time.time())
    if int(d.get("exp", 0)) < now:
        return None
    if int(d.get("nbf", 0)) > now:
        return None
    if (aud or JWT_AUD) and d.get("aud") != (aud or JWT_AUD):
        return None
    if d.get("iss") != (iss or JWT_ISS):
        return None
    if not d.get("sub"):
        return None
    return {"subject": d["sub"], "roles": list(d.get("roles") or []), "via": "jwt"}


# ---------------------------------------------------------------------------
# N6: rate-limit (token bucket, per subject/IP). 0 rps = выключено.
# ---------------------------------------------------------------------------
RATE_RPS = float(os.environ.get("RATE_LIMIT_RPS", "0") or 0)
RATE_BURST = int(os.environ.get("RATE_LIMIT_BURST", "0") or 0)


class RateLimiter:
    """Простой token bucket: ok, пока есть токены; иначе retry_after (сек)."""

    def __init__(self, rps: float, burst: int, max_keys: int = 4096):
        self.rps = float(rps or 0)
        self.burst = max(1, int(burst or 1))
        self.max_keys = max_keys
        self._state: dict = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        if self.rps <= 0:
            return True, 0.0
        now = time.monotonic()
        with self._lock:
            tokens, ts = self._state.get(key, (float(self.burst), now))
            tokens = min(float(self.burst), tokens + (now - ts) * self.rps)
            if tokens >= 1.0:
                self._state[key] = (tokens - 1.0, now)
                ok, retry = True, 0.0
            else:
                self._state[key] = (tokens, now)
                ok, retry = False, max(0.0, (1.0 - tokens) / self.rps)
            if len(self._state) > self.max_keys:      # защита от роста словаря
                for k in sorted(self._state, key=lambda x: self._state[x][1])[: self.max_keys // 4]:
                    self._state.pop(k, None)
        return ok, retry


_limiter = RateLimiter(RATE_RPS, max(RATE_BURST, 1))


def rate_limit_key(headers, ip: str = "") -> str:
    """Ключ лимита: API-ключ/JWT, иначе IP (для неавторизованных запросов)."""
    auth = (headers.get("Authorization") or "")
    tok = auth[7:].strip() if auth.lower().startswith("bearer ") else (headers.get("X-API-Key") or "")
    if tok:
        return tok[:24]
    try:                                   # UI: лимит по пользователю сессии, а не по общему IP
        ent = from_cookie(headers)
        if ent and ent.get("subject"):
            return "user:" + str(ent["subject"])[:40]
    except Exception:  # noqa: BLE001
        pass
    return "ip:" + (ip or "?")


def rate_limit(key: str) -> tuple[bool, float]:
    return _limiter.allow(key)


def set_rate_limit(rps: float, burst: int) -> dict:
    """Изменить лимит на лету (эксплуатация/тесты). Возвращает действующие значения."""
    global _limiter
    with _limiter._lock:  # noqa: SLF001 — согласованная подмена состояния
        _limiter = RateLimiter(rps, max(int(burst or 1), 1))
    return {"rps": float(rps or 0), "burst": max(int(burst or 1), 1)}


def rate_limit_state() -> dict:
    return {"rps": _limiter.rps, "burst": _limiter.burst}
