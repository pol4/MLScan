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

import hashlib
import json
import os
import sys
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


def new_request_id() -> str:
    return uuid.uuid4().hex


def request_id(headers) -> str:
    rid = headers.get("X-Request-ID") or headers.get("X-Correlation-ID")
    return rid.strip() if rid else new_request_id()


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
