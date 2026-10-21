#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MLScan Integrations (Этап 4).

Сквозные интеграции поверх Аналитического движка (Этап 3) и Сервиса тестирования (Этап 2):
  * Model Registry  — реестр решений по артефактам (ключ — SHA-256);
  * CI/CD Gate       — принять/заблокировать модель для пайплайна (GET /gate, POST /gate/scan);
  * SIEM/SOC Export  — события решений в JSONL и CEF (GET /events, GET /export/cef);
  * Threat Intel     — известные-плохие хэши и наблюдения по проверкам (GET/POST /intel).

Только стандартная библиотека. Не общается с Kubernetes API.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.parse
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


def TR(text, lang: str = "ru"):
    return i18n.tr(text, lang) if i18n else text

INTERNAL_KEY = os.environ.get("INTERNAL_KEY", "")


def _auth_headers() -> dict:
    return {"Authorization": f"Bearer {INTERNAL_KEY}"} if INTERNAL_KEY else {}


ANALYTICS_URL = os.environ.get(
    "ANALYTICS_URL", "http://mlscan-analytics.mlscan-analytics.svc.cluster.local:8080")
TESTING_URL = os.environ.get(
    "TESTING_URL", "http://mlscan-testing.mlscan-testing.svc.cluster.local:8080")
DATA_DIR = os.environ.get("DATA_DIR", "/data")
INTEL_PATH = os.environ.get("INTEL_PATH", "/etc/mlscan/intel.json")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "20"))
GATE_TIMEOUT = int(os.environ.get("GATE_TIMEOUT", "240"))

REGISTRY = os.path.join(DATA_DIR, "registry.json")
EVENTS = os.path.join(DATA_DIR, "events.jsonl")
_lock = threading.Lock()
_registry: dict[str, dict] = {}
_intel: dict = {"known_bad_sha256": [], "watch_checks": []}


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------
def http_get_json(url: str, timeout: int = 20):
    req = urllib.request.Request(url, headers=_auth_headers())
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def http_post_bytes(url: str, data: bytes, timeout: int = 60):
    req = urllib.request.Request(url, data=data, method="POST", headers=_auth_headers())
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


# ----------------------------------------------------------------------------
# Хранилища
# ----------------------------------------------------------------------------
def _load() -> None:
    global _registry, _intel
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.isfile(REGISTRY):
        try:
            with open(REGISTRY) as fh:
                _registry = json.load(fh)
        except Exception:  # noqa: BLE001
            _registry = {}
    if os.path.isfile(INTEL_PATH):
        try:
            with open(INTEL_PATH) as fh:
                _intel = json.load(fh)
        except Exception:  # noqa: BLE001
            pass


def _save_registry() -> None:
    with _lock:
        with open(REGISTRY, "w") as fh:
            json.dump(_registry, fh, ensure_ascii=False)


def _log_event(ev: dict) -> None:
    ev = dict(ev, ts=time.strftime("%Y-%m-%dT%H:%M:%S"))
    with _lock:
        with open(EVENTS, "a") as fh:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")


# ----------------------------------------------------------------------------
# Реестр и решения
# ----------------------------------------------------------------------------
def register(rec: dict) -> dict:
    sha = rec.get("sha256")
    if not sha:
        return rec
    entry = {
        "sha256": sha,
        "name": rec.get("name"),
        "verdict": rec.get("verdict"),
        "service_verdict": rec.get("service_verdict") or rec.get("verdict"),
        "action": (rec.get("policy") or {}).get("action"),
        "rule_id": (rec.get("policy") or {}).get("rule_id"),
        "risk_score": (rec.get("score") or {}).get("risk_score"),
        "active_checks": (rec.get("score") or {}).get("active_checks", []),
        "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _registry[sha] = entry
    _save_registry()
    return entry


def gate_decision(entry: dict, lang: str = "ru") -> dict:
    sha = entry.get("sha256")
    if sha and sha in _intel.get("known_bad_sha256", []):
        return {"decision": "block", "http": 403, "reason": T("msg.intel_block", lang)}
    checks = set(entry.get("active_checks") or [])
    watch = checks & set(_intel.get("watch_checks") or [])
    if watch:
        return {"decision": "block", "http": 403,
                "reason": T("msg.intel_watch", lang, ids=",".join(sorted(watch)))}
    action = (entry.get("action") or "").lower()
    if action == "allow":
        return {"decision": "allow", "http": 200, "reason": f"policy allow ({entry.get('verdict')})"}
    if action == "quarantine":
        return {"decision": "review", "http": 409, "reason": T("msg.policy_review", lang)}
    return {"decision": "block", "http": 403,
            "reason": f"policy {action or 'block'} ({entry.get('verdict')})"}


def sync_from_analytics() -> dict:
    try:
        data = http_get_json(ANALYTICS_URL + "/api/scans")
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"analytics: {exc}", "registered": 0}
    n = 0
    for rec in data.get("scans", []):
        sha = rec.get("sha256")
        if not sha:
            continue
        prev = _registry.get(sha, {})
        if prev.get("updated") == rec.get("analyzed_at"):
            continue
        register(rec)
        n += 1
    return {"ok": True, "registered": n, "total": len(_registry)}


def poller() -> None:
    while True:
        try:
            sync_from_analytics()
        except Exception:  # noqa: BLE001
            pass
        time.sleep(POLL_INTERVAL)


# ----------------------------------------------------------------------------
# On-demand gate scan (CI): отправить артефакт в сервис тестирования и решить
# ----------------------------------------------------------------------------
def gate_scan(name: str, fmt: str, data: bytes, lang: str = "ru") -> dict:
    try:
        r = http_post_bytes(f"{TESTING_URL}/scans?name={urllib.parse.quote(name)}&fmt={fmt}", data)
        sid = r["scan_id"]
    except Exception as exc:  # noqa: BLE001
        return {"decision": "review", "http": 409, "reason": f"testing service: {exc}"}
    t0 = time.time()
    while time.time() - t0 < GATE_TIMEOUT:
        try:
            rec = http_get_json(f"{TESTING_URL}/scans/{sid}")
        except Exception:  # noqa: BLE001
            time.sleep(2)
            continue
        if rec.get("state") in ("done", "error"):
            entry = {
                "sha256": rec.get("sha256"),
                "name": rec.get("name"),
                "verdict": rec.get("verdict"),
                "active_checks": sorted({f["check_id"] for f in rec.get("findings", [])}),
                "action": ("block" if rec.get("verdict") in ("Malicious", "Dangerous")
                           else "allow" if rec.get("verdict") == "Safe" else "quarantine"),
            }
            dec = gate_decision(entry, lang)
            entry["decision"] = dec["decision"]
            _registry[entry["sha256"]] = dict(entry, updated=time.strftime("%Y-%m-%dT%H:%M:%S"))
            _save_registry()
            _log_event({"kind": "gate_scan", "scan_id": sid, **entry, "reason": dec["reason"]})
            return {"scan_id": sid, **entry, **dec}
        time.sleep(2)
    return {"scan_id": sid, "decision": "review", "http": 409, "reason": T("msg.scan_timeout", lang)}


# ----------------------------------------------------------------------------
# SIEM
# ----------------------------------------------------------------------------
def read_events() -> list[dict]:
    out = []
    if os.path.isfile(EVENTS):
        with open(EVENTS) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:  # noqa: BLE001
                        pass
    return out


def to_cef(ev: dict) -> str:
    sev = {"block": 8, "review": 5, "allow": 1}.get(ev.get("decision"), 3)
    name = str(ev.get("name") or "unknown").replace("|", "/")
    ext = (f"src=MLScan sha256={ev.get('sha256')} verdict={ev.get('verdict')} "
           f"decision={ev.get('decision')} riskScore={ev.get('risk_score')} "
           f"checks={','.join(ev.get('active_checks', []))} msg={str(ev.get('reason') or '')}")
    return (f"CEF:0|MLScan|MLScan|1.0|{ev.get('kind','gate')}|{ev.get('decision','event')}|{sev}|"
            f"name={name} {ext}")


# ----------------------------------------------------------------------------
# HTTP handler
# ----------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "MLScanIntegrations/0.4"

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
            try:
                authz.audit("anonymous", "auth_denied", "http", self.path, self._rid,
                            self.client_address[0], {"method": self.command})
            except Exception:  # noqa: BLE001
                pass
            self._json(401, {"error": "unauthorized", "request_id": self._rid})
            return None
        if allowed and not (set(ent["roles"]) & set(allowed)):
            self._subject = ent["subject"]
            try:
                authz.audit(ent["subject"], "authz_denied", "http", self.path, self._rid,
                            self.client_address[0], {"method": self.command, "roles": ent["roles"]})
            except Exception:  # noqa: BLE001
                pass
            self._json(403, {"error": "forbidden", "request_id": self._rid})
            return None
        self._subject = ent["subject"]
        self._roles = ent.get("roles", [])
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
        if authz is not None and not getattr(self, "_logged", False):
            self._logged = True
            try:
                authz.log_connection(getattr(self, "_subject", "anonymous"), rid,
                                     self.client_address[0], self.headers.get("User-Agent", ""),
                                     self.path, self.command, code)
            except Exception:  # noqa: BLE001
                pass

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def do_GET(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        p = u.path
        if p == "/healthz":
            return self._json(200, {"status": "ok", "registry": len(_registry),
                                    "language": self._lang(q)})
        if self._require(["admin", "ci-reader", "service"]) is None:
            return
        lang = self._lang(q)
        if p == "/registry":
            return self._json(200, {"entries": list(_registry.values())})
        if p.startswith("/registry/"):
            sha = p.split("/", 2)[2]
            e = _registry.get(sha)
            return self._json(200, e) if e else self._json(404, {"error": T("msg.not_found", lang)})
        if p == "/intel":
            return self._json(200, _intel)
        if p == "/events":
            return self._send(200, "".join(json.dumps(e, ensure_ascii=False) + "\n"
                                           for e in read_events()).encode(),
                             "application/x-ndjson; charset=utf-8")
        if p == "/export/cef":
            return self._send(200, "".join(to_cef(e) + "\n" for e in read_events()).encode(),
                             "text/plain; charset=utf-8")
        if p == "/gate":
            if "sha256" in q:
                e = _registry.get(q["sha256"][0])
                if not e:
                    return self._json(404, {"decision": "review", "reason": T("msg.not_registered", lang)})
            elif "name" in q:
                e = next((x for x in _registry.values() if x.get("name") == q["name"][0]), None)
                if not e:
                    return self._json(404, {"decision": "review", "reason": T("msg.not_registered", lang)})
            else:
                return self._json(400, {"error": T("msg.need_sha_or_name", lang)})
            dec = gate_decision(e, lang)
            _log_event({"kind": "gate", **e, "decision": dec["decision"], "reason": dec["reason"]})
            return self._json(dec["http"], {**e, **dec})
        return self._json(404, {"error": T("msg.not_found", lang)})

    def do_POST(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        p = u.path
        n = int(self.headers.get("Content-Length", "0") or "0")
        if self._require(["admin", "ci-reader", "service"]) is None:
            return
        lang = self._lang(q)
        if p == "/intel" and "admin" not in getattr(self, "_roles", []):
            return self._json(403, {"error": "forbidden: intel requires admin",
                                    "request_id": getattr(self, "_rid", "")})
        if p == "/sync":
            return self._json(200, sync_from_analytics())
        if p == "/intel":
            body = json.loads(self.rfile.read(n) or b"{}")
            for sha in body.get("known_bad_sha256", []):
                if sha not in _intel["known_bad_sha256"]:
                    _intel["known_bad_sha256"].append(sha)
            for c in body.get("watch_checks", []):
                if c not in _intel["watch_checks"]:
                    _intel["watch_checks"].append(c)
            return self._json(200, _intel)
        if p == "/gate/scan":
            q = urllib.parse.parse_qs(u.query)
            data = self.rfile.read(n) if n else b""
            if not data:
                return self._json(400, {"error": "empty body"})
            dec = gate_scan(q.get("name", ["sample.pkl"])[0], q.get("fmt", ["pickle"])[0], data, lang)
            return self._json(dec.get("http", 409), dec)
        return self._json(404, {"error": T("msg.not_found", lang)})


def main() -> None:
    _load()
    threading.Thread(target=poller, daemon=True).start()
    port = int(os.environ.get("PORT", "8080"))
    print(f"[integrations] on :{port}; analytics={ANALYTICS_URL}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
