#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evidence: append-only HMAC-цепочка и WORM-анкор (v3, P6).

Каждая запись ссылается на digest предыдущей и подписана HMAC — любое изменение/удаление ломает
цепочку. «Голова» цепочки периодически **анкорится** (immutable запись digest+времени+опциональный
нотариальный токен) — для внешнего WORM/нотаризации.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

GENESIS = "sha256:" + "0" * 64


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(prev: str, payload) -> str:
    return "sha256:" + hashlib.sha256((prev + canonical(payload)).encode()).hexdigest()


def _sig(digest: str, key: str) -> str:
    return hmac.new(key.encode(), digest.encode(), hashlib.sha256).hexdigest()


def append(chain: list[dict], payload, key: str) -> dict:
    prev = chain[-1]["digest"] if chain else GENESIS
    seq = (chain[-1]["seq"] + 1) if chain else 1
    digest = _digest(prev, payload)
    entry = {"seq": seq, "prev": prev, "payload": payload, "digest": digest,
             "sig": _sig(digest, key), "ts": time.time()}
    chain.append(entry)
    return entry


def verify_chain(chain: list[dict], key: str) -> tuple[bool, str]:
    prev = GENESIS
    for i, e in enumerate(chain or [], start=1):
        if e.get("seq") != i:
            return False, f"seq mismatch at {i}"
        if e.get("prev") != prev:
            return False, f"prev mismatch at {i}"
        if _digest(e.get("prev", ""), e.get("payload")) != e.get("digest"):
            return False, f"digest mismatch at {i}"
        if not hmac.compare_digest(_sig(e["digest"], key), e.get("sig", "")):
            return False, f"signature mismatch at {i}"
        prev = e["digest"]
    return True, "ok"


def anchor_head(chain: list[dict], key: str, notary: str = "") -> dict:
    head = chain[-1]["digest"] if chain else GENESIS
    seq = chain[-1]["seq"] if chain else 0
    anchor = {"head": head, "seq": seq, "ts": time.time(), "notary": notary}
    anchor["sig"] = hmac.new(key.encode(), canonical(anchor).encode(), hashlib.sha256).hexdigest()
    return anchor


def verify_anchor(chain: list[dict], anchor: dict, key: str) -> bool:
    head = chain[-1]["digest"] if chain else GENESIS
    seq = chain[-1]["seq"] if chain else 0
    if anchor.get("head") != head or anchor.get("seq") != seq:
        return False
    body = {k: anchor[k] for k in ("head", "seq", "ts", "notary")}
    return hmac.compare_digest(
        hmac.new(key.encode(), canonical(body).encode(), hashlib.sha256).hexdigest(),
        anchor.get("sig", ""))
