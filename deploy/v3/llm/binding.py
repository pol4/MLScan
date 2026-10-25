#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Binding «модель ↔ образ движка» и неизменяемый Bundle (v3, L0/L4).

Bundle — content-addressed связка: image digest + model sha256 + манифест запуска + версии
(prompt-set, detectors, policy). Любое изменение полей → новый bundle_id (воспроизводимость вердикта).
"""
from __future__ import annotations

import hashlib
import json
import time


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def bundle_id(image_digest: str, model_sha256: str, engine_manifest: dict,
              prompt_set: str = "", detectors: str = "", policy: str = "") -> str:
    payload = {"engine_image": image_digest, "model_sha256": model_sha256,
               "engine_manifest": engine_manifest or {}, "prompt_set": prompt_set,
               "detectors": detectors, "policy": policy}
    return "b-" + hashlib.sha256(canonical(payload).encode()).hexdigest()[:24]


def make_bundle(*, image_digest: str, model_sha256: str, engine_manifest: dict | None = None,
                prompt_set: str = "", detectors: str = "", policy: str = "",
                tenant: str = "") -> dict:
    em = engine_manifest or {}
    return {"bundle_id": bundle_id(image_digest, model_sha256, em, prompt_set, detectors, policy),
            "engine_image": image_digest, "model_sha256": model_sha256,
            "engine_manifest": em, "prompt_set": prompt_set, "detectors": detectors,
            "policy": policy, "tenant": tenant, "created": time.time()}


def validate_bundle(bundle: dict) -> tuple[bool, str]:
    if not isinstance(bundle, dict):
        return False, "bundle must be an object"
    for k in ("bundle_id", "engine_image", "model_sha256"):
        if not bundle.get(k):
            return False, f"нет поля '{k}'"
    img = bundle["engine_image"]
    if "@sha256:" not in img:
        return False, "engine_image должен быть по digest (…@sha256:…)"
    sha = bundle["model_sha256"]
    if not (isinstance(sha, str) and len(sha) == 64):
        return False, "model_sha256 должен быть 64 hex"
    expect = bundle_id(img, sha, bundle.get("engine_manifest") or {},
                       bundle.get("prompt_set", ""), bundle.get("detectors", ""),
                       bundle.get("policy", ""))
    if bundle["bundle_id"] != expect:
        return False, f"bundle_id не соответствует содержимому (ожидалось {expect})"
    return True, "ok"
