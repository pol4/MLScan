#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Аттестации и решение CI-gate (v3, L4).

Аттестация — подписанное утверждение (in-toto/SLSA-подобный predicate) о результате прогона
bundle: входы (image digest, model sha, версии) и выходы (вердикт, покрытие, метрики). CI-gate
выдаёт `allow|block|quarantine` по вердикту/метрикам и привязке к bundle (образ+модель).
"""
from __future__ import annotations

import hashlib
import hmac
import json

BLOCK_VERDICTS = ("Malicious", "Dangerous")
REVIEW_VERDICTS = ("Needs review", "Inconclusive")


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def make_statement(*, bundle_id: str, engine_image: str, model_sha256: str,
                   verdict: str, action: str, coverage: dict | None = None,
                   metrics: dict | None = None, versions: dict | None = None) -> dict:
    predicate = {"verdict": verdict, "action": action, "coverage": coverage or {},
                 "metrics": metrics or {}, "versions": versions or {}}
    return {"type": "mlscan.bundle-verdict/v1", "subject": [
        {"name": engine_image, "digest": {"sha256": engine_image.split("@sha256:")[-1]}},
        {"name": "model", "digest": {"sha256": model_sha256}}],
        "predicate": predicate, "bundle_id": bundle_id}


def make_artifact_statement(*, model_sha256: str, verdict: str, action: str,
                            coverage: dict | None = None, source: str = "artifact-verdict",
                            engine_image: str = "") -> dict:
    """Подписанное утверждение о решении gate по артефакту модели (когда пары (образ, модель) нет).

    source: artifact-verdict (вердикт артефакта) | policy-default (решение по умолчанию, fail-closed).
    """
    subject = [{"name": "model", "digest": {"sha256": model_sha256}}]
    if engine_image:
        subject.append({"name": engine_image, "digest": {"sha256": engine_image.split("@sha256:")[-1]}})
    predicate = {"verdict": verdict or None, "action": action, "source": source,
                 "coverage": coverage or {}}
    return {"type": "mlscan.artifact-verdict/v1", "subject": subject,
            "predicate": predicate, "bundle_id": None}


def statement_digest(statement: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(statement).encode()).hexdigest()


def sign(statement: dict, key: str) -> str:
    return hmac.new(key.encode(), statement_digest(statement).encode(), hashlib.sha256).hexdigest()


def verify(statement: dict, signature: str, key: str) -> bool:
    return hmac.compare_digest(sign(statement, key), signature or "")


def gate_decision(verdict: str, *, safety_fail: int = 0, pass_rate: float = 1.0,
                  block_rate: float = 0.0) -> tuple[str, str]:
    """Решение CI-gate: (action, reason)."""
    if safety_fail and safety_fail > 0:
        return "block", "safety_fail>0"
    if verdict in BLOCK_VERDICTS:
        return "block", f"verdict={verdict}"
    if verdict in REVIEW_VERDICTS:
        return "quarantine", f"verdict={verdict}"
    if pass_rate < block_rate:
        return "quarantine", f"pass_rate {pass_rate} < {block_rate}"
    if verdict == "Safe":
        return "allow", "ok"
    # fail-closed: неизвестный/пустой вердикт не может быть разрешением
    return "quarantine", f"неизвестный вердикт: {verdict or '—'}"
