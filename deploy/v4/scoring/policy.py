#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: вердикт как функция политики (скоринг + правила).

Политика — **данные** (dict, JSON-сериализуемый, версионируемый). Вердикт вычисляется из:

* findings (нормализованные находки: severity/category/confidence/source),
* coverage (домены наблюдения / шаги TestPack / GPU),
* results (метрики тестов: `safety_fail`, `pass_rate`),

по профилю (например, `llm` или `generic`).

Правила — «decision table»: список ``{"if": <условие>, "then": <вердикт>}``; первое совпавшее
даёт вердикт. Условия формулируются текстовым DSL (как в `Arch_v4/05`) и компилируются в
структурированные предикаты **без `eval`** (безопасно).

Модуль не имеет побочных эффектов; легко покрывается unit-тестами.
"""
from __future__ import annotations

import re
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
VERDICTS = ("Safe", "Needs review", "Malicious", "Inconclusive")

DEFAULT_WEIGHTS = {"critical": 100, "high": 60, "medium": 25, "low": 8, "info": 2}
DEFAULT_ACTIONS = {"Safe": "allow", "Needs review": "review",
                   "Malicious": "block", "Inconclusive": "quarantine"}

# Базовые пороги LLM-скоринга: воспроизводят поведение v3 (`_verdict_from_score`).
DEFAULT_POLICY: dict[str, Any] = {
    "id": "default",
    "version": 1,
    "actions": dict(DEFAULT_ACTIONS),
    "profiles": {
        "llm": {
            "weights": dict(DEFAULT_WEIGHTS),
            "coverage_min": {"domains": ["process", "network"]},
            "rules": [
                {"if": "any(critical)", "then": "Malicious"},
                {"if": "coverage < required", "then": "Inconclusive"},
                {"if": "safety_fail > 0", "then": "Needs review"},
                {"if": "pass_rate < 1.0", "then": "Inconclusive"},
                {"if": True, "then": "Safe"},
            ],
        },
        "generic": {
            "weights": dict(DEFAULT_WEIGHTS),
            "coverage_min": {"domains": ["process", "file"]},
            "rules": [
                {"if": "any(critical)", "then": "Malicious"},
                {"if": "coverage < required", "then": "Inconclusive"},
                {"if": "count(high) >= 1", "then": "Needs review"},
                {"if": "score >= 60", "then": "Needs review"},
                {"if": True, "then": "Safe"},
            ],
        },
    },
}


# ---------------------------------------------------------------------------
# Нормализация находок и скоринг
# ---------------------------------------------------------------------------
def normalize_finding(f: dict[str, Any]) -> dict[str, Any]:
    """Привести находку к единому виду (severity/category/confidence/source)."""
    sev = str(f.get("severity", "info")).strip().lower()
    if sev not in SEVERITIES:
        sev = "info"
    try:
        conf = float(f.get("confidence", 0.5))
    except (TypeError, ValueError):
        conf = 0.5
    conf = min(max(conf, 0.0), 1.0)
    return {
        "id": f.get("id") or f.get("check_id") or "",
        "category": str(f.get("category") or "").strip().lower(),
        "severity": sev,
        "confidence": conf,
        "source": f.get("source") or "",
        "step": f.get("step") or "",
        "engine": f.get("engine") or "",
        "evidence": f.get("evidence"),
    }


def score_findings(findings: list[dict[str, Any]], weights: dict[str, int] | None = None) -> float:
    """Агрегированный риск-скор 0..∞ (обычно 0..100+).

    Σ по находкам `weight(severity) × confidence`. Детерминировано и воспроизводимо.
    """
    w = weights or DEFAULT_WEIGHTS
    total = 0.0
    for raw in findings or []:
        f = normalize_finding(raw)
        total += float(w.get(f["severity"], 0)) * float(f["confidence"])
    return round(total, 4)


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    c = {s: 0 for s in SEVERITIES}
    for raw in findings or []:
        c[normalize_finding(raw)["severity"]] += 1
    return c


def category_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    c: dict[str, int] = {}
    for raw in findings or []:
        cat = normalize_finding(raw)["category"]
        if cat:
            c[cat] = c.get(cat, 0) + 1
    return c


# ---------------------------------------------------------------------------
# Компиляция DSL условий → структурированные предикаты (без eval)
# ---------------------------------------------------------------------------
_TOP_SPLIT = re.compile(r"\s+(and|or)\s+", re.I)


def _split_top(expr: str) -> list[str]:
    """Разбить выражение по верхнеуровневым and/or, учитывая скобки."""
    parts: list[str] = []
    depth = 0
    cur = ""
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth == 0:
            m = _TOP_SPLIT.match(expr, i)
            if m:
                parts.append(cur.strip())
                parts.append(m.group(1).lower())
                cur = ""
                i = m.end()
                continue
        cur += ch
        i += 1
    parts.append(cur.strip())
    return [p for p in parts if p]


def parse_condition(text: Any) -> dict[str, Any]:
    """Скомпилировать текстовое условие DSL в структурированный предикат.

    Поддерживаются формы из `Arch_v4/05`:
    ``any(critical)``, ``coverage < required``, ``score >= N``,
    ``safety_fail > N``, ``pass_rate < N``, ``count(<sev|category>) >= N``,
    а также ``A and B`` / ``A or B``. ``True``/``"true"`` — всегда истина.
    """
    if text is True:
        return {"always": True}
    if text is False or text is None:
        return {"always": False}
    s = str(text).strip()
    if s.lower() in ("true", "always", "1"):
        return {"always": True}
    if s.lower() in ("false", "never", "0"):
        return {"always": False}

    parts = _split_top(s)
    if len(parts) >= 3:
        op = "and"
        conds = []
        for p in parts:
            if p in ("and", "or"):
                op = p
            else:
                conds.append(parse_condition(p))
        # при смешении операторов берём первый как доминирующий (защита от неоднозначности)
        return {op: conds}

    m = re.fullmatch(r"any\(\s*(critical|high|medium|low|info)\s*\)", s, re.I)
    if m:
        return {"any_severity": m.group(1).lower()}

    if re.fullmatch(r"coverage\s*<\s*required", s, re.I):
        return {"coverage_lt_required": True}

    m = re.fullmatch(r"score\s*(>=|>|<=|<)\s*([0-9.]+)", s, re.I)
    if m:
        return {"score_cmp": [m.group(1), float(m.group(2))]}

    m = re.fullmatch(r"safety_fail\s*(>=|>|<=|<)\s*([0-9.]+)", s, re.I)
    if m:
        return {"safety_fail_cmp": [m.group(1), float(m.group(2))]}

    m = re.fullmatch(r"pass_rate\s*(>=|>|<=|<)\s*([0-9.]+)", s, re.I)
    if m:
        return {"pass_rate_cmp": [m.group(1), float(m.group(2))]}

    m = re.fullmatch(r"count\(\s*([a-zA-Z0-9_.-]+)\s*\)\s*(>=|>|<=|<)\s*([0-9]+)", s)
    if m:
        return {"count_cmp": [m.group(1).lower(), m.group(2), int(m.group(3))]}

    raise ValueError(f"не удалось разобрать условие политики: {text!r}")


def _cmp(a: float, op: str, b: float) -> bool:
    if op == ">=":
        return a >= b
    if op == ">":
        return a > b
    if op == "<=":
        return a <= b
    if op == "<":
        return a < b
    return False


def evaluate_condition(cond: dict[str, Any], ctx: dict[str, Any]) -> bool:
    if "always" in cond:
        return bool(cond["always"])
    if "and" in cond:
        return all(evaluate_condition(c, ctx) for c in cond["and"])
    if "or" in cond:
        return any(evaluate_condition(c, ctx) for c in cond["or"])
    if "not" in cond:
        return not evaluate_condition(cond["not"], ctx)
    if "any_severity" in cond:
        return ctx["sev_counts"].get(cond["any_severity"], 0) > 0
    if "coverage_lt_required" in cond:
        return not ctx["coverage_ok"]
    if "score_cmp" in cond:
        op, v = cond["score_cmp"]
        return _cmp(ctx["score"], op, v)
    if "safety_fail_cmp" in cond:
        op, v = cond["safety_fail_cmp"]
        return _cmp(ctx["safety_fail"], op, v)
    if "pass_rate_cmp" in cond:
        op, v = cond["pass_rate_cmp"]
        return _cmp(ctx["pass_rate"], op, v)
    if "count_cmp" in cond:
        key, op, n = cond["count_cmp"]
        cnt = ctx["sev_counts"].get(key)
        if cnt is None:
            cnt = ctx["cat_counts"].get(key, 0)
        return _cmp(cnt, op, n)
    return False


# ---------------------------------------------------------------------------
# Вердикт
# ---------------------------------------------------------------------------
def _coverage_ok(coverage: dict[str, Any] | None, required: dict[str, Any] | None) -> bool:
    """Полнота покрытия.

    Если требования не заданы или покрытие не передано — считаем «ok» (обратная совместимость
    с v3, где guardrail отсутствовал). Если переданы оба — все требуемые домены должны
    наблюдаться.
    """
    if not required:
        return True
    req_domains = set((required or {}).get("domains") or [])
    if not req_domains:
        return True
    if not coverage:
        return True  # покрытие не измерялось — не вводим ограничение
    doms = set(coverage.get("domains") or [])
    if not req_domains <= doms:
        return False
    gpu = coverage.get("gpu")
    if gpu == "none" and (required or {}).get("gpu") == "required":
        return False
    return True


def evaluate(findings: list[dict[str, Any]] | None = None, *,
             coverage: dict[str, Any] | None = None,
             results: dict[str, Any] | None = None,
             policy: dict[str, Any] | None = None,
             profile: str = "generic") -> dict[str, Any]:
    """Вычислить вердикт по политике. Возвращает dict с вердиктом, действием и обоснованием."""
    pol = policy or DEFAULT_POLICY
    prof = (pol.get("profiles") or {}).get(profile) or (pol.get("profiles") or {}).get("generic") or {}
    findings = findings or []
    results = results or {}

    weights = prof.get("weights") or DEFAULT_WEIGHTS
    score = score_findings(findings, weights)
    sev = severity_counts(findings)
    cat = category_counts(findings)
    cov_ok = _coverage_ok(coverage, prof.get("coverage_min"))

    try:
        safety_fail = float(results.get("safety_fail", 0) or 0)
    except (TypeError, ValueError):
        safety_fail = 0.0
    try:
        pass_rate = float(results.get("pass_rate", 1.0))
    except (TypeError, ValueError):
        pass_rate = 1.0

    ctx = {"score": score, "sev_counts": sev, "cat_counts": cat,
           "coverage_ok": cov_ok, "safety_fail": safety_fail, "pass_rate": pass_rate}

    verdict = "Inconclusive"
    matched = None
    reasons: list[str] = []
    for idx, rule in enumerate(prof.get("rules") or []):
        cond = rule.get("if")
        try:
            c = parse_condition(cond)
        except ValueError as exc:
            reasons.append(str(exc))
            continue
        if evaluate_condition(c, ctx):
            verdict = rule.get("then", "Inconclusive")
            matched = idx
            reasons.append(f"rule#{idx}: {cond!r} -> {verdict}")
            break
    else:
        reasons.append("нет совпавших правил -> Inconclusive")

    # Guardrail: нельзя выдать Safe при недостаточном покрытии.
    if verdict == "Safe" and not cov_ok:
        verdict = "Inconclusive"
        reasons.append("guardrail: coverage < required => Inconclusive")

    if verdict not in VERDICTS:
        verdict = "Inconclusive"
        reasons.append(f"неизвестный вердикт {verdict!r} -> Inconclusive")

    actions = pol.get("actions") or DEFAULT_ACTIONS
    return {
        "verdict": verdict,
        "action": actions.get(verdict, "quarantine"),
        "score": score,
        "coverage_ok": cov_ok,
        "safety_fail": safety_fail,
        "pass_rate": pass_rate,
        "severity_counts": sev,
        "matched_rule": matched,
        "reasons": reasons,
        "policy": {"id": pol.get("id", ""), "version": pol.get("version", 0), "profile": profile},
    }


def parse_text_dsl(policy: dict[str, Any]) -> dict[str, Any]:
    """Проверить компилируемость всех правил политики (fail-fast при публикации)."""
    for pname, prof in (policy.get("profiles") or {}).items():
        for idx, rule in enumerate(prof.get("rules") or []):
            try:
                parse_condition(rule.get("if"))
            except ValueError as exc:
                raise ValueError(f"profile {pname} rule#{idx}: {exc}") from exc
    return policy
