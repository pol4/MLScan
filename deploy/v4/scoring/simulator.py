#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: симулятор/бэктест политики вердикта — инструмент управления критериями.

Позволяет **до публикации** прогнать политику на исторических кейсах (findings/coverage/results)
или на кейсах с эталонной меткой и получить: матрицу ошибок (TP/FP/TN/FN), долю `Inconclusive`,
«пропуски» (FN — опасное, а вердикт `Safe`), а также **sweep порога** (как меняется качество при
изменении порога). Всё детерминировано; без побочных эффектов.
"""
from __future__ import annotations

import copy
from typing import Any, Callable, Iterable

from . import policy as _policy

UNSAFE = {"Malicious", "Needs review"}
SAFE = {"Safe"}


def _label(case: dict[str, Any]) -> str | None:
    """Эталонная метка кейса: `safe` | `unsafe` | None (если не задана)."""
    lab = case.get("label")
    if lab in ("safe", "unsafe"):
        return lab
    exp = case.get("expected")
    if isinstance(exp, str):
        if exp in UNSAFE:
            return "unsafe"
        if exp in SAFE:
            return "safe"
    return None


def _classify(verdict: str) -> str:
    if verdict in UNSAFE:
        return "unsafe"
    if verdict in SAFE:
        return "safe"
    return "inconclusive"


def simulate(policy: dict[str, Any] | None, cases: Iterable[dict[str, Any]], *,
             default_profile: str = "generic") -> dict[str, Any]:
    """Прогнать политику по кейсам.

    Каждый кейс: ``{"id"?, "profile"?, "findings"?, "coverage"?, "results"?, "label"|"expected"?}``.
    Возвращает ``{"results": [...], "summary": {...}, "missed": [...]}``.
    """
    pol = policy or _policy.DEFAULT_POLICY
    rows: list[dict[str, Any]] = []
    tp = fp = tn = fn = inc = 0
    missed: list[dict[str, Any]] = []

    for case in cases or []:
        prof = case.get("profile") or default_profile
        v = _policy.evaluate(case.get("findings") or [], coverage=case.get("coverage"),
                             results=case.get("results") or {}, policy=pol, profile=prof)
        pred = v["verdict"]
        pred_class = _classify(pred)
        exp = _label(case)
        match = None
        if exp is not None:
            if pred_class == "inconclusive":
                inc += 1
                match = False
            elif exp == "unsafe" and pred_class == "unsafe":
                tp += 1; match = True
            elif exp == "unsafe" and pred_class == "safe":
                fn += 1; match = False
                missed.append({"id": case.get("id"), "expected": exp, "predicted": pred,
                               "score": v["score"]})
            elif exp == "safe" and pred_class == "safe":
                tn += 1; match = True
            elif exp == "safe" and pred_class == "unsafe":
                fp += 1; match = False
        rows.append({"id": case.get("id"), "profile": prof, "expected": exp,
                     "predicted": pred, "action": v["action"], "score": v["score"],
                     "coverage_ok": v["coverage_ok"], "match": match})

    labeled = tp + fp + tn + fn
    summary = {
        "cases": len(rows), "labeled": labeled,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "inconclusive": inc,
        "accuracy": round((tp + tn) / labeled, 4) if labeled else None,
        "false_negative_rate": round(fn / (fn + tp), 4) if (fn + tp) else None,
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else None,
    }
    return {"results": rows, "summary": summary, "missed": missed}


def set_path(policy: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    """Установить значение по пути вида ``profiles.llm.rules.2.if`` (копия политики)."""
    p = copy.deepcopy(policy)
    cur: Any = p
    keys = path.split(".")
    for k in keys[:-1]:
        cur = cur[int(k)] if isinstance(cur, list) else cur[k]
    last = keys[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value
    return p


def score_threshold_setter(profile: str, rule_index: int, *, op: str = ">=") -> Callable[[dict, Any], None]:
    """Сеттер для sweep: меняет порог `score` в правиле ``profiles.<profile>.rules[i].if``."""
    def _set(pol: dict[str, Any], value: Any) -> None:
        pol["profiles"][profile]["rules"][rule_index]["if"] = f"score {op} {value}"
    return _set


def sweep(policy: dict[str, Any], cases: Iterable[dict[str, Any]], values: Iterable[Any], *,
          mutate: Callable[[dict[str, Any], Any], None], default_profile: str = "generic") -> list[dict[str, Any]]:
    """Прогнать политику для набора значений (например, порогов) и вернуть сводки.

    ``mutate(policy_copy, value)`` должен изменить политику. Возвращает список
    ``{"value", **summary}`` — точка для графика/выбора порога.
    """
    cases = list(cases or [])
    out: list[dict[str, Any]] = []
    for val in values:
        p = copy.deepcopy(policy)
        mutate(p, val)
        s = simulate(p, cases, default_profile=default_profile)["summary"]
        out.append({"value": val, **s})
    return out
