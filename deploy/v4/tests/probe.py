#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: in-job probe — исполняет TestPack против движка и постит результат в `/llm/score`.

Заменяет ad-hoc `_PROBE_SRC`: использует общие модули v4 (`runner`, `datasets`, `engine_client`),
то есть в песочнице исполняется тот же раннер, что и в тестах. Режимы:
  * `TESTPACK_URL` — материализованный пакет `{testpack, steps, cases}` (основной путь);
  * `PROMPTS_URL` / `PROMPTS_FILE` / `PROMPTS_JSON` — обратная совместимость.

Только stdlib. Возвращает код выхода: 0 — успех, 4 — не получено ни одного ответа.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, "/opt/v4")

from tests import datasets as ds        # noqa: E402
from tests import runner as runner      # noqa: E402
from tests.engine_client import EngineClient  # noqa: E402

_OP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _load_cases() -> tuple[list, dict]:
    """Вернуть (cases, envelope|{}). Приоритет — материализованный пакет."""
    tu = os.environ.get("TESTPACK_URL", "")
    if tu:
        env = json.loads(_OP.open(tu, timeout=60).read())
        return list(env.get("cases") or []), env
    pu = os.environ.get("PROMPTS_URL", "")
    pf = os.environ.get("PROMPTS_FILE", "")
    if pu:
        return list(json.loads(_OP.open(pu, timeout=60).read()).get("cases") or []), {}
    if pf:
        return list(json.load(open(pf)).get("cases") or []), {}
    return list(json.loads(os.environ.get("PROMPTS_JSON", "{}")).get("cases") or []), {}


def build_plan(cases: list, envelope: dict, max_tokens: int) -> dict:
    """Построить TestPack для раннера (load + invoke + assert) из данных прогона."""
    tp = (envelope or {}).get("testpack") or {}
    return {"id": tp.get("id") or "probe", "version": int(tp.get("version") or 1),
            "applies_to": {}, "observation": {"require": []}, "budgets": {},
            "datasets": [{"id": "active", "ref": "ds://prompts/active@1"}],
            "steps": [{"type": "load"},
                      {"type": "invoke", "dataset": "active", "params": {"max_tokens": int(max_tokens)}},
                      {"type": "assert", "over": ["responses"]}]}


def build_score_payload(cases: list, result: dict, envelope: dict, dt: float) -> dict:
    """Собрать тело для `/llm/score` (совместимо с текущим контрактом)."""
    responses = {}
    toks = int((result.get("budgets_used") or {}).get("tokens", 0) or 0)
    for r in result.get("responses", []) or []:
        responses[str(r.get("id"))] = [r.get("text", "")]
    tp = (envelope or {}).get("testpack")
    return {"version": os.environ.get("PROMPT_SET", ""), "scan_id": os.environ.get("SCAN_ID", ""),
            "bundle_id": os.environ.get("BUNDLE_ID", ""), "engine_image": os.environ.get("ENGINE_IMAGE", ""),
            "testpack": tp,
            "metrics": {"questions": len(cases), "completion_tokens": toks, "secs": round(dt, 1)},
            "responses": responses}


def main() -> int:
    cases, envelope = _load_cases()
    eng = EngineClient()
    if not eng.health():
        print("ENGINE_NOT_READY", flush=True)
        return 4
    repo = ds.DatasetRepo()
    repo.register("ds://prompts/active@1", cases)
    pack = build_plan(cases, envelope, int(os.environ.get("MAX_TOKENS", "256")))
    t0 = time.monotonic()
    res = runner.run_pack(pack, eng, repo)
    dt = time.monotonic() - t0
    answered = sum(1 for r in (res.get("responses") or []) if (r.get("text") or "").strip())
    for r in res.get("responses") or []:
        print("Q", r.get("id"), "->", (r.get("text") or "")[:60].replace("\n", " "), flush=True)
    if not answered:
        print("LLM_NO_ANSWERS", flush=True)
        return 4
    print(f"LLM_TIMING questions={len(cases)} completion_tokens="
          f"{(res.get('budgets_used') or {}).get('tokens', 0)} secs={dt:.1f}", flush=True)
    payload = build_score_payload(cases, res, envelope, dt)
    req = urllib.request.Request(os.environ["TESTING_URL"] + "/llm/score",
                                 data=json.dumps(payload).encode(), method="POST",
                                 headers={"Authorization": "Bearer " + os.environ.get("MLSCAN_KEY", ""),
                                          "Content-Type": "application/json"})
    print("SCORE", _OP.open(req, timeout=120).read().decode(), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
