#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: клиент движка (OpenAI-совместимый) для раннера в песочнице.

Реализует узкий интерфейс, ожидаемый `tests.runner` (health/load/invoke), поверх HTTP к
локальному движку (`ENGINE_URL`, по умолчанию `http://127.0.0.1:8000`). Только stdlib.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Any


class EngineClient:
    def __init__(self, base: str | None = None, *, model: str = "m", timeout: int = 180,
                 wait_s: int | None = None):
        self.base = (base or os.environ.get("ENGINE_URL", "http://127.0.0.1:8000")).rstrip("/")
        self.model = model
        self.timeout = int(timeout)
        self.wait_s = int(wait_s if wait_s is not None else os.environ.get("ENGINE_WAIT", "180"))
        self._op = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _v1(self, path: str) -> str:
        return self.base + "/v1" + path

    def health(self, tries: int | None = None) -> bool:
        n = int(tries if tries is not None else max(1, self.wait_s // 2))
        for _ in range(n):
            try:
                with self._op.open(self._v1("/models"), timeout=3):
                    return True
            except Exception:  # noqa: BLE001
                time.sleep(2)
        return False

    def manifest(self) -> dict[str, Any]:
        return {"protocols": ["openai-http"], "streaming": False, "type": "llm"}

    def load(self) -> str:
        return "ready" if self.health() else "not-ready"

    def invoke(self, req: dict[str, Any]) -> dict[str, Any]:
        params = req.get("params") or {}
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": req.get("prompt", "")}],
            "temperature": 0,
            "max_tokens": int(params.get("max_tokens", 256)),
        }).encode()
        r = urllib.request.Request(self._v1("/chat/completions"), data=body, method="POST",
                                   headers={"Content-Type": "application/json"})
        with self._op.open(r, timeout=self.timeout) as resp:
            d = json.loads(resp.read())
        return {"text": (d.get("choices", [{}])[0].get("message") or {}).get("content", ""),
                "usage": d.get("usage") or {}}
