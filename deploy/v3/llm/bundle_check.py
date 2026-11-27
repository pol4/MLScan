#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Предполётная проверка bundle (v3/v4): достаточно ли артефакта для выбранного движка.

Чистая логика без БД/сети — используется сервисом (fail-fast до создания job'а) и тестами.
Совместимость архитектуры модели с версией движка проверяется самим движком при загрузке
(ошибка прогона видна в UI); здесь ловятся заведомо неисправные bundle.
"""
from __future__ import annotations

WEIGHT_EXT = (".safetensors", ".bin", ".pt", ".onnx", ".gguf")


def engine_is_dir(engine: str) -> bool:
    """vLLM/SGLang грузят каталог модели, а не одиночный файл."""
    e = (engine or "").lower()
    return ("vllm" in e) or ("sglang" in e)


def preflight_manifest(engine: str, sha: str, *, engine_ok: bool, key: str,
                       meta: dict | None) -> tuple[list[str], dict]:
    """Вернуть ``(reasons, info)``: причины отказа и собранные факты о манифесте."""
    meta = meta or {}
    info = {"dir": False, "files": 0, "has_config": False, "has_weights": False,
            "engine_is_dir": engine_is_dir(engine)}
    reasons: list[str] = []
    if not sha:
        reasons.append("не задан model_sha256")
    elif not engine_ok:
        reasons.append("движок не найден в registry_images")
    elif not key:
        reasons.append("артефакт модели не найден в хранилище")
    else:
        names = [str(f.get("name") if isinstance(f, dict) else f) for f in (meta.get("files") or [])]
        low = [n.lower() for n in names]
        info.update(dir=bool(meta.get("dir")), files=len(low),
                    has_config=any(n.endswith("config.json") for n in low),
                    has_weights=any(n.endswith(WEIGHT_EXT) for n in low))
        if info["engine_is_dir"] and info["dir"] and low:
            if not info["has_config"]:
                reasons.append("в каталоге модели нет config.json")
            if not info["has_weights"]:
                reasons.append("в каталоге модели нет весовых файлов (*.safetensors/*.bin)")
    return reasons, info
