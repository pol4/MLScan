#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Классификатор LLM-моделей (v3, L0).

По манифесту модели (имена файлов, config.json, gguf-метаданные, размер) определяет, является ли
артефакт LLM, семью, уверенность, доказательства и рекомендованные движки/ресурсы. Служит для
авто-предложения binding «модель↔образ движка» (см. `binding.py`); ручное указание всегда доступно.
"""
from __future__ import annotations

ARCH_TO_FAMILY = {
    "llamaforcausallm": "llama", "llamamodel": "llama",
    "qwen2forcausallm": "qwen2", "qwen2model": "qwen2", "qwen2moe": "qwen2",
    "mistralforcausallm": "mistral", "mixtralforcausallm": "mixtral",
    "gpt2lmheadmodel": "gpt2", "gptjlmheadmodel": "gptj",
    "gemmaforcausallm": "gemma", "phiforcausallm": "phi",
    "falconforcausallm": "falcon", "optforcausallm": "opt",
}
TYPE_TO_FAMILY = {
    "llama": "llama", "qwen2": "qwen2", "qwen2_moe": "qwen2", "mistral": "mistral",
    "mixtral": "mixtral", "gpt2": "gpt2", "gptj": "gptj", "gemma": "gemma",
    "gemma2": "gemma", "phi": "phi", "phi3": "phi", "falcon": "falcon", "opt": "opt",
}
TOKENIZER_FILES = ("tokenizer.json", "tokenizer.model", "tokenizer_config.json",
                   "vocab.json", "merges.txt", "spiece.model")
INDEX_SUFFIXES = (".safetensors.index.json", ".bin.index.json")
ENGINES_BY_FAMILY = {
    "llama": ["vllm", "tgi", "llama.cpp"], "qwen2": ["vllm", "tgi"],
    "mistral": ["vllm", "tgi"], "mixtral": ["vllm", "tgi"],
    "gemma": ["vllm", "tgi"], "phi": ["vllm", "llama.cpp"],
    "gpt2": ["tgi", "llama.cpp"], "gptj": ["tgi"], "falcon": ["tgi"], "opt": ["tgi"],
}


def _estimate_resources(size_bytes: int | None) -> dict:
    if not size_bytes or size_bytes <= 0:
        return {}
    gb = size_bytes / (1024 ** 3)
    return {"gpu": 1, "disk_gb": int(gb * 1.2) + 1, "ram_gb": int(gb * 1.5) + 2}


def classify(*, filenames=None, config=None, gguf_meta=None, size_bytes=None) -> dict:
    files = [str(f) for f in (filenames or [])]
    lower = [f.lower() for f in files]
    conf = 0.0
    evidence: list[str] = []
    family = ""

    cfg = config or {}
    if isinstance(cfg, dict) and cfg:
        mt = str(cfg.get("model_type", "")).lower()
        if mt in TYPE_TO_FAMILY:
            family = TYPE_TO_FAMILY[mt]
            conf += 0.5
            evidence.append(f"config.model_type={mt}")
        for a in (cfg.get("architectures") or []):
            fam = ARCH_TO_FAMILY.get(str(a).lower())
            if fam:
                family = family or fam
                conf += 0.3
                evidence.append(f"architectures={a}")
                break

    gm = gguf_meta or {}
    if isinstance(gm, dict) and gm:
        arch = str(gm.get("general.architecture", "")).lower()
        fam = TYPE_TO_FAMILY.get(arch) or ARCH_TO_FAMILY.get(arch)
        if fam:
            family = family or fam
            conf += 0.6
            evidence.append(f"gguf.general.architecture={arch}")

    if any(os_base.startswith("tokenizer") or os_base in TOKENIZER_FILES for os_base in
           [f.split("/")[-1] for f in lower]):
        conf += 0.25
        evidence.append("tokenizer files present")
    if any(f.endswith(INDEX_SUFFIXES) for f in lower):
        conf += 0.15
        evidence.append("sharded index present")

    conf = round(min(conf, 0.99), 2)
    is_llm = conf >= 0.5 and bool(family)
    return {
        "is_llm": is_llm,
        "family": family if is_llm else "",
        "confidence": conf,
        "evidence": evidence,
        "suggested_engines": ENGINES_BY_FAMILY.get(family, ["vllm", "tgi"]) if is_llm else [],
        "recommended_resources": _estimate_resources(size_bytes) if is_llm else {},
    }
