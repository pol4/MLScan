#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: EngineDescriptor — описание движка инференса как данных.

Движок (загрузчик/анализатор/рантайм/LLM-сервер) описывается записью: образ по digest, тип,
совместимые виды артефактов, возможности (protocols/capabilities), runtime (start/readiness/
resources), integrity (signed/sbom). Планировщик RuntimeClass выбирает **профиль Kata**
(`kata-gpu` / `kata-btf` / `kata`) либо **отклоняет** Job — хост-исполнение
(`runtimeClassName=nvidia`) не допускается (инвариант v4).

Только стандартная библиотека. Модуль без побочных эффектов (легко покрывается unit-тестами).
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Iterable

# Тип движка: чем он «поднимает» артефакт.
KINDS = ("loader", "analyzer", "runtime", "llm")

# Профили Kata, допустимые для job'ов проверки артефактов.
KATA_CLASSES = ("kata", "kata-btf", "kata-gpu")
# Профили, где недоверенный код попадает на хост-ядро. Запрещены для проверки артефактов.
HOST_FORBIDDEN_CLASSES = ("nvidia", "runc")

# Возможные виды артефактов (для совместимости). Список открытый (строки).
KNOWN_ARTIFACT_KINDS = (
    "pickle", "torch", "numpy", "safetensors", "onnx", "hdf5", "keras", "gguf",
    "llm-gguf", "llm-safetensors", "tflite", "openvino", "tensorrt", "coreml",
    "archive", "dataset", "script", "notebook", "config", "native-lib",
)


@dataclass
class EngineDescriptor:
    """Описание движка. Поля — данные; поведение платформы выводится из них."""

    id: str
    oci: str
    kind: str
    artifact_kinds: list[str] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)
    runtime: dict[str, Any] = field(default_factory=dict)
    integrity: dict[str, Any] = field(default_factory=dict)
    version: int = 1

    # ---- валидация -------------------------------------------------------
    def validate(self) -> list[str]:
        """Вернуть список проблем (пусто — валидно). Ничего не бросает."""
        errs: list[str] = []
        if not self.id:
            errs.append("id is required")
        if not self.oci:
            errs.append("oci is required")
        elif "@sha256:" not in self.oci:
            errs.append("oci must be pinned by digest (…@sha256:…)")
        if self.kind not in KINDS:
            errs.append(f"kind must be one of {KINDS}, got {self.kind!r}")
        if not isinstance(self.artifact_kinds, list) or not self.artifact_kinds:
            errs.append("artifact_kinds must be a non-empty list")
        for k in self.artifact_kinds or []:
            if not isinstance(k, str) or not k:
                errs.append(f"artifact_kinds contains invalid entry: {k!r}")
        caps = self.capabilities or {}
        if caps:
            protos = caps.get("protocols")
            if protos is not None and not isinstance(protos, list):
                errs.append("capabilities.protocols must be a list")
        rt = self.runtime or {}
        if "readiness" in rt and not isinstance(rt["readiness"], dict):
            errs.append("runtime.readiness must be an object")
        res = rt.get("resources")
        if res is not None and not isinstance(res, dict):
            errs.append("runtime.resources must be an object")
        return errs

    def is_valid(self) -> bool:
        return not self.validate()

    # ---- возможности -----------------------------------------------------
    def needs_gpu(self) -> bool:
        return bool((self.capabilities or {}).get("gpu"))

    def protocols(self) -> list[str]:
        return list((self.capabilities or {}).get("protocols") or [])

    def resource_profile(self) -> dict[str, Any]:
        return dict((self.runtime or {}).get("resources") or {})

    def compatible(self, artifact_kind: str) -> bool:
        """Совместим ли движок с видом артефакта.

        Точное совпадение, а также «семейство» (llm-* ↔ llm-движок, runtime-форматы ↔ runtime).
        """
        ak = (artifact_kind or "").strip().lower()
        if not ak:
            return False
        kinds = {k.lower() for k in (self.artifact_kinds or [])}
        if ak in kinds:
            return True
        if self.kind == "llm" and ak.startswith("llm-"):
            return True
        if self.kind == "llm" and ak in ("gguf", "safetensors"):
            return True
        if self.kind == "runtime" and ak in ("onnx", "tflite", "openvino", "tensorrt", "coreml"):
            return True
        return False

    # ---- сериализация ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EngineDescriptor":
        return cls(
            id=d.get("id", ""),
            oci=d.get("oci", ""),
            kind=d.get("kind", ""),
            artifact_kinds=list(d.get("artifact_kinds") or []),
            capabilities=dict(d.get("capabilities") or {}),
            runtime=dict(d.get("runtime") or {}),
            integrity=dict(d.get("integrity") or {}),
            version=int(d.get("version", 1)),
        )

    @classmethod
    def from_registry_row(cls, row: Any) -> "EngineDescriptor":
        """Минимальный дескриптор из записи реестра образов (`registry_images`).

        Принимает кортеж/список `(digest, ref[, source, type])` или dict с ключами
        `digest`/`ref`/`type`. Служит мостом v3→v4: существующие движки становятся данными.
        """
        if isinstance(row, dict):
            digest = row.get("digest", "")
            ref = row.get("ref", "")
            source = row.get("source", "")
            rtype = row.get("type", "")
        else:
            digest = row[0] if len(row) > 0 else ""
            ref = row[1] if len(row) > 1 else ""
            source = row[2] if len(row) > 2 else ""
            rtype = row[3] if len(row) > 3 else ""
        ref_l = f"{ref} {rtype}".lower()
        kind = "llm" if ("llm" in rtype.lower() or "vllm" in ref_l or "sglang" in ref_l
                         or "llama" in ref_l) else (
            "analyzer" if "analy" in ref_l else (
                "runtime" if any(x in ref_l for x in ("onnx", "openvino", "tensorrt", "tflite"))
                else "loader"))
        if source == "builtin":
            kind = "loader"
        ak = {
            "llm": ["llm-gguf", "llm-safetensors"],
            "runtime": ["onnx", "tflite", "openvino", "tensorrt"],
            "analyzer": ["safetensors", "onnx", "hdf5", "gguf", "archive"],
            "loader": ["pickle", "torch", "numpy", "safetensors", "archive", "dataset"],
        }[kind]
        return cls(
            id=(ref or digest),
            oci=(f"{ref}@{digest}" if ref and "@" not in ref else (digest or ref)),
            kind=kind,
            artifact_kinds=ak,
            capabilities={"gpu": kind == "llm", "protocols": ["raw-http"] if kind != "loader" else []},
            runtime={},
            integrity={"signed": False, "sbom": False},
        )


def plan_runtime_class(desc: EngineDescriptor, *, available: Iterable[str] | None = None,
                       gpu_available: bool = False, allow_cpu_fallback: bool = True) -> dict[str, Any]:
    """Выбрать RuntimeClass для job'а по дескриптору (без хост-профилей).

    Возвращает ``{"runtime_class", "degraded", "reason"}`` либо бросает ``RuntimeError``,
    если безопасно запустить нельзя (движку нужен GPU, а `kata-gpu` недоступен и CPU-режим
    не допускается). Инвариант: результат всегда из ``KATA_CLASSES``.
    """
    avail = set(available or KATA_CLASSES)
    # хотим самый «наблюдаемый» доступный Kata-профиль по умолчанию
    def pick(candidates: list[str]) -> str | None:
        for c in candidates:
            if c in avail:
                return c
        return None

    if not desc.needs_gpu():
        cls = pick(["kata-btf", "kata"])
        if not cls:
            raise RuntimeError("нет доступного Kata-профиля (kata/kata-btf)")
        return {"runtime_class": cls, "degraded": False, "reason": "cpu/inert artifact"}

    # движку нужен GPU
    if "kata-gpu" in avail and gpu_available:
        return {"runtime_class": "kata-gpu", "degraded": False, "reason": "gpu-in-kata"}
    if allow_cpu_fallback:
        cls = pick(["kata-btf", "kata"])
        if cls:
            return {"runtime_class": cls, "degraded": True,
                    "reason": "gpu required but kata-gpu unavailable: cpu-in-kata (limited coverage)"}
    raise RuntimeError("движку нужен GPU, а kata-gpu недоступен: отказ (host-fallback запрещён)")


def runtime_class_is_safe(runtime_class: str) -> bool:
    """Разрешён ли RuntimeClass для job'ов проверки артефактов (инвариант v4)."""
    rc = (runtime_class or "").strip().lower()
    if rc in HOST_FORBIDDEN_CLASSES:
        return False
    return rc in KATA_CLASSES
