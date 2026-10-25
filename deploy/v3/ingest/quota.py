#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Квоты и fair-share ingest (v3, P1).

Чистые функции без внешних зависимостей: проверяют допустимость загрузки по квотам тенанта,
диапазон размера части и решение о throttling по суточному лимиту. Fair-share — равные веса
активных тенантов (расширяемо весами/приоритетами).
"""
from __future__ import annotations

from dataclasses import dataclass

MiB = 1024 * 1024

OK = "ok"
DENY_TOO_LARGE = "object_too_large"
DENY_DAILY = "daily_quota_exceeded"
DENY_CONCURRENT = "too_many_uploads"
DENY_PART = "part_size_out_of_range"


@dataclass(frozen=True)
class Quota:
    max_bytes_per_day: int = 0            # 0 = без лимита
    max_object_bytes: int = 0            # 0 = без лимита
    max_concurrent_uploads: int = 8
    rps: int = 30
    min_part_size: int = 5 * MiB         # минимум S3 для части multipart
    max_part_size: int = 1024 * MiB      # P1: до 1 ГиБ


def check_upload(quota: Quota, *, size: int, used_bytes_today: int = 0,
                 concurrent_uploads: int = 0) -> tuple[bool, str]:
    """Проверить загрузку объекта размером `size`. Возвращает (ok, code)."""
    if size <= 0:
        return False, DENY_TOO_LARGE
    if quota.max_object_bytes and size > quota.max_object_bytes:
        return False, DENY_TOO_LARGE
    if quota.max_bytes_per_day and used_bytes_today + size > quota.max_bytes_per_day:
        return False, DENY_DAILY
    if quota.max_concurrent_uploads and concurrent_uploads >= quota.max_concurrent_uploads:
        return False, DENY_CONCURRENT
    return True, OK


def check_part_size(quota: Quota, part_size: int) -> tuple[bool, str]:
    if part_size < quota.min_part_size or part_size > quota.max_part_size:
        return False, DENY_PART
    return True, OK


def throttle_decision(quota: Quota, used_bytes_today: int) -> str:
    """Решение по throttling: ok | throttle (>=90%) | deny (>=100%)."""
    if not quota.max_bytes_per_day:
        return "ok"
    ratio = used_bytes_today / quota.max_bytes_per_day
    if ratio >= 1.0:
        return "deny"
    if ratio >= 0.9:
        return "throttle"
    return "ok"


def fair_share(tenants_active: list[str], weights: dict[str, float] | None = None) -> dict[str, float]:
    """Доли пропускной между активными тенантами (по умолчанию равные)."""
    tenants = [t for t in tenants_active if t]
    if not tenants:
        return {}
    w = weights or {}
    total = sum(w.get(t, 1.0) for t in tenants)
    return {t: round(w.get(t, 1.0) / total, 6) for t in tenants}
