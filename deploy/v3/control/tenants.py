#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Реестр тенантов (v3, P2): идентичность субъекта → тенант с квотами и приоритетом.

Тенант — first-class сущность: свои квоты (см. `../ingest/quota.py`), приоритет класса и признак
включённости. Если квота для тенанта не задана — используется дефолт.
"""
from __future__ import annotations

from dataclasses import dataclass, field

try:  # модуль квот доступен в том же образе/каталоге v3
    from quota import Quota  # type: ignore
except Exception:  # noqa: BLE001
    Quota = None  # type: ignore

from pq import CLASS_INTERACTIVE, VALID_CLASSES  # type: ignore


@dataclass
class Tenant:
    tenant_id: str
    quota: object = None                 # Quota или None (дефолт)
    priority: str = CLASS_INTERACTIVE
    enabled: bool = True
    labels: dict = field(default_factory=dict)


class TenantRegistry:
    def __init__(self, default_quota=None, default_priority: str = CLASS_INTERACTIVE) -> None:
        self._tenants: dict[str, Tenant] = {}
        self._default_quota = default_quota
        self._default_priority = default_priority

    def upsert(self, tenant: Tenant) -> None:
        if tenant.priority not in VALID_CLASSES:
            raise ValueError(f"unknown priority: {tenant.priority}")
        self._tenants[tenant.tenant_id] = tenant

    def resolve(self, subject: str) -> Tenant:
        t = self._tenants.get(subject)
        if t is not None:
            return t
        return Tenant(tenant_id=subject or "shared", quota=self._default_quota,
                      priority=self._default_priority)

    def quota_for(self, subject: str):
        t = self.resolve(subject)
        return t.quota if t.quota is not None else self._default_quota

    def is_enabled(self, subject: str) -> bool:
        return self.resolve(subject).enabled

    def all(self) -> list[Tenant]:
        return list(self._tenants.values())
