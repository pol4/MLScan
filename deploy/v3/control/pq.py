#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Персистентная очередь сканов с приоритетами (v3, P2; модуль pq, чтобы не конфликтовать со stdlib queue).

Приоритеты: CI (наивысший) > interactive > batch. Внутри класса — FIFO. Очередь
сериализуема (`snapshot()`/`restore()`) для хранения в БД и восстановления после рестарта.
"""
from __future__ import annotations

import heapq
import itertools
import time
import uuid
from dataclasses import dataclass, field, asdict

CLASS_CI = "ci"
CLASS_INTERACTIVE = "interactive"
CLASS_BATCH = "batch"
RANK = {CLASS_CI: 0, CLASS_INTERACTIVE: 1, CLASS_BATCH: 2}
VALID_CLASSES = set(RANK)


@dataclass(order=False)
class Task:
    task_id: str
    tenant: str
    priority: str = CLASS_INTERACTIVE
    payload: dict = field(default_factory=dict)
    created: float = field(default_factory=time.time)
    seq: int = 0

    def to_record(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_record(rec: dict) -> "Task":
        return Task(task_id=rec["task_id"], tenant=rec.get("tenant", ""),
                    priority=rec.get("priority", CLASS_INTERACTIVE),
                    payload=rec.get("payload") or {}, created=float(rec.get("created") or 0.0),
                    seq=int(rec.get("seq") or 0))


class PriorityQueue:
    """Min-heap по (rank, seq). Не потокобезопасна — обёртывается локами выше."""

    def __init__(self) -> None:
        self._heap: list[tuple[int, int, Task]] = []
        self._counter = itertools.count()

    @staticmethod
    def _rank(priority: str) -> int:
        return RANK.get(priority, RANK[CLASS_INTERACTIVE])

    def push(self, tenant: str, priority: str = CLASS_INTERACTIVE, payload: dict | None = None,
             task_id: str | None = None) -> Task:
        if priority not in VALID_CLASSES:
            raise ValueError(f"unknown priority: {priority}")
        seq = next(self._counter)
        t = Task(task_id=task_id or uuid.uuid4().hex, tenant=tenant, priority=priority,
                 payload=payload or {}, seq=seq)
        heapq.heappush(self._heap, (self._rank(priority), seq, t))
        return t

    def pop(self) -> Task | None:
        while self._heap:
            _, _, t = heapq.heappop(self._heap)
            return t
        return None

    def peek(self) -> Task | None:
        return self._heap[0][2] if self._heap else None

    def size(self) -> int:
        return len(self._heap)

    def snapshot(self) -> list[dict]:
        return [t.to_record() for _, _, t in sorted(self._heap)]

    def restore(self, records: list[dict]) -> None:
        self._heap.clear()
        self._counter = itertools.count(max([r.get("seq", 0) for r in records], default=0) + 1)
        for rec in sorted(records, key=lambda r: (self._rank(r.get("priority", "")), r.get("seq", 0))):
            t = Task.from_record(rec)
            heapq.heappush(self._heap, (self._rank(t.priority), t.seq, t))
