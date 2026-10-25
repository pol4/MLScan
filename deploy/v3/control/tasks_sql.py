#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Персистентная очередь сканов в PostgreSQL (v3, P2).

Таблица `tasks`: приоритет (rank), порядок (seq), статус. Выборка следующей задачи — по
(rank, seq) с `FOR UPDATE SKIP LOCKED` (безопасно для нескольких воркеров/orchestrator'ов).
"""
from __future__ import annotations


def _lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


DDL_TASKS = """
CREATE TABLE IF NOT EXISTS tasks (
  task_id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  priority TEXT NOT NULL,
  rank INT NOT NULL,
  seq BIGSERIAL,
  payload TEXT,
  status TEXT NOT NULL DEFAULT 'queued',
  created TIMESTAMPTZ DEFAULT now(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_dequeue ON tasks(status, rank, seq);
""".strip()


def enqueue_sql(task_id: str, tenant: str, priority: str, rank: int, payload: str = "{}") -> str:
    return ("INSERT INTO tasks(task_id,tenant,priority,rank,payload,status) VALUES "
            f"({_lit(task_id)},{_lit(tenant)},{_lit(priority)},{int(rank)},{_lit(payload)},'queued') "
            "ON CONFLICT (task_id) DO NOTHING")


def dequeue_sql() -> str:
    return ("UPDATE tasks SET status='running', started_at=now() WHERE task_id = ("
            "SELECT task_id FROM tasks WHERE status='queued' ORDER BY rank, seq "
            "FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING task_id, tenant, priority, payload")


def complete_sql(task_id: str, ok: bool = True, error: str = "") -> str:
    status = "done" if ok else "failed"
    return ("UPDATE tasks SET status=" + _lit(status) + ", finished_at=now(), error=" + _lit(error) +
            " WHERE task_id=" + _lit(task_id))


def requeue_sql(task_id: str) -> str:
    return ("UPDATE tasks SET status='queued', started_at=NULL WHERE task_id=" + _lit(task_id))


def queue_depth_sql() -> str:
    return "SELECT COALESCE(count(*),0) FROM tasks WHERE status='queued'"
