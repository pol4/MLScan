#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P2: unit-тесты control plane — приоритетная очередь (pq), версии/подпись политик, тенанты."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "control"))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "ingest"))

import pq  # noqa: E402
import policy  # noqa: E402
import tenants  # noqa: E402
import quota  # noqa: E402
import tasks_sql  # noqa: E402
import orchestrator  # noqa: E402


class QueueTest(unittest.TestCase):
    def test_priority_order(self):
        q = pq.PriorityQueue()
        q.push("t", pq.CLASS_BATCH, {"n": "b1"})
        q.push("t", pq.CLASS_CI, {"n": "ci1"})
        q.push("t", pq.CLASS_INTERACTIVE, {"n": "i1"})
        q.push("t", pq.CLASS_CI, {"n": "ci2"})
        order = [q.pop().payload["n"] for _ in range(4)]
        self.assertEqual(order, ["ci1", "ci2", "i1", "b1"])

    def test_fifo_within_class(self):
        q = pq.PriorityQueue()
        for i in range(3):
            q.push("t", pq.CLASS_CI, {"i": i})
        self.assertEqual([q.pop().payload["i"] for _ in range(3)], [0, 1, 2])

    def test_snapshot_restore(self):
        q = pq.PriorityQueue()
        q.push("a", pq.CLASS_BATCH, {"n": "b"})
        q.push("a", pq.CLASS_CI, {"n": "ci"})
        snap = q.snapshot()
        q2 = pq.PriorityQueue(); q2.restore(snap)
        self.assertEqual(q2.size(), 2)
        self.assertEqual(q2.pop().payload["n"], "ci")
        self.assertEqual(q2.pop().payload["n"], "b")

    def test_unknown_priority(self):
        with self.assertRaises(ValueError):
            pq.PriorityQueue().push("t", "urgent")

    def test_empty_pop(self):
        self.assertIsNone(pq.PriorityQueue().pop())


class PolicyTest(unittest.TestCase):
    POL = {"version": 12, "rules": [
        {"id": "block-rce", "when": {"check_id_in": ["A-01"]}, "action": "block"}]}

    def test_hash_deterministic(self):
        self.assertEqual(policy.content_hash(self.POL), policy.content_hash(dict(reversed(list(self.POL.items())))))

    def test_sign_verify(self):
        sig = policy.sign(self.POL, "k")
        self.assertTrue(policy.verify(self.POL, sig, "k"))
        self.assertFalse(policy.verify(self.POL, sig, "other"))
        tampered = {"version": 12, "rules": [
            {"id": "block-rce", "when": {"check_id_in": ["A-01"]}, "action": "allow"}]}
        self.assertFalse(policy.verify(tampered, sig, "k"))

    def test_validate(self):
        ok, _ = policy.validate(self.POL); self.assertTrue(ok)
        self.assertTrue(policy.validate({"rules": []})[0])  # пустой набор правил допустим
        self.assertFalse(policy.validate({"rules": [{"id": "x", "when": {}, "action": "boom"}]})[0])
        self.assertFalse(policy.validate({"rules": [{"id": "x"}]})[0])

    def test_make_policy(self):
        pv = policy.make_policy("pol-v12", self.POL, "k")
        self.assertEqual(pv.version, "pol-v12")
        self.assertTrue(policy.verify(pv.content, pv.signature, "k"))
        with self.assertRaises(ValueError):
            policy.make_policy("bad", {"rules": [{"id": "x"}]})


class TenantTest(unittest.TestCase):
    def test_defaults(self):
        reg = tenants.TenantRegistry(default_quota=quota.Quota(max_object_bytes=100))
        t = reg.resolve("nobody")
        self.assertEqual(t.tenant_id, "nobody")
        self.assertEqual(reg.quota_for("nobody").max_object_bytes, 100)
        self.assertTrue(reg.is_enabled("nobody"))

    def test_upsert_and_priority(self):
        reg = tenants.TenantRegistry()
        reg.upsert(tenants.Tenant("ci-team", priority=pq.CLASS_CI, enabled=True))
        self.assertEqual(reg.resolve("ci-team").priority, pq.CLASS_CI)
        with self.assertRaises(ValueError):
            reg.upsert(tenants.Tenant("bad", priority="ultra"))

    def test_disabled(self):
        reg = tenants.TenantRegistry()
        reg.upsert(tenants.Tenant("blocked", enabled=False))
        self.assertFalse(reg.is_enabled("blocked"))

    def test_all(self):
        reg = tenants.TenantRegistry()
        reg.upsert(tenants.Tenant("a")); reg.upsert(tenants.Tenant("b"))
        self.assertEqual(sorted(t.tenant_id for t in reg.all()), ["a", "b"])




class TasksSqlTest(unittest.TestCase):
    def test_ddl(self):
        self.assertIn("CREATE TABLE IF NOT EXISTS tasks", tasks_sql.DDL_TASKS)
        self.assertIn("idx_tasks_dequeue", tasks_sql.DDL_TASKS)

    def test_enqueue_and_dequeue_sql(self):
        e = tasks_sql.enqueue_sql("t-1", "ci", pq.CLASS_CI, pq.RANK[pq.CLASS_CI], '{"a":1}')
        self.assertIn("INSERT INTO tasks", e)
        self.assertIn("ON CONFLICT (task_id) DO NOTHING", e)
        d = tasks_sql.dequeue_sql()
        self.assertIn("ORDER BY rank, seq", d)
        self.assertIn("FOR UPDATE SKIP LOCKED", d)
        self.assertIn("RETURNING", d)

    def test_complete_and_requeue(self):
        self.assertIn("status='done'", tasks_sql.complete_sql("t", True))
        self.assertIn("status='failed'", tasks_sql.complete_sql("t", False, "boom"))
        self.assertIn("status='queued'", tasks_sql.requeue_sql("t"))

    def test_escaping(self):
        self.assertIn("'o''brien'", tasks_sql.enqueue_sql("t", "o'brien", "ci", 0))


class OrchestratorTest(unittest.TestCase):
    def test_archive_detected_by_ext(self):
        self.assertEqual(orchestrator.choose_strategy(fmt="model.tar.gz")["strategy"], "archive")
        self.assertEqual(orchestrator.choose_strategy(kind="archive")["strategy"], "archive")

    def test_llm_with_engine(self):
        r = orchestrator.choose_strategy(is_llm=True, has_engine_image=True)
        self.assertEqual(r["strategy"], "llm-inference"); self.assertTrue(r["dynamic"])

    def test_llm_without_engine(self):
        r = orchestrator.choose_strategy(is_llm=True, has_engine_image=False)
        self.assertEqual(r["strategy"], "static"); self.assertFalse(r["dynamic"])

    def test_dynamic_vs_static_by_size(self):
        self.assertEqual(orchestrator.choose_strategy(size=1024)["strategy"], "dynamic")
        self.assertEqual(orchestrator.choose_strategy(size=10 ** 13, dynamic_max_bytes=10 ** 12)["strategy"], "static")

    def test_engine_image(self):
        self.assertEqual(orchestrator.choose_strategy(kind="engine_image")["strategy"], "static")


class PolicyLoadTest(unittest.TestCase):
    POL = {"version": 7, "rules": [
        {"id": "r1", "when": {"check_id_in": ["A-01"]}, "action": "block"}]}

    def test_load_ok(self):
        pv = policy.load(self.POL)
        self.assertEqual(pv.version, "7")

    def test_load_requires_valid_signature(self):
        sig = policy.sign(self.POL, "k")
        pv = policy.load(self.POL, key="k", require_signature=True, signature=sig)
        self.assertEqual(pv.version, "7")
        with self.assertRaises(ValueError):
            policy.load(self.POL, key="k", require_signature=True, signature="deadbeef")
        with self.assertRaises(ValueError):
            policy.load(self.POL, require_signature=True)

    def test_load_invalid_schema(self):
        with self.assertRaises(ValueError):
            policy.load({"rules": [{"id": "x", "when": {}, "action": "nope"}]})


if __name__ == "__main__":
    unittest.main(verbosity=2)
