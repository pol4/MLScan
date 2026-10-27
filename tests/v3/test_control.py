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
import attest  # noqa: E402
import leader  # noqa: E402


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




class AttestTest(unittest.TestCase):
    DIG = "mlscan-registry/t/vllm@sha256:" + "a" * 64
    SHA = "b" * 64

    def st(self, **kw):
        base = dict(bundle_id="b-1", engine_image=self.DIG, model_sha256=self.SHA,
                    verdict="Safe", action="allow")
        base.update(kw); return attest.make_statement(**base)

    def test_statement_and_digest(self):
        st = self.st()
        self.assertEqual(st["type"], "mlscan.bundle-verdict/v1")
        self.assertTrue(attest.statement_digest(st).startswith("sha256:"))
        self.assertEqual(attest.statement_digest(st), attest.statement_digest(self.st()))

    def test_sign_verify(self):
        st = self.st()
        sig = attest.sign(st, "k")
        self.assertTrue(attest.verify(st, sig, "k"))
        self.assertFalse(attest.verify(st, sig, "other"))
        tampered = self.st(verdict="Malicious")
        self.assertFalse(attest.verify(tampered, sig, "k"))

    def test_gate_block_on_verdict(self):
        self.assertEqual(attest.gate_decision("Malicious")[0], "block")
        self.assertEqual(attest.gate_decision("Dangerous")[0], "block")

    def test_gate_block_on_safety_fail(self):
        self.assertEqual(attest.gate_decision("Safe", safety_fail=1)[0], "block")

    def test_gate_quarantine_review_and_inconclusive(self):
        self.assertEqual(attest.gate_decision("Needs review")[0], "quarantine")
        self.assertEqual(attest.gate_decision("Inconclusive")[0], "quarantine")

    def test_gate_allow(self):
        self.assertEqual(attest.gate_decision("Safe", pass_rate=1.0)[0], "allow")

    def test_artifact_statement_signed_and_typed(self):
        st = attest.make_artifact_statement(model_sha256="a" * 64, verdict="Dangerous",
                                            action="block", source="artifact-verdict")
        self.assertEqual(st["type"], "mlscan.artifact-verdict/v1")
        self.assertIsNone(st["bundle_id"])
        self.assertEqual(st["predicate"]["source"], "artifact-verdict")
        sig = attest.sign(st, "k")
        self.assertTrue(attest.verify(st, sig, "k"))
        self.assertFalse(attest.verify(st, sig, "other"))
        self.assertEqual(st["subject"][0]["digest"]["sha256"], "a" * 64)

    def test_artifact_statement_default_source(self):
        st = attest.make_artifact_statement(model_sha256="b" * 64, verdict="", action="quarantine",
                                            source="policy-default", engine_image="reg/x@sha256:" + "c" * 64)
        self.assertEqual(st["predicate"]["source"], "policy-default")
        self.assertEqual(len(st["subject"]), 2)

    def test_gate_unknown_verdict_is_fail_closed(self):
        # неизвестный/пустой вердикт не может быть разрешением
        self.assertEqual(attest.gate_decision("")[0], "quarantine")
        self.assertEqual(attest.gate_decision("Weird")[0], "quarantine")

    def test_gate_pass_rate_threshold(self):
        self.assertEqual(attest.gate_decision("Safe", pass_rate=0.5, block_rate=0.8)[0], "quarantine")




class LeaderTest(unittest.TestCase):
    def test_lock_id_stable(self):
        self.assertEqual(leader.lock_id("evidence"), leader.lock_id("evidence"))
        self.assertNotEqual(leader.lock_id("evidence"), leader.lock_id("lifecycle"))
        self.assertGreaterEqual(leader.lock_id("x"), 0)

    def test_acquire_release(self):
        state = {"locked": False}

        def q(_sql):
            return [(not state["locked"],)]

        def e(_sql):
            state["locked"] = False

        ld = leader.Leader("evidence", q, e, owner="pod-1")
        self.assertTrue(ld.acquire()); self.assertTrue(ld.is_leader())
        state["locked"] = True
        ld2 = leader.Leader("evidence", q, e, owner="pod-2")
        self.assertFalse(ld2.acquire()); self.assertFalse(ld2.is_leader())
        ld.release(); self.assertFalse(ld.is_leader())
        self.assertTrue(ld2.acquire())

    def test_hold_key(self):
        ld = leader.Leader("lifecycle", lambda s: [(True,)], lambda s: None)
        self.assertEqual(ld.hold_key(), "mlscan:leader:lifecycle")


if __name__ == "__main__":
    unittest.main(verbosity=2)
