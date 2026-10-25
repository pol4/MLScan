#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P6: unit-тесты evidence-цепочки/анкора и per-tenant KMS."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "security"))

import evidence  # noqa: E402
import kms  # noqa: E402


class EvidenceTest(unittest.TestCase):
    def test_append_and_verify(self):
        chain = []
        for i in range(5):
            evidence.append(chain, {"scan_id": f"s{i}", "verdict": "Safe"}, "k")
        ok, why = evidence.verify_chain(chain, "k")
        self.assertTrue(ok, why)
        self.assertEqual(chain[0]["prev"], evidence.GENESIS)
        self.assertEqual(chain[-1]["seq"], 5)

    def test_tamper_payload_detected(self):
        chain = []
        for i in range(3):
            evidence.append(chain, {"v": i}, "k")
        chain[1]["payload"] = {"v": 999}
        self.assertFalse(evidence.verify_chain(chain, "k")[0])

    def test_remove_entry_detected(self):
        chain = []
        for i in range(4):
            evidence.append(chain, {"v": i}, "k")
        del chain[2]
        self.assertFalse(evidence.verify_chain(chain, "k")[0])

    def test_wrong_key_detected(self):
        chain = []
        evidence.append(chain, {"v": 1}, "k")
        self.assertFalse(evidence.verify_chain(chain, "other")[0])

    def test_anchor_and_verify(self):
        chain = []
        for i in range(3):
            evidence.append(chain, {"v": i}, "k")
        a = evidence.anchor_head(chain, "k", notary="tsa.example")
        self.assertTrue(evidence.verify_anchor(chain, a, "k"))
        # после добавления записи старый анкор больше не соответствует голове
        evidence.append(chain, {"v": 4}, "k")
        self.assertFalse(evidence.verify_anchor(chain, a, "k"))

    def test_anchor_tamper(self):
        chain = []; evidence.append(chain, {"v": 1}, "k")
        a = evidence.anchor_head(chain, "k")
        a["head"] = "sha256:" + "f" * 64
        self.assertFalse(evidence.verify_anchor(chain, a, "k"))


class KmsTest(unittest.TestCase):
    MASTER = b"master-key-material"

    def test_roundtrip(self):
        pt = b"secret model metadata"
        blob = kms.encrypt(self.MASTER, "tenant-a", pt)
        self.assertEqual(kms.decrypt(self.MASTER, blob), pt)
        self.assertTrue(kms.verify(blob, self.MASTER))

    def test_tenant_isolated(self):
        blob = kms.encrypt(self.MASTER, "tenant-a", b"x")
        blob_b = dict(blob); blob_b["tenant"] = "tenant-b"     # подмена тенанта -> тег не сойдётся
        self.assertFalse(kms.verify(blob_b, self.MASTER))
        with self.assertRaises(ValueError):
            kms.decrypt(self.MASTER, blob_b)

    def test_tamper_ct(self):
        blob = kms.encrypt(self.MASTER, "t", b"payload")
        ct = bytearray(bytes.fromhex(blob["ct"])); ct[0] ^= 1
        blob["ct"] = bytes(ct).hex()
        self.assertFalse(kms.verify(blob, self.MASTER))

    def test_tenant_keys_differ(self):
        self.assertNotEqual(kms.tenant_key(self.MASTER, "a"), kms.tenant_key(self.MASTER, "b"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
