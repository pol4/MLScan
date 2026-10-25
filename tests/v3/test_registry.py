#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L1a: unit-тесты разбора/валидации образов (digest/allowlist) и подписи/SBOM."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "registry"))

import images  # noqa: E402
import sbom  # noqa: E402

D = "sha256:" + "a" * 64
REF = "mlscan-registry/team/vllm@" + D


class ImagesTest(unittest.TestCase):
    def test_parse(self):
        p = images.parse_ref(REF)
        self.assertEqual(p["registry"], "mlscan-registry")
        self.assertEqual(p["repo"], "team/vllm")
        self.assertEqual(p["digest"], D)

    def test_parse_tag(self):
        p = images.parse_ref("mlscan-registry/team/vllm:v1.2")
        self.assertEqual(p["tag"], "v1.2")
        self.assertEqual(p["digest"], "")

    def test_valid_digest(self):
        self.assertTrue(images.is_valid_digest(D))
        for bad in ("", "sha256:xyz", "a" * 64, "sha256:" + "A" * 64):
            self.assertFalse(images.is_valid_digest(bad))

    def test_validate_ref_requires_digest(self):
        ok, why = images.validate_ref("mlscan-registry/team/vllm:latest")
        self.assertFalse(ok); self.assertIn("digest", why)
        self.assertTrue(images.validate_ref(REF)[0])

    def test_allowlist(self):
        self.assertTrue(images.validate_ref(REF, allowlist=["mlscan-registry"])[0])
        ok, why = images.validate_ref(REF, allowlist=["docker.io"])
        self.assertFalse(ok); self.assertIn("allowlist", why)

    def test_storage_key(self):
        self.assertEqual(images.storage_key(D), f"registry/images/{'a'*64}/blob.tar")
        with self.assertRaises(ValueError):
            images.storage_key("bad")


class SbomTest(unittest.TestCase):
    def test_sign_verify(self):
        sig = sbom.sign_ref(D, "k")
        self.assertTrue(sbom.verify_ref(D, sig, "k"))
        self.assertFalse(sbom.verify_ref(D, sig, "other"))
        self.assertFalse(sbom.verify_ref("sha256:" + "b" * 64, sig, "k"))

    def test_record_and_validate(self):
        rec = sbom.make_image_record(digest=D, ref=REF, source="ci", size=123,
                                     signature=sbom.sign_ref(D, "k"), sbom="spdx:abc")
        ok, why = sbom.validate_record(rec); self.assertTrue(ok, why)
        ok2, why2 = sbom.validate_record(rec, key="k", require_signature=True)
        self.assertTrue(ok2, why2)
        self.assertFalse(sbom.validate_record(rec, key="wrong", require_signature=True)[0])
        self.assertFalse(sbom.validate_record({}, key="k", require_signature=True)[0])
        self.assertFalse(sbom.validate_record({"digest": "bad"})[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
