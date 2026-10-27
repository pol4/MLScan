#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""N6: JWT (HS256) и rate-limit из deploy/v2/auth/authz.py."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "v2", "auth"))
os.environ.setdefault("MLSCAN_AUTH", "on")
import authz  # noqa: E402


class JwtTest(unittest.TestCase):
    KEY = "unit-test-key"

    def test_roundtrip_and_claims(self):
        tok = authz.make_jwt("ci-bot", ["ci"], ttl=60, key=self.KEY)
        self.assertEqual(tok.count("."), 2)
        v = authz.verify_jwt(tok, key=self.KEY)
        self.assertEqual(v["subject"], "ci-bot")
        self.assertEqual(v["roles"], ["ci"])
        self.assertEqual(v["via"], "jwt")

    def test_wrong_key_rejected(self):
        tok = authz.make_jwt("ci", ["ci"], ttl=60, key=self.KEY)
        self.assertIsNone(authz.verify_jwt(tok, key="other-key"))

    def test_expired_rejected(self):
        tok = authz.make_jwt("ci", ["ci"], ttl=-10, key=self.KEY)
        self.assertIsNone(authz.verify_jwt(tok, key=self.KEY))

    def test_tampered_payload_rejected(self):
        tok = authz.make_jwt("ci", ["ci"], ttl=60, key=self.KEY)
        head, pay, sig = tok.split(".")
        forged = head + "." + authz._b64u_enc(b'{"sub":"admin","exp":9999999999,"roles":["admin"]}') + "." + sig
        self.assertIsNone(authz.verify_jwt(forged, key=self.KEY))

    def test_alg_none_rejected(self):
        head = authz._b64u_enc(b'{"alg":"none","typ":"JWT"}')
        pay = authz._b64u_enc(b'{"sub":"admin","exp":9999999999,"aud":"mlscan-api","iss":"mlscan"}')
        self.assertIsNone(authz.verify_jwt(head + "." + pay + ".", key=self.KEY))

    def test_audience_and_issuer_enforced(self):
        tok = authz.make_jwt("ci", ["ci"], ttl=60, aud="other-app", iss="other-iss", key=self.KEY)
        self.assertIsNone(authz.verify_jwt(tok, key=self.KEY))
        self.assertIsNotNone(authz.verify_jwt(tok, aud="other-app", iss="other-iss", key=self.KEY))

    def test_no_key_is_fail_closed(self):
        self.assertIsNone(authz.make_jwt("ci", ["ci"], ttl=60, key=""))
        # пустой ключ окружения не должен приниматься ни при каких условиях
        self.assertIsNone(authz.verify_jwt("a.b.c", key=""))


class RateLimitTest(unittest.TestCase):
    def test_burst_then_deny_and_refill(self):
        rl = authz.RateLimiter(rps=1000, burst=2)
        self.assertTrue(rl.allow("u")[0])
        self.assertTrue(rl.allow("u")[0])
        ok, retry = rl.allow("u")
        self.assertFalse(ok)
        self.assertGreater(retry, 0.0)
        self.assertTrue(rl.allow("other")[0])          # ключи независимы

    def test_disabled_when_zero(self):
        rl = authz.RateLimiter(rps=0, burst=1)
        for _ in range(50):
            self.assertTrue(rl.allow("u")[0])

    def test_set_rate_limit_switches_state(self):
        st = authz.set_rate_limit(0, 1)
        self.assertEqual(st["rps"], 0.0)
        self.assertEqual(authz.rate_limit_state()["rps"], 0.0)
        authz.set_rate_limit(50, 100)
        self.assertEqual(authz.rate_limit_state()["burst"], 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)
