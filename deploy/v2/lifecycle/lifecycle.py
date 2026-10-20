#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MLScan lifecycle (stdlib): retention/TTL артефактов, карантин вредоносных, tombstones.

Правила:
 * обычные артефакты старше TTL (по умолчанию 90 дней) удаляются из S3 (tombstone в БД);
 * артефакты, связанные со сканом с вердиктом Malicious/Dangerous (по policy), НЕ удаляются
   раньше quarantine-TTL (по умолчанию 365 дней) — «юридический удерж»;
 * метаданные/отпечатки/evidence в БД сохраняются всегда (удаляется только блоб).

Использование: python lifecycle.py [--ttl-days N] [--quarantine-ttl-days M] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, "/opt/pg")
sys.path.insert(0, "/opt/s3")
from pgclient import Pg  # noqa: E402
from s3client import S3  # noqa: E402

PGHOST = os.environ.get("PGHOST", "")
S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "")
S3_BUCKET = os.environ.get("S3_BUCKET", "mlscan-artifacts")


def _lit(v) -> str:
    if v is None:
        return "NULL"
    return "'" + str(v).replace("'", "''") + "'"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ttl-days", type=int, default=int(os.environ.get("TTL_DAYS", "90")))
    ap.add_argument("--quarantine-ttl-days", type=int,
                    default=int(os.environ.get("QUARANTINE_TTL_DAYS", "365")))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only-name", default="", help="ограничить префиксом имени файла")
    ap.add_argument("--only-sha", default="", help="ограничить конкретным sha256")
    args = ap.parse_args()

    pg = Pg(PGHOST, int(os.environ.get("PGPORT", "5432")), os.environ.get("PGUSER", "mlscan"),
            os.environ.get("PGPASSWORD", ""), os.environ.get("PGDATABASE", "mlscan"), timeout=20)
    pg.connect()
    s3 = S3(S3_ENDPOINT, os.environ.get("S3_ACCESS_KEY", ""), os.environ.get("S3_SECRET_KEY", ""),
            region=os.environ.get("S3_REGION", "garage"), bucket=S3_BUCKET, timeout=60)

    # вердикты по артефактам: uploads(artifact_id, request_id=scan_id) -> scans.verdict
    _cols, verdict_rows = pg.query(
        "SELECT u.artifact_id, max(s.verdict) FROM uploads u "
        "JOIN scans s ON s.scan_id = u.request_id WHERE u.artifact_id IS NOT NULL "
        "GROUP BY u.artifact_id")
    verdicts = {int(r[0]): (r[1] or "") for r in verdict_rows if r[0] is not None}

    _cols, arts = pg.query(
        "SELECT id, sha256, s3_key, filename, "
        "EXTRACT(EPOCH FROM (now() - created_at))/86400.0 AS age_days "
        "FROM artifacts WHERE s3_key IS NOT NULL")

    deleted = kept = scanned = 0
    for aid, sha, key, fname, age in arts:
        aid = int(aid)
        age_days = float(age or 0)
        if args.only_name and not str(fname or "").startswith(args.only_name):
            continue
        if args.only_sha and sha != args.only_sha:
            continue
        verdict = verdicts.get(aid, "")
        malicious = verdict in ("Malicious", "Dangerous")
        ttl = args.quarantine_ttl_days if malicious else args.ttl_days
        scanned += 1
        if age_days < ttl:
            kept += 1
            continue
        print(f"DELETE {fname} sha={sha[:12]} age={age_days:.1f}d verdict={verdict or '-'}")
        if not args.dry_run:
            try:
                st, _, _ = s3.delete(key)
                if st not in (200, 204):
                    print(f"  s3 delete status {st}", file=sys.stderr)
                    kept += 1
                    continue
                pg.query("INSERT INTO artifact_deletions(sha256,s3_key,reason) VALUES "
                         f"({_lit(sha)},{_lit(key)},{_lit('ttl' if not malicious else 'quarantine-ttl')})")
                deleted += 1
            except Exception as exc:  # noqa: BLE001
                print(f"  delete error: {exc}", file=sys.stderr)
                kept += 1
        else:
            deleted += 1
    pg.close()
    print(json.dumps({"scanned": scanned, "deleted": deleted, "kept": kept,
                      "dry_run": args.dry_run, "ttl_days": args.ttl_days,
                      "quarantine_ttl_days": args.quarantine_ttl_days}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
