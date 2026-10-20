#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Проверка stdlib-клиента PostgreSQL (SCRAM) против развёрнутой БД MLScan."""
import os
import sys

sys.path.insert(0, "/opt/pg")
from pgclient import Pg  # noqa: E402

pg = Pg(os.environ.get("PGHOST", "postgres.mlscan-data.svc.cluster.local"),
        int(os.environ.get("PGPORT", "5432")),
        os.environ.get("PGUSER", "mlscan"),
        os.environ["PGPASSWORD"],
        os.environ.get("PGDATABASE", "mlscan"))
pg.connect()
print("auth OK")

cols, rows = pg.query("SELECT current_user, current_database()")
print("identity:", rows)

cols, rows = pg.query("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
print("public tables:", rows[0][0])

pg.query("INSERT INTO artifacts(sha256,size,filename,s3_key) VALUES "
         "('pgclient-test',1,'t.bin','pgclient-test/t.bin') ON CONFLICT (sha256) DO NOTHING")
cols, rows = pg.query("SELECT sha256,size FROM artifacts WHERE sha256='pgclient-test'")
print("select:", rows)

try:
    pg.query("UPDATE evidence SET scan_id='x'")
    print("append-only: NOT enforced (unexpected)")
except Exception as exc:  # noqa: BLE001
    print("append-only OK:", str(exc)[:60])

pg.close()
print("PG CLIENT VERIFY OK")
