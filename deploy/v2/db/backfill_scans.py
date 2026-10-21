#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Бэкфилл метаданных сканов из файлов `/data/scans/*.json` в PostgreSQL.

Зачем: исторические сканы (до включения записи в БД) не имеют связи
`scans.artifact_id`, поэтому список и статистика не могли читаться из БД и
сервис перечитывал тысячи JSON-файлов. Скрипт идемпотентен: дозаполняет
`artifacts`, `scans` (с `artifact_id`) и `findings` для каждого файла скана.

Запуск (в поде сервиса тестирования, где есть и файлы, и доступ к БД):

    kubectl -n mlscan-testing exec -i deploy/mlscan-testing -- python3 - < deploy/v2/db/backfill_scans.py
"""
from __future__ import annotations

import glob
import json
import os
import sys

sys.path.insert(0, "/opt/pg")

try:
    from pgclient import Pg  # type: ignore
except Exception as exc:  # noqa: BLE001
    print(f"pgclient недоступен: {exc}", file=sys.stderr)
    raise SystemExit(2)

DATA_DIR = os.environ.get("DATA_DIR", "/data")


def _lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def _run(c, sql: str, what: str):
    """Выполняет запрос; при ошибке печатает контекст и возвращает None."""
    try:
        return c.query(sql)
    except Exception as exc:  # noqa: BLE001
        print(f"[{what}] {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"      SQL: {sql[:300]}", file=sys.stderr)
        return None


def connect() -> "Pg":
    c = Pg(os.environ["PGHOST"], int(os.environ.get("PGPORT", "5432")),
           os.environ.get("PGUSER", "mlscan"), os.environ.get("PGPASSWORD", ""),
           os.environ.get("PGDATABASE", "mlscan"), timeout=60)
    c.connect()
    return c


def main() -> int:
    files = sorted(glob.glob(os.path.join(DATA_DIR, "scans", "*.json")))
    print(f"файлов сканов: {len(files)}")
    c = connect()
    linked = inserted = skipped = 0
    for path in files:
        try:
            with open(path) as fh:
                rec = json.load(fh)
        except Exception:  # noqa: BLE001
            skipped += 1
            continue
        sid = rec.get("scan_id")
        sha = rec.get("sha256")
        if not sid:
            skipped += 1
            continue
        art_id = None
        if sha:
            res = _run(c,
                "INSERT INTO artifacts(sha256,size,format,filename,s3_key) VALUES "
                f"({_lit(sha)},{int(rec.get('size') or 0)},{_lit(rec.get('format'))},"
                f"{_lit(rec.get('name'))},{_lit(rec.get('s3_key'))}) "
                "ON CONFLICT (sha256) DO UPDATE SET size=EXCLUDED.size, "
                "filename=EXCLUDED.filename, s3_key=EXCLUDED.s3_key RETURNING id", "artifacts")
            art_id = res[1][0][0] if res and res[1] else None
        state = rec.get("state") or "done"
        verdict = rec.get("verdict")
        reason = rec.get("reason")
        timings = json.dumps(rec.get("timings") or {}, ensure_ascii=False)
        created = rec.get("created") or rec.get("updated")
        finished = rec.get("updated") if state in ("done", "error") else None
        _run(c,
            "INSERT INTO scans(scan_id,artifact_id,status,stage,progress,verdict,reason,timings,"
            "started_at,finished_at,created_at) VALUES "
            f"({_lit(sid)},{art_id if art_id is not None else 'NULL'},{_lit(state)},"
            f"{_lit(rec.get('stage'))},{int(rec.get('progress') or 0)},{_lit(verdict)},{_lit(reason)},"
            f"{_lit(timings)}::jsonb,"
            f"{(_lit(created) + '::timestamptz') if created else 'NULL'},"
            f"{(_lit(finished) + '::timestamptz') if finished else 'NULL'},"
            f"{(_lit(created) + '::timestamptz') if created else 'now()'}) "
            "ON CONFLICT (scan_id) DO UPDATE SET artifact_id=EXCLUDED.artifact_id, "
            "status=EXCLUDED.status, stage=EXCLUDED.stage, progress=EXCLUDED.progress, "
            "verdict=EXCLUDED.verdict, reason=EXCLUDED.reason, timings=EXCLUDED.timings, "
            "finished_at=EXCLUDED.finished_at", "scans")
        if art_id is not None:
            linked += 1
        # findings — только если для скана их ещё нет
        res = _run(c, f"SELECT count(*) FROM findings WHERE scan_id={_lit(sid)}", "findings-count")
        cnt = res[1] if res else [["0"]]
        if not (cnt and int(cnt[0][0])):
            for f in rec.get("findings") or []:
                ev = f.get("evidence")
                ev_sql = "NULL" if ev is None else _lit(json.dumps(ev, ensure_ascii=False))
                _run(c, "INSERT INTO findings(scan_id,level,check_id,category,severity,confidence,"
                        "title,evidence) VALUES "
                        f"({_lit(sid)},{_lit(f.get('level'))},{_lit(f.get('check_id'))},"
                        f"{_lit(f.get('category'))},{_lit(f.get('severity'))},"
                        f"{f.get('confidence') if f.get('confidence') is not None else 'NULL'},"
                        f"{_lit(f.get('title'))},{ev_sql})", "findings")
            inserted += 1
    _cols, rows = c.query("SELECT count(*), count(artifact_id) FROM scans")
    c.close()
    print(f"связано с artifacts: {linked}; добавлено наборов findings: {inserted}; пропущено: {skipped}")
    print(f"scans в БД: {rows[0][0]}, с artifact_id: {rows[0][1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
