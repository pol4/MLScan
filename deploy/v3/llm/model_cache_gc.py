#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""G4: GC read-mostly кэша моделей (per-sha, LRU/по возрасту).

Платформа отдала очистку кэша тенанту (данные тенанта). Кэш живёт на общем PVC
(ceph-rwx), раскладка: ``<cache>/<sha256>/files`` + маркер ``.ready``; при
использовании обновляется ``<cache>/<sha256>/.used`` (mtime = last used).

Правила удаления (fail-safe):
  * удаляем только готовые per-sha каталоги (``<sha>/.ready`` существует);
  * НИКОГДА не трогаем: активные записи (есть ``<sha>.lock``), слишком «свежие»
    (``last_used`` моложе ``GC_MIN_IDLE_S``) и ``GC_KEEP`` самых новых записей;
  * цель — суммарный размер ``<= GC_TARGET_GB`` (ниже порога алерта платформы 85%);
  * также подчищаем брошенные ``<sha>.tmp`` и протухшие ``<sha>.lock``.

Модуль без побочных эффектов на импорте; ``main()`` читает env и печатает сводку.
"""
from __future__ import annotations

import os
import shutil
import sys
import time

SHA_LEN = 64


def _is_sha(name: str) -> bool:
    return len(name) == SHA_LEN and all(c in "0123456789abcdef" for c in name.lower())


def dir_size(path: str) -> int:
    total = 0
    for dp, _, fs in os.walk(path):
        for fn in fs:
            try:
                total += os.path.getsize(os.path.join(dp, fn))
            except OSError:
                pass
    return total


def scan(cache_dir: str, now: float | None = None) -> dict:
    """Собрать состояние кэша: готовые записи, .tmp-заготовки и .lock-файлы."""
    now = time.time() if now is None else now
    entries: list[dict] = []
    tmps: list[str] = []
    locks: list[str] = []
    try:
        names = os.listdir(cache_dir)
    except OSError:
        names = []
    for name in names:
        full = os.path.join(cache_dir, name)
        if name.endswith(".lock"):
            try:
                locks.append({"name": name, "mtime": os.path.getmtime(full)})
            except OSError:
                pass
            continue
        if name.endswith(".tmp"):
            if os.path.isdir(full):
                try:
                    tmps.append({"name": name, "mtime": os.path.getmtime(full)})
                except OSError:
                    pass
            continue
        if not (os.path.isdir(full) and _is_sha(name)):
            continue
        ready = os.path.join(full, ".ready")
        if not os.path.exists(ready):
            continue
        used = os.path.join(full, ".used")
        mt = 0.0
        for p in (used, ready):
            try:
                mt = max(mt, os.path.getmtime(p))
            except OSError:
                pass
        entries.append({"key": name, "path": full, "size": dir_size(full),
                        "last_used": mt, "locked": os.path.exists(os.path.join(cache_dir, name + ".lock"))})
    return {"entries": entries, "tmps": tmps, "locks": locks, "now": now}


def plan_eviction(entries: list[dict], target_bytes: int, keep: int, min_idle_s: int, now: float) -> list[dict]:
    """Выбрать к удалению (LRU) так, чтобы суммарный размер стал <= target_bytes.

    Не удаляет: заблокированные, моложе min_idle_s и `keep` самых новых. Возвращает
    список выбранных записей (по возрастанию last_used).
    """
    total = sum(int(e.get("size", 0)) for e in entries)
    if total <= target_bytes:
        return []
    protected = sorted(entries, key=lambda e: e.get("last_used", 0), reverse=True)[:max(int(keep), 0)]
    protected_keys = {e["key"] for e in protected}
    candidates = [e for e in entries
                  if e["key"] not in protected_keys
                  and not e.get("locked")
                  and (now - float(e.get("last_used", 0))) >= min_idle_s]
    candidates.sort(key=lambda e: e.get("last_used", 0))     # самые старые — первыми
    evicted: list[dict] = []
    for e in candidates:
        if total <= target_bytes:
            break
        evicted.append(e)
        total -= int(e.get("size", 0))
    return evicted


def gc(cache_dir: str, *, target_gb: float = 200.0, keep: int = 1, min_idle_s: int = 21600,
       tmp_ttl_s: int = 3600, lock_ttl_s: int = 7200, dry_run: bool = False,
       now: float | None = None) -> dict:
    """Выполнить цикл GC; вернуть сводку (что удалено/сколько освобождено)."""
    now = time.time() if now is None else now
    st = scan(cache_dir, now)
    entries = st["entries"]
    total_before = sum(e["size"] for e in entries)
    target = int(float(target_gb) * (1 << 30))
    victims = plan_eviction(entries, target, keep, min_idle_s, now)
    freed = 0
    evicted_keys: list[str] = []
    for v in victims:
        freed += int(v["size"])
        evicted_keys.append(v["key"])
        if not dry_run:
            shutil.rmtree(v["path"], ignore_errors=True)
    # брошенные .tmp и протухшие .lock
    tmp_removed, lock_removed = [], []
    for t in st["tmps"]:
        if (now - t["mtime"]) >= tmp_ttl_s:
            tmp_removed.append(t["name"])
            if not dry_run:
                shutil.rmtree(os.path.join(cache_dir, t["name"]), ignore_errors=True)
    for lk in st["locks"]:
        if (now - lk["mtime"]) >= lock_ttl_s:
            lock_removed.append(lk["name"])
            if not dry_run:
                try:
                    os.remove(os.path.join(cache_dir, lk["name"]))
                except OSError:
                    pass
    total_after = total_before - freed
    return {"target_gb": target_gb, "total_before": total_before, "total_after": total_after,
            "evicted": evicted_keys, "freed": freed, "tmp_removed": tmp_removed,
            "lock_removed": lock_removed, "dry_run": dry_run, "entries": len(entries)}


def main() -> int:
    cache = os.environ.get("CACHE_DIR", "/cache")
    target_gb = float(os.environ.get("GC_TARGET_GB", "200"))
    keep = int(os.environ.get("GC_KEEP", "1"))
    min_idle_s = int(os.environ.get("GC_MIN_IDLE_S", "21600"))       # 6ч
    tmp_ttl_s = int(os.environ.get("GC_TMP_TTL_S", "3600"))
    lock_ttl_s = int(os.environ.get("GC_LOCK_TTL_S", "7200"))
    dry = os.environ.get("GC_DRY_RUN", "0") == "1"
    if not os.path.isdir(cache):
        print(f"[gc] cache dir отсутствует: {cache}", file=sys.stderr)
        return 1
    r = gc(cache, target_gb=target_gb, keep=keep, min_idle_s=min_idle_s,
           tmp_ttl_s=tmp_ttl_s, lock_ttl_s=lock_ttl_s, dry_run=dry)
    print("[gc] cache={cache} target={target_gb}G entries={entries} before={b:.2f}G after={a:.2f}G "
          "evicted={n} freed={f:.2f}G tmp_removed={t} lock_removed={l} dry_run={d}".format(
              cache=cache, target_gb=r["target_gb"], entries=r["entries"],
              b=r["total_before"] / (1 << 30), a=r["total_after"] / (1 << 30),
              n=len(r["evicted"]), f=r["freed"] / (1 << 30),
              t=len(r["tmp_removed"]), l=len(r["lock_removed"]), d=r["dry_run"]), flush=True)
    for k in r["evicted"]:
        print(f"[gc] evict {k}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
