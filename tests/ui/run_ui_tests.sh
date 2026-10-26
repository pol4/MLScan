#!/usr/bin/env bash
# Запуск UI-тестов в браузере: ставит зависимости (puppeteer-core) при необходимости
# и запускает node-скрипты в tests/ui. Учитывает прокси через no_proxy для локальных адресов.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export NO_PROXY="${NO_PROXY:-},127.0.0.1,localhost,analytics.mlscan.local,mlscan.local"
export no_proxy="$NO_PROXY"

if [ ! -d "$HERE/node_modules" ]; then
  echo "[ui] установка зависимостей (puppeteer-core)…"
  (cd "$HERE" && npm install --no-audit --no-fund >/tmp/mlscan-ui-npm.log 2>&1) \
    || { echo "[ui] npm install не удался:"; tail -20 /tmp/mlscan-ui-npm.log; exit 2; }
fi

# bundle для UI-теста «Тест bundle»: берём первый с моделью в хранилище (если есть доступ к кластеру)
if [ -z "${MLSCAN_BUNDLE_ID:-}" ] && command -v kubectl >/dev/null 2>&1; then
  # предпочитаем bundle с РЕАЛЬНЫМ движком llama.cpp (иначе job теста не сможет скачать образ)
  MLSCAN_BUNDLE_ID="$(kubectl -n mlscan-testing exec deploy/mlscan-testing -- python3 -c '
import sys; sys.path.insert(0,"/opt/svc")
import mlscan_testing as m
q=("SELECT b.bundle_id FROM bundles b JOIN artifacts a ON a.sha256=b.model_sha256 "
   "WHERE b.engine_image LIKE " + m._lit("%ggml-org/llama.cpp@sha256%") + " ORDER BY b.created DESC LIMIT 1")
r=m.db_query(q) or m.db_query("SELECT b.bundle_id FROM bundles b JOIN artifacts a ON a.sha256=b.model_sha256 "
                              "ORDER BY b.created DESC LIMIT 1")
print(r[0][0] if r else "")' 2>/dev/null | tr -d "\r")"
  [ -n "${MLSCAN_BUNDLE_ID:-}" ] && { export MLSCAN_BUNDLE_ID; echo "[ui] bundle для теста: $MLSCAN_BUNDLE_ID"; }
fi

rc=0
for t in "$HERE"/*_test.js; do
  [ -e "$t" ] || continue
  echo "[ui] === $(basename "$t") ==="
  node "$t" || rc=1
done

# Полный операторский E2E с РЕАЛЬНЫМИ моделями (LMSCAN_E2E=1): требует HF-egress, реальные
# файлы в /tmp (см. шапку скрипта) и доступ к сервису тестирования (MLSCAN_TESTING_URL).
if [ "${MLSCAN_E2E:-0}" = "1" ] && [ -e "$HERE/operator_browser_e2e.js" ]; then
  # Ключ не хранится в репозитории: берём админ-ключ из Secret кластера (или из MLSCAN_API_KEY).
  if [ -z "${MLSCAN_API_KEY:-}" ] && command -v kubectl >/dev/null 2>&1; then
    MLSCAN_API_KEY="$(kubectl -n mlscan-testing get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' 2>/dev/null \
      | base64 -d 2>/dev/null \
      | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])' 2>/dev/null)"
    [ -n "${MLSCAN_API_KEY:-}" ] && echo "[ui] MLSCAN_API_KEY получен из Secret mlscan-keys"
  fi
  export MLSCAN_API_KEY="${MLSCAN_API_KEY:-}"
  echo "[ui] === operator_browser_e2e.js (реальные модели) ==="
  node "$HERE/operator_browser_e2e.js" || rc=1
fi
# cleanup: завершённые/висящие job'ы теста bundle держат GPU — убираем после прогона UI-тестов
if command -v kubectl >/dev/null 2>&1; then
  kubectl -n mlscan-build delete jobs -l app=mlscan-llm-test --ignore-not-found >/dev/null 2>&1
fi
exit $rc
