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

rc=0
for t in "$HERE"/*_test.js; do
  [ -e "$t" ] || continue
  echo "[ui] === $(basename "$t") ==="
  node "$t" || rc=1
done

# Полный операторский E2E с РЕАЛЬНЫМИ моделями (LMSCAN_E2E=1): требует HF-egress, реальные
# файлы в /tmp (см. шапку скрипта) и доступ к сервису тестирования (MLSCAN_TESTING_URL).
if [ "${MLSCAN_E2E:-0}" = "1" ] && [ -e "$HERE/operator_browser_e2e.js" ]; then
  echo "[ui] === operator_browser_e2e.js (реальные модели) ==="
  node "$HERE/operator_browser_e2e.js" || rc=1
fi
exit $rc
