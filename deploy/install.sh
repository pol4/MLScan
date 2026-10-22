#!/usr/bin/env bash
# Установка выбранного уровня MLScan (см. deploy/README.md).
#
#   bash deploy/install.sh 0        # уровень 0 — PoC: ничего не разворачивается, печатается инструкция
#   bash deploy/install.sh 1        # уровень 1 — изолированная песочница (микро-ВМ) на одном узле
#   bash deploy/install.sh 2        # уровень 2 — + сервис тестирования (S3 + PostgreSQL)
#   bash deploy/install.sh 3        # уровень 3 — + аналитика, policy, evidence, UI
#   bash deploy/install.sh 4        # уровень 4 — + интеграции (реестр, CI-gate, SIEM)
#   bash deploy/install.sh 5        # уровень 5 — + эксплуатация (метрики, качество, lifecycle, backup)
#
# Скрипт идемпотентен: все шаги — `kubectl apply`, повторный запуск безопасен.
# Уровни включают всё необходимое предыдущих уровней (можно ставить сразу 5).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
LEVEL="${1:-}"

die() { echo "Ошибка: $*" >&2; exit 1; }
step() { echo; echo "=== $*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "не найден '$1' ($2)"; }

case "$LEVEL" in
  0|1|2|3|4|5) ;;
  *) cat <<'USAGE'
Использование: bash deploy/install.sh <0..5>

  0 — PoC: Python + Docker, без кластера (многоформатный статический анализ + динамика в Docker)
  1 — изолированная песочница (Kata microVM) на одном узле Kubernetes
  2 — + сервис тестирования: S3 (Garage), PostgreSQL, приём больших артефактов
  3 — + аналитика, Policy Engine, append-only evidence, веб-UI (вход, RU/EN, /settings)
  4 — + интеграции: реестр моделей, CI-gate, SIEM-экспорт, threat-intel
  5 — + эксплуатация: метрики, качество (TPR/FPR), retest, alerts, retention/TTL, backup

Что выбрать — см. deploy/README.md. Проверка уровня — deploy/verify.sh <уровень>.
USAGE
     exit 2 ;;
esac

# ---------------------------------------------------------------- уровень 0
if [ "$LEVEL" = "0" ]; then
  step "Уровень 0 — PoC (без инфраструктуры)"
  need python3 "нужен Python 3.10+"
  python3 -c 'import sys; assert sys.version_info[:2] >= (3, 10), sys.version_info' \
    || die "требуется Python 3.10+"
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "Docker: доступен — динамический этап (L2) будет работать"
  else
    echo "Docker: НЕ доступен — динамический этап будет пропущен (вердикт Inconclusive с причиной)"
  fi
  cat <<'EOF'

Уровень 0 готов к работе (кластер не требуется):
  python3 poc/mlscan_poc.py <файл> --static-only          # только статика по всем форматам
  python3 poc/mlscan_poc.py <файл> --out report.md        # статика + динамика + поведение
  python3 poc/mlscan_poc.py <файл> --static-only --lang en

Проверка: bash deploy/verify.sh 0
Документация: poc/README.md
EOF
  exit 0
fi

# ------------------------------------------------- уровни 1..5: предпосылки
need kubectl "нужен kubectl"
kubectl cluster-info >/dev/null 2>&1 || die "нет доступа к кластеру Kubernetes (kubectl cluster-info)"
if ! kubectl get runtimeclass kata >/dev/null 2>&1; then
  echo "Предупреждение: RuntimeClass 'kata' не найдена — песочница уровня 1 не сможет"
  echo "использовать микро-ВМ. См. deploy/stage1/README.md (установка Kata/gVisor)."
fi
K8S_VER="$(kubectl version -o json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])' 2>/dev/null || echo '?')"
echo "Kubernetes: $K8S_VER | уровень установки: $LEVEL"

# ------------------------------------------------------------ уровень 1
step "[уровень 1] изолированная песочница (Kata microVM)"
bash "$HERE/stage1/apply.sh"
if [ -x "$HERE/stage1/60-falco.sh" ]; then
  echo "Falco/eBPF (наблюдаемость песочницы) — запускается отдельно: bash deploy/stage1/60-falco.sh"
fi
echo "Образ песочницы собирается Kaniko (нужен для динамики в кластере):"
echo "  bash deploy/sandbox-image/build.sh v4"
[ "$LEVEL" = "1" ] || true

if [ "$LEVEL" -ge 2 ]; then
# ------------------------------------------------------------ уровень 2
step "[уровень 2] хранилища: S3 (Garage) + PostgreSQL"
bash "$HERE/v2/data/apply.sh"
bash "$HERE/v2/db/apply.sh"
if [ "$LEVEL" -ge 5 ]; then
  echo "Резервное копирование БД (CronJob mlscan-pg-backup):"
  bash "$HERE/v2/backup/apply.sh"
fi
step "[уровень 2] сборка образа песочницы и запуск сервиса тестирования"
bash "$HERE/sandbox-image/build.sh" v4
echo "Ожидание сборки образа песочницы (Kaniko)…"
if ! kubectl -n mlscan-build wait --for=condition=complete job/mlscan-sandbox-build --timeout=900s >/dev/null 2>&1; then
  echo "Предупреждение: сборка не завершилась за 15 мин — проверьте:"
  echo "  kubectl -n mlscan-build logs job/mlscan-sandbox-build"
  echo "  (дальнейшие шаги продолжатся; образ подхватится после успешной сборки)"
fi
bash "$HERE/stage2/apply.sh"

# ------------------------------------------------------------ уровень 3
if [ "$LEVEL" -ge 3 ]; then
  step "[уровень 3] доступы (API-ключи и пользователи UI)"
  bash "$HERE/v2/auth/keys.sh"
  bash "$HERE/v2/auth/users.sh"
  step "[уровень 3] аналитика, policy, evidence, UI"
  bash "$HERE/stage3/apply.sh"
  step "[уровень 3] внешний доступ (Istio Ingress) и egress-allowlist"
  bash "$HERE/ingress/apply.sh"
fi

# ------------------------------------------------------------ уровень 4
if [ "$LEVEL" -ge 4 ]; then
  step "[уровень 4] интеграции (реестр, CI-gate, SIEM, threat-intel)"
  bash "$HERE/stage4/apply.sh"
fi

# ------------------------------------------------------------ уровень 5
if [ "$LEVEL" -ge 5 ]; then
  step "[уровень 5] эксплуатация (метрики, качество, retest, lifecycle)"
  bash "$HERE/stage5/apply.sh"
  bash "$HERE/v2/lifecycle/apply.sh"
fi
fi

cat <<EOF

Уровень $LEVEL развёрнут.
  Проверка:        bash deploy/verify.sh $LEVEL
  Что дальше:      deploy/upgrade.md (переход на уровень $((LEVEL + 1)))
  Состав уровней:  deploy/README.md
EOF
