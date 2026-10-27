#!/usr/bin/env bash
# B1: BTF-ядро для Kata-песочницы (in-guest eBPF/Tetragon) — БЕЗ рестарта containerd/kata.
#
# Почему так: в этой сборке (Kata 3.32 + containerd MicroK8s) per-pod аннотация
# io.katacontainers.config.hypervisor.kernel игнорируется даже при enable_annotations,
# поэтому единственный надёжный путь без правки containerd-template.toml — переключить
# kernel в АКТИВНОМ конфиге Kata на BTF-вариант (vmlinux-debug.container, CONFIG_DEBUG_INFO_BTF=y).
# Конфиг читается при создании каждой микро-ВМ: изменения действуют для новых подов, рестарт не нужен.
#
# Идемпотентно, с бэкапом в /var/backups/mlscan/. Откат — восстановить конфиг из бэкапа.
# Все kata-нагрузки стенда — только mlscan-sandbox (сканеры), поэтому переключение ядра безопасно.
# Запуск: MLSCAN_NODE_SSH=user@node bash deploy/v3/sandbox/kata-btf/install.sh
set -uo pipefail
CTX="${MLSCAN_KUBE_CONTEXT:-microk8s}"
NODE="${MLSCAN_NODE_SSH:-${1:-}}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 ${MLSCAN_NODE_SSH_OPTS:-})
CONF="/opt/kata/share/defaults/kata-containers/configuration.toml"
KERNEL_BTF="/opt/kata/share/kata-containers/vmlinux-debug.container"
KERNEL_STD="/opt/kata/share/kata-containers/vmlinux.container"

[ -n "$NODE" ] || { echo "укажите узел: MLSCAN_NODE_SSH=user@node $0" >&2; exit 2; }
run() { ssh "${SSH_OPTS[@]}" "$NODE" "$1"; }

echo "[kata-btf] 1) проверка BTF-ядра Kata"
run "sudo test -e $KERNEL_BTF && sudo grep -q 'CONFIG_DEBUG_INFO_BTF=y' /opt/kata/share/kata-containers/config-*-debug && echo OK" \
  | grep -q OK || { echo "ОШИБКА: нет BTF-ядра ($KERNEL_BTF)"; exit 1; }
echo "  [OK] $KERNEL_BTF (CONFIG_DEBUG_INFO_BTF=y)"

echo "[kata-btf] 2) kernel в активном конфиге -> BTF-вариант (бэкап в /var/backups/mlscan)"
run "set -e
  ts=\$(date +%Y%m%d%H%M%S)
  sudo mkdir -p /var/backups/mlscan
  sudo test -f /var/backups/mlscan/kata-configuration.toml.\$ts || sudo cp $CONF /var/backups/mlscan/kata-configuration.toml.\$ts
  cur=\$(sudo grep -m1 -E '^kernel *=' $CONF)
  echo \"было: \$cur\"
  if echo \"\$cur\" | grep -q 'vmlinux-debug.container'; then echo 'NOCHANGE'; else
    sudo sed -i '0,/^kernel *=.*/s##kernel = \"$KERNEL_BTF\"#' $CONF
    echo 'CHANGED'
  fi
  sudo grep -m1 -E '^kernel *=' $CONF"

echo "[kata-btf] 3) RuntimeClass kata-btf (маркер; handler kata)"
cat <<'Y' | kubectl --context "$CTX" apply -f - >/dev/null
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-btf
  labels: {app.kubernetes.io/part-of: mlscan, mlscan.io/component: sandbox}
handler: kata
Y
kubectl --context "$CTX" get runtimeclass kata-btf -o name
echo "[kata-btf] готово. Откат: восстановить $CONF из /var/backups/mlscan/ (и убедиться, что kernel = $KERNEL_STD)"
