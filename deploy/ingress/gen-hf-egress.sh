#!/usr/bin/env bash
# Генерация HF-egress allowlist (deploy/ingress/33-egress-hf.yaml).
#
# FQDN-политики (toFQDNs) в этом Calico-CRD НЕТ (проверено: crd.projectcalico.org/v1 и
# globalnetworkpolicies — поле destination.domains отсутствует), поэтому доступ к Hugging Face
# открывается по IP-адресам его хостов и CDN загрузки (только TCP/443).
#
# Политика узкая: по умолчанию выпускаются ТОЛЬКО /32 найденных адресов. Опция
# HF_EGRESS_INCLUDE_24=1 дополнительно добавляет /24 подсети (устойчивость к ротации внутри
# подсети, но шире заявленного «только HF») — включать осознанно.
#
# Запуск:  MLSCAN_NODE_SSH=user@node bash deploy/ingress/gen-hf-egress.sh
# Применение: kubectl apply -f deploy/ingress/33-egress-hf.yaml  (также делает deploy/ingress/apply.sh)
# Адреса HF/CDN ротируются — при поломке реального HF перегенерировать и применить заново.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/33-egress-hf.yaml"
# Узел для резолва задаётся явно (без site-specific значений в репозитории):
NODE="${MLSCAN_NODE_SSH:-${1:-}}"
if [ -z "$NODE" ]; then
  echo "укажите узел: MLSCAN_NODE_SSH=user@node bash deploy/ingress/gen-hf-egress.sh" >&2
  echo "(нужен хост с DNS/интернетом, например узел кластера; доступ по known_hosts)" >&2
  exit 2
fi
# Аутентификация узла обязательна (host key из known_hosts); доп. опции — через MLSCAN_NODE_SSH_OPTS.
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 ${MLSCAN_NODE_SSH_OPTS:-})

HOSTS="huggingface.co hf.co cdn-lfs.hf.co cdn-lfs-us-1.hf.co cdn.hf.co us.aws.cdn.hf.co cas-bridge.xethub.hf.co cas-server.xethub.hf.co transfer.xethub.hf.co xethub.hf.co"
HOSTS="${HOSTS//$'\n'/ }"   # одна строка: перенос ломает удалённый for-список

echo "[hf-egress] резолв хостов HF/CDN на $NODE…"
IPS="$(ssh "${SSH_OPTS[@]}" "$NODE" \
  "for h in $HOSTS; do getent ahostsv4 \$h 2>/dev/null | awk '{print \$1}'; done | sort -u" 2>/dev/null | tr '\n' ' ')"
[ -n "${IPS// /}" ] || { echo "[hf-egress] не удалось получить IP (нужен доступ к узлу/DNS по known_hosts)"; exit 2; }

INCLUDE_24="${HF_EGRESS_INCLUDE_24:-0}" python3 - "$OUT" $IPS <<'PY'
import os, sys
out, ips = sys.argv[1], sorted({x for x in sys.argv[2:] if x})
include_24 = os.environ.get("HF_EGRESS_INCLUDE_24", "0") == "1"
cidrs = set()
for ip in ips:
    cidrs.add(ip + "/32")
    if include_24:                  # opt-in: подсеть целиком (шире, чем «только HF»)
        cidrs.add(".".join(ip.split(".")[:3]) + ".0/24")
to = "\n".join(f"    - ipBlock: {{cidr: {c}}}" for c in sorted(cidrs))
note = ("# Включены /32 найденных адресов" + (" и /24 их подсетей (HF_EGRESS_INCLUDE_24=1)."
        if include_24 else " (узко; /24 добавляются только при HF_EGRESS_INCLUDE_24=1)."))
open(out, "w").write(f"""# HF-egress (docs/15 §10, B3): доступ ТОЛЬКО к Hugging Face и адресам загрузки моделей (TCP/443).
# FQDN-политики в этом Calico-CRD нет, поэтому allowlist по IP-адресам хостов HF и его CDN:
#   huggingface.co, *.hf.co (cdn-lfs*, us.aws.cdn.hf.co), cas-bridge/cas-server/transfer.xethub.hf.co
{note}
# Адреса HF/CDN ротируются: при поломке реального HF перегенерировать
#   bash deploy/ingress/gen-hf-egress.sh && kubectl apply -f deploy/ingress/33-egress-hf.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mlscan-hf-egress
  namespace: mlscan-testing
  labels: {{app.kubernetes.io/part-of: mlscan, mlscan.io/stage: "ingress"}}
spec:
  podSelector: {{}}
  policyTypes: [Egress]
  egress:
  - ports:
    - {{protocol: TCP, port: 443}}
    to:
{to}
""")
print(f"[hf-egress] {out}: {len(cidrs)} CIDR" + (" (с /24)" if include_24 else " (только /32)"))
PY
