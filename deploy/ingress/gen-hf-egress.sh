#!/usr/bin/env bash
# Генерация HF-egress allowlist (deploy/ingress/33-egress-hf.yaml).
#
# FQDN-политики (toFQDNs) в этом Calico-CRD НЕТ (проверено: crd.projectcalico.org/v1 и
# globalnetworkpolicies — поле destination.domains отсутствует), поэтому доступ к Hugging Face
# открывается по IP-адресам его хостов и CDN загрузки (только TCP/443).
#
# Запуск: bash deploy/ingress/gen-hf-egress.sh   (резолв хостов — на узле, где есть DNS/интернет)
# После генерации: kubectl apply -f deploy/ingress/33-egress-hf.yaml
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/33-egress-hf.yaml"
NODE="${MLSCAN_NODE_SSH:-col@rtx-cluster}"

HOSTS="huggingface.co hf.co cdn-lfs.hf.co cdn-lfs-us-1.hf.co cdn.hf.co us.aws.cdn.hf.co
       cas-bridge.xethub.hf.co cas-server.xethub.hf.co transfer.xethub.hf.co xethub.hf.co"

echo "[hf-egress] резолв хостов HF/CDN на $NODE…"
IPS="$(ssh -o StrictHostKeyChecking=no "$NODE" \
  "for h in $HOSTS; do getent ahostsv4 \$h 2>/dev/null | awk '{print \$1}'; done | sort -u" 2>/dev/null | tr '\n' ' ')"
[ -n "${IPS// /}" ] || { echo "[hf-egress] не удалось получить IP (нужен доступ к узлу/DNS)"; exit 2; }

python3 - "$OUT" $IPS <<'PY'
import sys
out, ips = sys.argv[1], sorted({x for x in sys.argv[2:] if x})
cidrs = set()
for ip in ips:                      # /32 хостов + /24 их подсетей (устойчивость к ротации)
    cidrs.add(ip + "/32"); cidrs.add(".".join(ip.split(".")[:3]) + ".0/24")
to = "\n".join(f"    - ipBlock: {{cidr: {c}}}" for c in sorted(cidrs))
open(out, "w").write(f"""# HF-egress (docs/15 §10, B3): доступ ТОЛЬКО к Hugging Face и адресам загрузки моделей (TCP/443).
# FQDN-политики в этом Calico-CRD нет, поэтому allowlist по IP-адресам хостов HF и его CDN:
#   huggingface.co, *.hf.co (cdn-lfs*, us.aws.cdn.hf.co), cas-bridge/cas-server/transfer.xethub.hf.co
# Включены /32 найденных адресов и /24 их подсетей. Обновлять при смене адресов:
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
print(f"[hf-egress] {out}: {len(cidrs)} CIDR")
PY
