#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Генератор манифестов многоузлового прототипа Garage для v3 (P0, RF>=2).

Печатает YAML: namespace, 3 Service'а (по одному на инстанс), 3 ConfigMap (per-node config),
3 PVC и 3 Deployment. Прототип размещается в отдельном namespace (по умолчанию `mlscan-v3-data`)
и не затрагивает v2-Garage. На одиночном стенде узлы логические (один хост) — проверяем
топологию/приём RF>=2, а не физическую изоляцию отказов.

Использование: python3 gen.py [--ns mlscan-v3-data] [--nodes 3] [--rf 2] [--capacity 10G]
"""
from __future__ import annotations

import argparse

TMPL = """\
# --- {name} ---
apiVersion: {api}
kind: {kind}
metadata:
  name: {name}
  namespace: {ns}
{labels}spec:
{spec}"""


def _labels(extra: str = "") -> str:
    lab = "  labels: {app: garage-v3, app.kubernetes.io/part-of: mlscan, mlscan.io/stage: v3}\n"
    return lab + extra


def service(name: str, ns: str, instance: int, ports: str) -> str:
    return TMPL.format(api="v1", kind="Service", name=name, ns=ns, labels=_labels(),
                       spec=f"  selector: {{app: garage-v3, instance: \"{instance}\"}}\n{ports}")


def configmap(name: str, ns: str, instance: int, nodes: int, rf: int) -> str:
    peers = ", ".join(f'"garage-v3-{i}:3901"' for i in range(nodes))
    cfg = (
        '      metadata_dir = "/var/lib/garage/meta"\n'
        '      data_dir = "/var/lib/garage/data"\n'
        '      db_engine = "lmdb"\n'
        f'      replication_factor = {rf}\n'
        '      rpc_bind_addr = "[::]:3901"\n'
        f'      rpc_public_addr = "garage-v3-{instance}:3901"\n'
        f'      bootstrap_peers = [{peers}]\n'
        '      [s3_api]\n'
        '      s3_region = "garage"\n'
        '      api_bind_addr = "[::]:3900"\n'
        '      root_domain = ".s3.garage.localhost"\n'
        '      [admin]\n'
        '      api_bind_addr = "[::]:3903"\n'
    )
    return (f"# --- {name} ---\n"
            "apiVersion: v1\nkind: ConfigMap\n"
            "metadata:\n"
            f"  name: {name}\n  namespace: {ns}\n"
            "  labels: {app: garage-v3, app.kubernetes.io/part-of: mlscan, mlscan.io/stage: v3}\n"
            "data:\n    garage.toml: |\n" + cfg)


def pvc(name: str, ns: str, size: str) -> str:
    spec = ("  accessModes: [\"ReadWriteOnce\"]\n"
            "  storageClassName: local-path\n"
            "  resources:\n    requests:\n"
            f"      storage: {size}\n")
    return TMPL.format(api="v1", kind="PersistentVolumeClaim", name=name, ns=ns, labels=_labels(),
                       spec=spec)


def deployment(name: str, ns: str, instance: int) -> str:
    spec = f"""  replicas: 1
  selector:
    matchLabels: {{app: garage-v3, instance: "{instance}"}}
  template:
    metadata:
      labels: {{app: garage-v3, instance: "{instance}"}}
    spec:
      containers:
      - name: garage
        image: dxflrs/garage:v1.0.1
        imagePullPolicy: IfNotPresent
        command: ["/garage", "server"]
        env:
        - {{name: GARAGE_CONFIG_FILE, value: /etc/garage/garage.toml}}
        - name: GARAGE_RPC_SECRET
          valueFrom: {{secretKeyRef: {{name: garage-v3-secrets, key: RPC_SECRET}}}}
        - name: GARAGE_ADMIN_TOKEN
          valueFrom: {{secretKeyRef: {{name: garage-v3-secrets, key: ADMIN_TOKEN}}}}
        ports:
        - {{name: s3, containerPort: 3900}}
        - {{name: rpc, containerPort: 3901}}
        - {{name: admin, containerPort: 3903}}
        readinessProbe:
          tcpSocket: {{port: 3900}}
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests: {{cpu: "100m", memory: "256Mi"}}
          limits: {{cpu: "1", memory: "1Gi"}}
        volumeMounts:
        - {{name: config, mountPath: /etc/garage, readOnly: true}}
        - {{name: data, mountPath: /var/lib/garage}}
      volumes:
      - name: config
        configMap: {{name: garage-v3-{instance}-config}}
      - name: data
        persistentVolumeClaim: {{claimName: garage-v3-{instance}-data}}
"""
    return TMPL.format(api="apps/v1", kind="Deployment", name=name, ns=ns, labels=_labels(), spec=spec)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns", default="mlscan-v3-data")
    ap.add_argument("--nodes", type=int, default=3)
    ap.add_argument("--rf", type=int, default=2)
    ap.add_argument("--capacity", default="10G")
    args = ap.parse_args()
    ns = args.ns
    docs = [f"""\
# --- namespace ---
apiVersion: v1
kind: Namespace
metadata:
  name: {ns}
  labels: {{app.kubernetes.io/part-of: mlscan, mlscan.io/stage: v3}}
"""]
    for i in range(args.nodes):
        docs.append(service(f"garage-v3-{i}", ns, i,
                            "  ports:\n"
                            "  - {name: s3, port: 3900, targetPort: 3900}\n"
                            "  - {name: rpc, port: 3901, targetPort: 3901}\n"
                            "  - {name: admin, port: 3903, targetPort: 3903}\n"))
    for i in range(args.nodes):
        docs.append(configmap(f"garage-v3-{i}-config", ns, i, args.nodes, args.rf))
    for i in range(args.nodes):
        docs.append(pvc(f"garage-v3-{i}-data", ns, args.capacity))
    for i in range(args.nodes):
        docs.append(deployment(f"garage-v3-{i}", ns, i))
    print("---\n".join(d.strip() + "\n" for d in docs))


if __name__ == "__main__":
    main()
