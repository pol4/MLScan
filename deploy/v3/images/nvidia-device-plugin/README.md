# NVIDIA k8s-device-plugin (сборка из исходников в наш реестр)

Публичный образ плагина публикуется на `nvcr.io` и требует NGC-ключ (анонимный pull → 403), поэтому
плагин собирается из исходников официального репозитория и публикуется в локальный реестр.

- Источник: `https://github.com/NVIDIA/k8s-device-plugin` (тег `v0.17.0`).
- Сборка: kaniko в кластере (namespace `mlscan-build`), свой минимальный Dockerfile
  `Dockerfile.mlscan` (Go-build + `debian:bookworm-slim`), т.к. Dockerfile репозитория базируется на
  nvcr.io/ubi9 (недоступны/не распаковываются в kaniko).
- Публикация: `192.168.20.116:32000/nvidia/k8s-device-plugin:v0.17.0-mlscan`
  (digest `sha256:4d64bbf424f9131fe4c4f366ae49b90dc6dab48af525e259271aea0f7748f02b`).
- Развёртывание: `daemonset.yaml` (namespace `kube-system`), `--mig-strategy=none`,
  `--device-discovery-strategy=nvml`; монтирует `/var/lib/kubelet/device-plugins` и
  `/usr/lib/x86_64-linux-gnu` (для `libnvidia-ml.so.1`).
- Проверка: `kubectl get node -o jsonpath='{.status.allocatable.nvidia\.com/gpu}'` → `3`;
  pod с `resources.limits."nvidia.com/gpu": 1` + `runtimeClassName: nvidia` видит GPU (`nvidia-smi`).

**MIG**: на этом стенде GPU MIG **не поддерживают** (`nvidia-smi --query-gpu=mig.mode.current` → `[N/A]`;
MIG нужен A100/A30/H100 и т.п.), поэтому плагин запускается с `--mig-strategy=none`.

## Воспроизведение

```bash
kubectl apply -f deploy/v3/images/nvidia-device-plugin/build-job.yaml   # сборка+push в локальный реестр
kubectl -n kube-system apply -f deploy/v3/images/nvidia-device-plugin/daemonset.yaml
kubectl get node -o jsonpath='{.status.allocatable.nvidia\.com/gpu}'
```
