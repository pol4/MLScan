# Kata-native CDI GPU device plugin (reference)

Зачем: адвертайзить `nvidia.com/gpu` для vfio-GPU и пробрасывать их в Kata **без** инжекта
контейнерного vfio-устройства. GPU-Operator `nvidia-sandbox-device-plugin` отдаёт 7 container
DeviceSpecs (volume-mounts, KubeVirt-модель) → plain-Kata runtime-rs падает
`initialize vfio device failed: ENOENT`; конфиг `deviceListStrategy` в sandbox-DS не применяется.

Механизм: `Allocate` возвращает **CDI-устройства** (`k8s.io/kubelet .../v1beta1`.CDIDevices).
kubelet ставит аннотации `cdi.k8s.io/*` → containerd/runtime-rs применяет CDI → Kata делает
cold-plug GPU в VM (guest-драйвер в kata-gpu образе).

Требования:
- k8s ≥ 1.29 (CDIDevices в deviceplugin v1beta1); у нас 1.31.14.
- CDI-spec на узле: `/etc/cdi/nvidia-tu104.json`, `kind: nvidia.com/TU104GL_QUADRO_RTX_4000`,
  `devices: [{name: "0000:05:00.0", ...}, {name: "0000:84:00.0", ...}]` (deviceNodes можно оставить
  пустыми/минимальными — Kata резолвит устройство по имени).
- RuntimeClass `kata-gpu` (уже есть), vfio-GPU на узле (уже привязаны).
- Собрать и запушить образ (go build есть в Dockerfile; собирать kaniko/локально), подставить IMAGE
  в `daemonset.yaml`, применить. На узле отключить операторный sandbox-DS
  (`nvidia.com/gpu.deploy.sandbox-device-plugin=false`), чтобы не было конфликта resourceName.

Файлы: `main.go`, `go.mod`, `Dockerfile`, `daemonset.yaml`.

Секретов не содержит. BDF/kind/resourceName при необходимости скорректировать.
