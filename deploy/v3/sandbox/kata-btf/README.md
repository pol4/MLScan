# B1: BTF-ядро Kata и in-guest eBPF

## Статус (проверено на стенде)

| Шаг | Результат |
|---|---|
| BTF-ядро Kata в каталоге | ✅ `/opt/kata/share/kata-containers/vmlinux-debug.container` (`.BTF` в ELF, `CONFIG_DEBUG_INFO_BTF=y`) |
| Переключение ядра без рестарта демонов | ✅ `kernel = …/vmlinux-debug.container` в активном `configuration.toml`; конфиг читается при создании микро-ВМ |
| BTF в госте | ✅ `/sys/kernel/btf/vmlinux` (5 512 480 байт) внутри Kata-пода |
| Загрузка eBPF в госте | ✅ `BPF_PROG_LOAD` (RAW_TRACEPOINT) + attach raw-tracepoint `sys_enter` — `ebpf_smoke.py` |
| Tetragon как агент | ⛔ упирается в отсутствие `bpffs` в госте (pinning карт в `/sys/fs/bpf`) — нужен `mount -t bpf` (CAP_SYS_ADMIN) или собственный агент |

**Вывод:** B1 разблокирован **без правок containerd и без рестарта демонов**. Для реального наблюдения
используем собственный минимальный in-guest eBPF-агент (развитие `ebpf_smoke.py`), который пишет события
в общий том пода; их читает probe-runner и отправляет в `/llm/events` → маппинг `LLM-B-*`.

## Почему не аннотации

Per-pod аннотация `io.katacontainers.config.hypervisor.kernel` в этой сборке (Kata 3.32 + containerd
MicroK8s) **игнорируется** даже после добавления `kernel` в `enable_annotations` (проверено: qemu
продолжал брать `vmlinux-6.18.35-197`). Альтернатива — отдельный runtime handler с `ConfigPath` —
требует правки `containerd-template.toml` и рестарта containerd, поэтому выбран переключатель ядра
в активном конфиге.

## Установка/откат

```bash
MLSCAN_NODE_SSH=user@node bash deploy/v3/sandbox/kata-btf/install.sh   # бэкап в /var/backups/mlscan/
# откат: восстановить configuration.toml из /var/backups/mlscan/ (kernel = …/vmlinux.container)
```

Диагностика в госте (без внешних образов):

```bash
kubectl -n mlscan-build create configmap kata-btf-ebpf --from-file=ebpf_smoke.py=deploy/v3/sandbox/kata-btf/ebpf_smoke.py
# запустить Job с runtimeClassName=kata, python:3.12-slim, caps [BPF,PERFMON,SYS_RESOURCE], скрипт /opt/ebpf/ebpf_smoke.py
```
