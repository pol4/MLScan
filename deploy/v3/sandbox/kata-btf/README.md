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

## Минимальный in-guest агент (`ebpf_agent.py`) — статус WIP

Что **работает** (проверено на стенде):
- создание ARRAY-карты, `BPF_PROG_LOAD` программ типа RAW_TRACEPOINT и attach к raw-tracepoint
  `sys_enter` **из гостевой ВМ** (без Torvalds-магии и внешних образов);
- определение номера syscall через `pt_regs` (`orig_ax` = offset 120) и фильтрация по нему —
  хуки `execve` (59) и `connect` (42) срабатывают, счётчики и события пишутся (JSONL + POST `/llm/events`);
- окно `pt_regs` читается `bpf_probe_read_kernel` корректно (проверено дампом: `ax=-38`,
  `si/ip` — user-указатели, `di=-100 (AT_FDCWD)`, `orig_ax=257`).

Что **не получилось** (открытый вопрос для следующего шага):
- `bpf_probe_read_user` по указателю аргумента возвращает `-EFAULT` (14) → строки (путь/адрес)
  пока не извлекаются; сама схема проверена на уровне счётчиков и типов событий.
- Вероятная причина: raw-tracepoint `sys_enter` даёт `pt_regs`-контекст, но в этой сборке чтение
  user-памяти требует иного подхода; надёжный путь — **типизированный tracepoint**
  `syscalls/sys_enter_execve` (`BPF_PROG_TYPE_TRACEPOINT`, смещение `filename` из
  `/sys/kernel/tracing/events/syscalls/sys_enter_execve/format`) с attach через `perf_event_open` +
  `PERF_EVENT_IOC_SET_BPF`. Либо CO-RE (BTF) чтение `task_struct->mm`.
- Слоты карты: 0 = execve, 1 = connect (openat отложен до расширения карты).

Артефакты: `ebpf_agent.py` (агент), `ebpf_smoke.py` (диагностика загрузки/attach), `install.sh` (ядро).
Запуск агента в Job: `runtimeClassName: kata`, образ с python3, caps `[BPF, PERFMON, SYS_RESOURCE]`,
`--out /events/ebpf.jsonl` (общий том) и/или `--post <TESTING_URL>/llm/events --key <key> --scan-id .. --nonce ..`.

## Итог B1 (проверено end-to-end)

| Звено | Статус |
|---|---|
| BTF-ядро в госте (**без** правок containerd и рестарта демонов) | ✅ `install.sh`, обратимо |
| Загрузка/привязка eBPF в госте (RAW_TRACEPOINT `sys_enter`) | ✅ `ebpf_smoke.py` |
| Агент: хуки `execve`/`connect`, атрибуция процесса | ✅ `ebpf_agent.py` (`bpf_get_current_comm`, helper 16) |
| Реальные findings | ✅ `tests/e2e/llm_ebpf_e2e.sh`: in-guest event → `/llm/events` → **`LLM-B-01` (high)** |
| Антиподмена (чужой nonce) | ✅ отклоняется (`rejected=1`) |

Ограничения (осознанные):
- `bpf_probe_read_user` в этом госте даёт `EFAULT` → строки из user-памяти (пути, `sockaddr`) не читаются;
  атрибуция процесса — через `bpf_get_current_comm` (имя процесса), поэтому `LLM-B-01` работает,
  а `LLM-B-02` (внешний egress) требует отдельного источника адреса (kprobe по `tcp_connect`/CO-RE).
- Tetragon не используется: ему нужен `bpffs` в госте (pinning карт) — заменён своим агентом.

Осталось для «продакшн»-включения в песочницу:
1. **Согласовать ослабление PodSecurity в `mlscan-sandbox`** (`restricted` → `baseline`),
   иначе Kubernetes/ Kyverno не пропускает контейнер с caps `BPF/PERFMON`
   (проверено: «would violate PodSecurity restricted … must not include BPF, PERFMON»).
   Готовый манифест: `30-allow-ebpf-agent.yaml` (применять только после согласования).
2. Добавить контейнер `ebpf-agent` в job инференса (образ песочницы по digest, скрипт из ConfigMap,
   общий том событий) — обвязка в `make_llama_test_job`/sandbox job.
3. E2E «инференс на реальной LLM → `LLM-B-*`» в самой песочнице (сейчас E2E агента идёт в `mlscan-build`).

## Внедрение в песочницу (вариант C — согласовано и применено 2026-10-27)

Применено `30-allow-ebpf-agent.yaml`:
- namespace `mlscan-sandbox`: `pod-security.kubernetes.io/enforce: baseline` (audit/warn остаются `restricted`);
- ClusterPolicy `mlscan-ebpf-agent-guard`: (1) контейнеру `ebpf-agent` разрешены **только** `BPF`/`PERFMON`;
  (2) в namespace запрещены опасные capabilities (`SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `NET_RAW`,
  `SYS_MODULE`, `DAC_OVERRIDE`, `SYS_CHROOT`, `MKNOD`, `AUDIT_CONTROL`, `SYS_TIME`) — даже при baseline;
- прежние требования сохраняются: `require-kata-and-digest-image` (образ сканера по digest) и
  `require-hardened-security-context` (non-root, drop ALL, RO-FS, seccomp, без privilege escalation).

Проверено: Job в `mlscan-sandbox` с контейнерами `harness` + `ebpf-agent` (caps `BPF/PERFMON`) —
**допущен**; обычный скан (`tests/e2e/binding_e2e.sh`, sandbox-джоб) — **работает**;
`tests/e2e/llm_ebpf_e2e.sh` — **OK** (`LLM-B-01` из реального in-guest eBPF + антиподмена).

Осталось (следующий шаг): добавить контейнер `ebpf-agent` в job инференса/сканов
(образ песочницы по digest, скрипт из ConfigMap `mlscan-ebpf-agent`, общий том событий,
nonce скана) и E2E «прогон в песочнице → реальные `LLM-B-*`».

## B1 завершён: агент в job'е теста bundle (in-guest наблюдение инференса)

- `LLM_TEST_EBPF=1` (env сервиса) — job теста bundle получает третий контейнер `ebpf-agent`:
  образ python, скрипт из ConfigMap `mlscan-ebpf-agent`, caps `BPF/PERFMON`, тома нет (публикует сам);
- запрос теста может переопределять: `{"gpu": false, "runtime_class": "kata", "ebpf": true}` —
  так E2E гоняет **реальный in-guest** путь (GPU+Kata требует отдельного nvidia-gpu kata-ядра);
- агент публикует события **инкрементально** (дельтами каждые ~3 c) в `/llm/events` по **run-token**
  job'а (не API-ключ) — findings появляются сразу;
- **нюанс сборки**: eBPF в госте этой Kata доступен только **root-в-госте** (non-root с `CAP_BPF`
  получает EPERM — проверено), поэтому агент запускается root в контейнере, а движок и probe остаются
  non-root; под изолирован в микро-ВМ.

Проверка: `tests/e2e/llm_ebpf_inference_e2e.sh` → «B1 llm ebpf inference: OK»: реальный прогон
инференса (llama.cpp CPU, Kata+BTF) → агент → `/llm/events` → **LLM-B-01 (high)**; вердикт bundle
(`Needs review` → `block`) и подписанная аттестация формируются как раньше.
