# Образ in-guest eBPF-сенсора БЕЗ root: capabilities выдаются бинарнику python (file caps),
# поэтому процесс стартует non-root, но получает CAP_BPF/CAP_PERFMON в effective-наборе.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

COPY ebpf_agent.py /opt/ebpf/ebpf_agent.py

# проверка интерпретатора ДО setcap (после — python нельзя запускать без CAP_BPF в сборочном окружении)
RUN python -c "import sys; print('python', sys.version.split()[0])"

# file capabilities на интерпретатор: любой запуск python получает BPF/PERFMON (процесс остаётся non-root)
RUN setcap cap_bpf,cap_perfmon+ep /usr/local/bin/python3.12 \
 && getcap /usr/local/bin/python3.12
