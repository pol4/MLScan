# Образ песочницы MLScan (Kata): python3.12-slim + torch(CPU)/numpy/joblib/dill/cloudpickle.
# Реконструирован из истории собранного образа (deploy/export/snapshot/sandbox-image-history.txt);
# канонический digest стенда — в deploy/export/snapshot/mlscan-sandbox-digest.
# Harness-код в образ НЕ входит: он монтируется из ConfigMap (deploy/stage1/gen_configmaps.py) в /opt/mlscan.
FROM python:3.12-slim

RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch \
 && pip install --no-cache-dir numpy joblib dill cloudpickle \
 && python -c "import torch, numpy; print('torch', torch.__version__, 'numpy', numpy.__version__)"

CMD ["python3"]
