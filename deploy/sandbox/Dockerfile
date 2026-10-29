# Образ песочницы MLScan (Kata): python3.12-slim + зависимости harness.
# Зависимости взяты из HARNESS_SRC (poc/mlscan_poc.py): torch(CPU), numpy, joblib, dill, cloudpickle,
# safetensors, gguf, h5py, pyarrow, onnxruntime. Harness монтируется из ConfigMap в /opt/mlscan.
# Сборка без реестра: kaniko --no-push --tar-path, затем ctr images import в узле (см. deploy/sandbox/build.md).
FROM python:3.12-slim

RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch \
 && pip install --no-cache-dir numpy joblib dill cloudpickle safetensors gguf h5py pyarrow onnxruntime \
 && python -c "import torch, numpy, safetensors, gguf, h5py, pyarrow, onnxruntime; print('sandbox deps ok')"

CMD ["python3"]
