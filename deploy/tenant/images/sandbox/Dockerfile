FROM harbor.platform.rtx.local/proxy-dockerhub/library/python:3.12-slim
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch \
 && pip install --no-cache-dir numpy joblib dill cloudpickle safetensors onnxruntime onnx h5py gguf PyYAML pyarrow \
 && python -c "import torch, numpy, onnxruntime, onnx, h5py, safetensors, yaml, pyarrow; print('sandbox deps ok')"
CMD ["python3"]
