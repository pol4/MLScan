FROM python:3.12-slim

# Песочница для динамического анализа ML-моделей: torch (CPU) + типовые библиотеки,
# чтобы payload'ы реальных моделей ДОСТИГАЛИ исполнения при десериализации.
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch \
 && pip install --no-cache-dir numpy joblib dill cloudpickle \
    safetensors onnxruntime onnx h5py gguf PyYAML pyarrow \
 && python -c "import torch, numpy, onnxruntime, onnx, h5py, safetensors, yaml, pyarrow; \
print('torch', torch.__version__, 'numpy', numpy.__version__, 'ort', onnxruntime.__version__, \
      'onnx', onnx.__version__)"
