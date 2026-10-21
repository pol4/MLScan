# Образ песочницы MLScan (`mlscan-sandbox`)

Специализированный образ для динамического анализа: содержит **PyTorch (CPU)** и типовые
библиотеки сериализации, чтобы payload'ы реальных моделей **достигали исполнения** при
десериализации (в песочнице Kata).

## Состав

- база: `python:3.12-slim`;
- `torch` (CPU) — **2.14.1+cpu**, `numpy` 2.5.4;
- `safetensors`, `onnxruntime` (CPU), `h5py`, `gguf`;
- `joblib`, `dill`, `cloudpickle`.

Тег по умолчанию: **`:v4`** (см. `--image`/`SANDBOX_IMAGE`). В `:v3` добавлены `onnx` и
`PyYAML` (ONNX/конфиги официальными библиотеками), в `:v4` — `pyarrow` (датасеты
Parquet/Arrow/Feather: и генерация примеров, и динамическая загрузка схемы).

## Сборка (Kaniko, без Docker на хосте)

```bash
bash deploy/sandbox-image/build.sh v4       # соберёт и опубликует :v4
kubectl -n mlscan-build logs -f job/mlscan-sandbox-build
```

Kaniko собирает образ и публикует его в **in-cluster registry**:
`registry.container-registry.svc.cluster.local:5000/mlscan-sandbox:v4`,
что соответствует для kubelet `localhost:32000/mlscan-sandbox:v4`
(registry addon MicroK8s).

## Использование

Сервис тестирования создаёт sandbox-Job с образом, задаваемым переменной
`SANDBOX_IMAGE` (см. `deploy/stage2/30-service.yaml`):

```
SANDBOX_IMAGE = localhost:32000/mlscan-sandbox:v4
```

После сборки образа достаточно, чтобы `SANDBOX_IMAGE` указывал на него (уже настроено);
образ подтягивается kubelet'ом (сетевая политика namespace на pull не влияет).

## Эффект

- **Python-2 pickle** (`__builtin__`) — поддержано в harness, payload исполняется.
- **torch-модели** — теперь загружаются (`torch.load(weights_only=False)` внутри песочницы) и
  их payload'ы исполняются. Проверено: `pytorch_model.bin` (265 МБ) → `load.ok=True`,
  `mem_exec=2`, вердикт **Malicious** (ранее — `Dangerous` из-за отсутствия torch).

## Обновление образа

Измените `Dockerfile`, перезапустите `build.sh`; Job перезапускается и публикует новый
`:latest`. Для иммутабельности рекомендуется тегировать по содержимому (`:sha-<hash>`),
подписывать (cosign) и фиксировать digest в `SANDBOX_IMAGE`.
