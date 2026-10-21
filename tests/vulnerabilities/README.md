# Синтетический корпус уязвимостей и процедура проверки MLScan

Каталог для воспроизводимой проверки того, **что система действительно обнаруживает**.
Содержит генератор синтетических артефактов по основным классам рисков, ожидаемые чек-иды
и прогонщик, который подаёт образцы в развёрнутую систему и формирует отчёт о детекции.

Все payload'ы **синтетические и безобидные** (echo/id, локальные connect без эффекта);
запускать их следует только через MLScan (в песочнице Kata).

## Состав каталога

```
tests/vulnerabilities/
  gen_corpus.py     # генератор образцов + expected.json
  samples/          # сгенерированные артефакты (38 шт.)
  expected.json     # имя -> {expect_checks:[...], kind: malicious|benign}
  run_tests.py      # прогон корпуса через сервис + отчёт
  README.md         # этот файл (процедура)
  REPORT.md         # результат последнего прогона
```

## Покрываемые классы рисков и образцы

| Класс | Образцы | Ожидаемые чек-иды |
|-------|---------|-------------------|
| pickle RCE | `vuln_pickle_os_system/subprocess/eval/builtins_tamper/network/obfuscated` | `A-01`, `A-05`, `A-20` |
| контейнеры pickle | `vuln_torch_zip`, `vuln_numpy_object`, `vuln_joblib`, `vuln_dill`, `vuln_cloudpickle` | `A-01` |
| model-as-code | `vuln_mar.mar` | `EXEC-01`, `EXEC-02` |
| конфиги/фреймворки | `vuln_auto_map.json`, `vuln_keras.keras`, `vuln_onnx.onnx`, `vuln_hdf5.h5` | `EXEC-04/05/06/07`, `FMT-09` |
| шаблоны/токенизаторы | `vuln_gguf.gguf`, `vuln_tokenizer_config.json`, `vuln_tokenizer_override.json` | `INJ-01`, `BD-02` |
| архивы/парсеры | `vuln_zip_bomb.zip`, `vuln_tar_traversal.tar`, `vuln_tar_symlink.tar`, `vuln_xxe.xml`, `vuln_unsafe_yaml.yaml` | `FMT-03/04/05/06` |
| SafeTensors | `vuln_safetensors_overlap/trailing/nan` | `FMT-02`, `FMT-11`, `BD-01` |
| целостность/SC | `vuln_install_hooks.zip`, `vuln_url_config.json` | `INT-04`, `INT-03` |
| стеганография | `vuln_steg_trailing.zip`, `vuln_steg_blob.json`, `vuln_steg_polyglot.png` | `STEG-01/02/03` |
| prompt-injection/agent | `vuln_prompt_card.md`, `vuln_tools.json`, `vuln_mcp.json` | `INJ-03/04`, `AGT-01` |
| безопасные (контроль) | `safe_pickle_state.pkl`, `safe_config.json`, `safe_safetensors.safetensors`, `safe_card.md`, `safe_image.png` | — (ожидается Safe, без FP) |

## Процедура проверки

### 1. Сгенерировать корпус
```bash
python3 tests/vulnerabilities/gen_corpus.py
# -> samples/ (38 артефактов) + expected.json
```

### 2. Подготовить доступ к развёрнутой системе
Нужны: сервис тестирования (API) и аналитика (для policy-вердикта) + API-ключ.
```bash
# ключ (если не создан): bash deploy/v2/auth/keys.sh  -> /tmp/mlscan-keys.json
KEY=$(python3 -c "import json;print([k for k,v in json.load(open('/tmp/mlscan-keys.json')).items() if v['roles']==['admin']][0])")

# доступ (в кластере сервисы — ClusterIP/Ingress; удобно через port-forward)
kubectl -n mlscan-testing   port-forward svc/mlscan-testing   18080:8080 &
kubectl -n mlscan-analytics port-forward svc/mlscan-analytics 18081:8080 &
```

### 3. Прогнать корпус и получить отчёт
```bash
python3 tests/vulnerabilities/run_tests.py \
  --url http://127.0.0.1:18080 \
  --analytics-url http://127.0.0.1:18081 \
  --key "$KEY" \
  --out tests/vulnerabilities/REPORT.md
```

### 4. Прочитать результат
`REPORT.md` содержит таблицу по каждому образцу (ожидаемые чек-иды, факт обнаружения,
вердикт сервиса, policy-решение) и сводку: **обнаружено N/M malicious**, пропущено,
ложные срабатывания на benign.

Критерий успеха проверки:
- все `vuln_*` определились хотя бы одним ожидаемым чек-идом (`OK`, не `MISS`);
- ни один `safe_*` не получил вердикт `Malicious/Dangerous` и не дал `critical/high` находок.

## Замечания

- `fmt` для образца выбирается по расширению (`pickle/joblib/dill/cloudpickle/numpy/torch/raw`);
  для не-pickle форматов в песочницу идёт `raw` — детектируют статические адаптеры.
- Часть образцов получает статус сервиса `Dangerous`/`Needs review` (статика без
  динамического подтверждения) — это нормально; итоговое блокирование даёт **Policy Engine**
  аналитики (колонка `Policy`).
- Динамическое подтверждение ограничено: pickle/torch/numpy/model-as-code — да;
  Keras/TF/ONNX — только статика (нет фреймворк-образов).


## Дополнительные форматы «Волны 4» (вредоносные и безопасные)

Помимо базового набора корпус содержит примеры форматов, которые часто встречаются в
ML-пайплайнах и редко проверяются сканерами:

| Формат | Вредоносный пример | Безопасный пример |
|--------|--------------------|-------------------|
| Jupyter notebook | `vuln_notebook.ipynb` (код ячеек + injection) | `safe_notebook.ipynb` |
| Скрипты | `vuln_script.sh` (curl\|bash), `vuln_script.ps1` (IEX+DownloadString) | `safe_script.sh` |
| TorchScript/torch.package | `vuln_torchscript_code.pt` (код в `code/`) | `safe_torchscript.pt` (легитимный torch.jit) |
| MLflow-модель | `vuln_mlflow.zip` (python_model + внешний канал) | `safe_mlflow.zip` |
| TF SavedModel | `vuln_savedmodel.zip` (`py_function`) | `safe_savedmodel.zip` |
| TFLite / CoreML | `vuln_tflite.tflite`, `vuln_coreml.mlmodel` (custom-операции) | `safe_tflite.tflite`, `safe_coreml.mlmodel` |
| PMML | `vuln_pmml.pmml` (Extension/Java) | `safe_pmml.pmml` |
| Parquet/Arrow | `vuln_parquet_pickle.parquet` (pickle в метаданных) | `safe_parquet.parquet`, `safe_arrow.arrow` |
| ONNX external_data | `vuln_onnx_external.onnx` (path traversal в `location`) | — |
| HDF5 external link | `vuln_hdf5_extlink.h5` | — |
| safetensors metadata | `vuln_safetensors_meta.safetensors` (`__metadata__` с payload) | — |
| Поведение интерпретатора | `vuln_behavior_state.pkl` (import hooks/env/sys.path) | — |

Вредоносные генерируются [`gen_corpus_extra.py`](./gen_corpus_extra.py) (запускать в образе
песочницы — нужны torch/onnx/h5py/pyarrow), безопасные — `gen_benign_formats.py`.
Проверки: `EXEC-01..07`, `INT-03/04`, `INJ-03`, `F-22/F-24/F-32`, `FMT-09`.

## Доброкачественные примеры сложных форматов

Кроме образцов с закладками корпус содержит **35 безопасных** примеров (`safe_*`) в 28 форматах, в том числе
реальные файлы сложных форматов: safetensors (f32/f16), numpy `.npz`, torch `.pt`, HDF5 `.h5`,
ONNX (MatMul+Add, opset 13), GGUF, Keras `.keras` (zip: `config.json` + `weights.h5`),
архивы `.zip`/`.tar.gz`, joblib/dill/cloudpickle, tokenizer.json, MCP-манифест, YAML/XML-конфиги,
PNG и карточка модели. Они проверяют, что на корректных моделях **нет находок** и динамика
**реально загружает** модель (иначе скан честно помечается как неполный).

Генератор: [`gen_benign_formats.py`](./gen_benign_formats.py) (нужны torch/onnx/h5py/gguf —
запускать в образе песочницы).

```bash
# небольшие примеры -> в репозиторий (samples/)
kubectl -n mlscan-data run gen-benign --rm -i --restart=Never \
  --image=localhost:32000/mlscan-sandbox:v3 --command -- \
  python3 - --out /tmp/benign < tests/vulnerabilities/gen_benign_formats.py

# крупные (≈198 МБ) — генерируются и сразу загружаются в сервис тестирования
kubectl -n mlscan-data exec gen-benign -- python3 /tmp/gen/gen_benign_formats.py \
  --out /tmp/large --large-mb 192 --upload http://<testing>:8080 --key <API_KEY> --verify
```

Крупные примеры (>64 МБ) статика разбирает по префиксу (защита от OOM), а тело загружает
динамика профильными библиотеками (mmap safetensors, onnxruntime, h5py, torch, numpy).
