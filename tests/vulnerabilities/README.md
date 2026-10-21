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
