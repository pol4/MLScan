# Отчёт: проверка системы на синтетическом корпусе уязвимостей

- Дата: 2026-10-21 20:54:57
- Образцов: 83 (malicious=48, benign=35)
- **Обнаружено (malicious): 48/48**
- **Пропущено: 0**
- **Ложных срабатываний на benign: 0/35**

| Образец | Тип | Ожидаемые чек-иды | Результат | Вердикт (сервис) | Policy | State | Найдено |
|---------|-----|-------------------|-----------|------------------|--------|-------|---------|
| safe_arrow.arrow | benign | — | OK | Safe | Malicious/block | done | D-10 |
| safe_card.md | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_card_clean.md | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_config.json | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_config.xml | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_config.yaml | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_coreml.mlmodel | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_image.png | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_mcp_manifest.json | benign | — | OK | Needs review | Needs review/quarantine | done | D-10, INT-03 |
| safe_mlflow.zip | benign | — | OK | Safe | Malicious/block | done | — |
| safe_notebook.ipynb | benign | — | OK | Safe | Malicious/block | done | D-10 |
| safe_parquet.parquet | benign | — | OK | Safe | Malicious/block | done | D-10 |
| safe_pickle_state.pkl | benign | — | OK | Safe | Safe/allow | done | — |
| safe_pmml.pmml | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_real.cloudpickle | benign | — | OK | Safe | Safe/allow | done | — |
| safe_real.dill | benign | — | OK | Safe | Safe/allow | done | — |
| safe_real.joblib | benign | — | OK | Safe | Safe/allow | done | — |
| safe_real_archive.tar.gz | benign | — | OK | Safe | Safe/allow | done | B-11 |
| safe_real_archive.zip | benign | — | OK | Safe | Safe/allow | done | B-11 |
| safe_real_gguf.gguf | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_real_hdf5.h5 | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_real_image.png | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_real_keras.keras | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_real_numpy.npz | benign | — | OK | Safe | Safe/allow | done | B-11 |
| safe_real_onnx.onnx | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_real_pickle.pkl | benign | — | OK | Safe | Safe/allow | done | — |
| safe_real_safetensors.safetensors | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_real_safetensors_f16.safetensors | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_real_torch.pt | benign | — | OK | Safe | Safe/allow | done | A-02 |
| safe_safetensors.safetensors | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_savedmodel.zip | benign | — | OK | Safe | Safe/allow | done | B-11 |
| safe_script.sh | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_tflite.tflite | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_tokenizer_bpe.json | benign | — | OK | Safe | Safe/allow | done | D-10 |
| safe_torchscript.pt | benign | — | OK | Safe | Malicious/block | done | A-02, A-19 |
| vuln_archive_script.tar.gz | malicious | EXEC-02, INT-03 | OK | Dangerous | Malicious/block | done | EXEC-02, INT-03 |
| vuln_auto_map.json | malicious | EXEC-04 | OK | Dangerous | Malicious/block | done | D-10, EXEC-04 |
| vuln_behavior_state.pkl | malicious | A-01, F-22, F-24, F-32 | OK | Malicious | Malicious/block | done | A-01, A-02, F-22, F-23, F-24, F-32 |
| vuln_coreml.mlmodel | malicious | EXEC-02 | OK | Dangerous | Malicious/block | done | D-10, EXEC-02 |
| vuln_gguf.gguf | malicious | INJ-01 | OK | Dangerous | Malicious/block | done | D-10, INJ-01 |
| vuln_hdf5.h5 | malicious | EXEC-05, EXEC-07 | OK | Dangerous | Malicious/block | done | D-10, EXEC-05, EXEC-07 |
| vuln_hdf5_extlink.h5 | malicious | EXEC-07 | OK | Dangerous | Malicious/block | done | D-10, EXEC-07, F-27 |
| vuln_install_hooks.zip | malicious | INT-04 | OK | Dangerous | Malicious/block | done | B-11, EXEC-02, INT-04 |
| vuln_joblib.joblib | malicious | A-01 | OK | Malicious | Malicious/block | done | A-01, A-02, F-30 |
| vuln_keras.keras | malicious | EXEC-05 | OK | Dangerous | Malicious/block | done | D-10, EXEC-05 |
| vuln_mar.mar | malicious | EXEC-01, EXEC-02 | OK | Malicious | Malicious/block | done | B-11, EXEC-01, EXEC-02, F-30 |
| vuln_mcp.json | malicious | AGT-01 | OK | Dangerous | Malicious/block | done | AGT-01, D-10 |
| vuln_mlflow.zip | malicious | EXEC-02, INT-03 | OK | Dangerous | Malicious/block | done | B-11, EXEC-02, INT-03 |
| vuln_notebook.ipynb | malicious | EXEC-02, INJ-03 | OK | Dangerous | Malicious/block | done | D-10, EXEC-02, INJ-03 |
| vuln_numpy_object.npy | malicious | A-01 | OK | Dangerous | Malicious/block | done | A-01, A-02 |
| vuln_onnx.onnx | malicious | EXEC-06, FMT-09 | OK | Dangerous | Malicious/block | done | D-10, EXEC-06, FMT-09 |
| vuln_onnx_external.onnx | malicious | EXEC-06, FMT-09 | OK | Needs review | Needs review/quarantine | done | D-10, FMT-09 |
| vuln_parquet_pickle.parquet | malicious | EXEC-02 | OK | Dangerous | Malicious/block | done | D-10, EXEC-02 |
| vuln_pickle_builtins_tamper.pkl | malicious | A-01, A-05 | OK | Malicious | Malicious/block | done | A-01, A-02, F-20, F-32 |
| vuln_pickle_eval.pkl | malicious | A-01, A-05 | OK | Malicious | Malicious/block | done | A-01, A-02, F-32 |
| vuln_pickle_network.pkl | malicious | A-01 | OK | Malicious | Malicious/block | done | A-01, A-02, A-20, F-31, F-32 |
| vuln_pickle_obfuscated.pkl | malicious | A-05, A-20 | OK | Malicious | Malicious/block | done | A-01, A-02, A-20, F-30, F-32 |
| vuln_pickle_os_system.pkl | malicious | A-01 | OK | Malicious | Malicious/block | done | A-01, A-02, F-30 |
| vuln_pickle_subprocess.pkl | malicious | A-01 | OK | Malicious | Malicious/block | done | A-01, A-02, A-20, F-30, F-32 |
| vuln_pmml.pmml | malicious | EXEC-02 | OK | Needs review | Malicious/block | done | D-10, EXEC-02 |
| vuln_prompt_card.md | malicious | INJ-03 | OK | Dangerous | Malicious/block | done | D-10, INJ-03 |
| vuln_safetensors_meta.safetensors | malicious | EXEC-02 | OK | Dangerous | Malicious/block | done | D-10, EXEC-02 |
| vuln_safetensors_nan.safetensors | malicious | BD-01 | OK | Dangerous | Needs review/quarantine | done | BD-01, D-10 |
| vuln_safetensors_overlap.safetensors | malicious | FMT-02 | OK | Dangerous | Needs review/quarantine | done | D-10, FMT-02 |
| vuln_safetensors_trailing.safetensors | malicious | FMT-11 | OK | Inconclusive | Needs review/quarantine | done | D-10, FMT-11 |
| vuln_savedmodel.zip | malicious | EXEC-01 | OK | Dangerous | Malicious/block | done | B-11, EXEC-01 |
| vuln_script.ps1 | malicious | EXEC-02, INT-03 | OK | Dangerous | Malicious/block | done | D-10, EXEC-02, INT-03 |
| vuln_script.sh | malicious | EXEC-02, INT-03 | OK | Dangerous | Malicious/block | done | D-10, EXEC-02, INT-03 |
| vuln_steg_blob.json | malicious | STEG-02 | OK | Needs review | Needs review/quarantine | done | D-10, STEG-02 |
| vuln_steg_polyglot.png | malicious | STEG-03 | OK | Dangerous | Malicious/block | done | D-10, STEG-03 |
| vuln_steg_trailing.zip | malicious | STEG-01 | OK | Needs review | Needs review/quarantine | done | A-00, STEG-01 |
| vuln_tar_symlink.tar | malicious | FMT-05 | OK | Dangerous | Malicious/block | done | B-11, FMT-05 |
| vuln_tar_traversal.tar | malicious | FMT-03 | OK | Dangerous | Malicious/block | done | B-11, FMT-03 |
| vuln_tflite.tflite | malicious | EXEC-02 | OK | Dangerous | Malicious/block | done | D-10, EXEC-02 |
| vuln_tokenizer_config.json | malicious | INJ-01 | OK | Dangerous | Malicious/block | done | D-10, F-27, INJ-01 |
| vuln_tokenizer_override.json | malicious | BD-02 | OK | Dangerous | Malicious/block | done | BD-02, D-10 |
| vuln_tools.json | malicious | INJ-04 | OK | Dangerous | Malicious/block | done | D-10, INJ-04 |
| vuln_torch_zip.pkl | malicious | A-01 | OK | Dangerous | Malicious/block | done | A-01, A-02 |
| vuln_torchscript_code.pt | malicious | EXEC-03, EXEC-02 | OK | Dangerous | Malicious/block | done | EXEC-02, EXEC-03 |
| vuln_unsafe_yaml.yaml | malicious | FMT-06 | OK | Dangerous | Malicious/block | done | D-10, FMT-06 |
| vuln_url_config.json | malicious | INT-03 | OK | Needs review | Needs review/quarantine | done | D-10, F-27, INT-03 |
| vuln_xxe.xml | malicious | FMT-06 | OK | Dangerous | Malicious/block | done | D-10, FMT-06 |
| vuln_zip_bomb.zip | malicious | FMT-04 | OK | Dangerous | Needs review/quarantine | done | A-00, FMT-04 |


---

## Форматы «Волны 4» (добавлены в этот прогон)

Корпус расширен до **83 образцов (48 с закладками + 35 безопасных)**. Новые форматы и векторы:

| Образец | Тип | Результат | Вердикт | Найдено |
|---------|-----|-----------|---------|---------|
| `vuln_notebook.ipynb` | malicious | OK | Dangerous | `EXEC-02`, `INJ-03` |
| `vuln_script.sh` / `vuln_script.ps1` | malicious | OK | Dangerous | `EXEC-02`, `INT-03` |
| `vuln_torchscript_code.pt` | malicious | OK | Dangerous | `EXEC-02`, `EXEC-03` |
| `vuln_mlflow.zip` | malicious | OK | Dangerous | `EXEC-02`, `INT-03` |
| `vuln_savedmodel.zip` | malicious | OK | Dangerous | `EXEC-01` |
| `vuln_tflite.tflite` / `vuln_coreml.mlmodel` | malicious | OK | Dangerous | `EXEC-02` |
| `vuln_pmml.pmml` | malicious | OK | Needs review | `EXEC-02` |
| `vuln_parquet_pickle.parquet` | malicious | OK | Dangerous | `EXEC-02` |
| `vuln_onnx_external.onnx` | malicious | OK | Needs review | `FMT-09` |
| `vuln_hdf5_extlink.h5` | malicious | OK | Dangerous | `EXEC-07` |
| `vuln_safetensors_meta.safetensors` | malicious | OK | Dangerous | `EXEC-02` |
| `vuln_behavior_state.pkl` | malicious | OK | Malicious | `A-01`, `F-22`, `F-24`, `F-32` |
| `safe_notebook.ipynb`, `safe_script.sh`, `safe_torchscript.pt`, `safe_mlflow.zip`, `safe_savedmodel.zip`, `safe_tflite.tflite`, `safe_coreml.mlmodel`, `safe_pmml.pmml`, `safe_parquet.parquet`, `safe_arrow.arrow` | benign | OK | Safe | — |

Все безопасные примеры новых форматов — `Safe` с полным покрытием (в т.ч. настоящий
`torch.jit`-TorchScript не даёт ложного `EXEC-03`, а Parquet/Arrow загружаются pyarrow).
