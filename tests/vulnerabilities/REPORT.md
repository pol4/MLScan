# Отчёт: проверка системы на синтетическом корпусе уязвимостей

- Дата: 2026-10-21 09:08:09
- Образцов: 38 (malicious=33, benign=5)
- **Обнаружено (malicious): 33/33**
- **Пропущено: 0**
- **Ложных срабатываний на benign: 0/5**

| Образец | Тип | Ожидаемые чек-иды | Результат | Вердикт (сервис) | Policy | State | Найдено |
|---------|-----|-------------------|-----------|------------------|--------|-------|---------|
| safe_card.md | benign | — | OK | Safe | Safe/allow | done | A-00 |
| safe_config.json | benign | — | OK | Safe | Safe/allow | done | A-00 |
| safe_image.png | benign | — | OK | Safe | Safe/allow | done | A-00 |
| safe_pickle_state.pkl | benign | — | OK | Safe | Safe/allow | done | — |
| safe_safetensors.safetensors | benign | — | OK | Safe | Safe/allow | done | D-10 |
| vuln_auto_map.json | malicious | EXEC-04 | OK | Dangerous | Malicious/block | done | A-00, EXEC-04 |
| vuln_gguf.gguf | malicious | INJ-01 | OK | Dangerous | Malicious/block | done | A-00, INJ-01 |
| vuln_hdf5.h5 | malicious | EXEC-05, EXEC-07 | OK | Dangerous | Malicious/block | done | D-10, EXEC-05, EXEC-07 |
| vuln_install_hooks.zip | malicious | INT-04 | OK | Dangerous | Malicious/block | done | B-11, EXEC-02, INT-04 |
| vuln_joblib.joblib | malicious | A-01 | OK | Malicious | Malicious/block | done | A-01, A-02, F-30 |
| vuln_keras.keras | malicious | EXEC-05 | OK | Dangerous | Malicious/block | done | B-11, EXEC-05 |
| vuln_mar.mar | malicious | EXEC-01, EXEC-02 | OK | Malicious | Malicious/block | done | B-11, EXEC-01, EXEC-02, F-30 |
| vuln_mcp.json | malicious | AGT-01 | OK | Dangerous | Malicious/block | done | A-00, AGT-01 |
| vuln_numpy_object.npy | malicious | A-01 | OK | Malicious | Malicious/block | done | A-01, A-02, F-30 |
| vuln_onnx.onnx | malicious | EXEC-06, FMT-09 | OK | Dangerous | Malicious/block | done | D-10, EXEC-06, FMT-09 |
| vuln_pickle_builtins_tamper.pkl | malicious | A-01, A-05 | OK | Malicious | Malicious/block | done | A-01, A-02, F-20, F-32 |
| vuln_pickle_eval.pkl | malicious | A-01, A-05 | OK | Malicious | Malicious/block | done | A-01, A-02, F-32 |
| vuln_pickle_network.pkl | malicious | A-01 | OK | Malicious | Malicious/block | done | A-01, A-02, A-20, F-31, F-32 |
| vuln_pickle_obfuscated.pkl | malicious | A-05, A-20 | OK | Malicious | Malicious/block | done | A-01, A-02, A-20, F-30, F-32 |
| vuln_pickle_os_system.pkl | malicious | A-01 | OK | Malicious | Malicious/block | done | A-01, A-02, F-30 |
| vuln_pickle_subprocess.pkl | malicious | A-01 | OK | Malicious | Malicious/block | done | A-01, A-02, A-20, F-30, F-32 |
| vuln_prompt_card.md | malicious | INJ-03 | OK | Dangerous | Malicious/block | done | A-00, A-20, INJ-03 |
| vuln_safetensors_nan.safetensors | malicious | BD-01 | OK | Dangerous | Needs review/quarantine | done | BD-01, D-10 |
| vuln_safetensors_overlap.safetensors | malicious | FMT-02 | OK | Dangerous | Needs review/quarantine | done | D-10, FMT-02 |
| vuln_safetensors_trailing.safetensors | malicious | FMT-11 | OK | Needs review | Needs review/quarantine | done | D-10, FMT-11 |
| vuln_steg_blob.json | malicious | STEG-02 | OK | Needs review | Needs review/quarantine | done | A-00, STEG-02 |
| vuln_steg_polyglot.png | malicious | STEG-03 | OK | Dangerous | Malicious/block | done | A-00, A-20, STEG-03 |
| vuln_steg_trailing.zip | malicious | STEG-01 | OK | Needs review | Needs review/quarantine | done | A-00, STEG-01 |
| vuln_tar_symlink.tar | malicious | FMT-05 | OK | Dangerous | Malicious/block | done | A-00, FMT-05 |
| vuln_tar_traversal.tar | malicious | FMT-03 | OK | Dangerous | Malicious/block | done | FMT-03 |
| vuln_tokenizer_config.json | malicious | INJ-01 | OK | Dangerous | Malicious/block | done | A-00, INJ-01 |
| vuln_tokenizer_override.json | malicious | BD-02 | OK | Dangerous | Malicious/block | done | A-00, BD-02 |
| vuln_tools.json | malicious | INJ-04 | OK | Dangerous | Malicious/block | done | A-00, INJ-04 |
| vuln_torch_zip.pkl | malicious | A-01 | OK | Malicious | Malicious/block | done | A-01, A-02, F-30 |
| vuln_unsafe_yaml.yaml | malicious | FMT-06 | OK | Dangerous | Malicious/block | done | A-00, A-20, FMT-06 |
| vuln_url_config.json | malicious | INT-03 | OK | Needs review | Needs review/quarantine | done | A-00, A-20, INT-03 |
| vuln_xxe.xml | malicious | FMT-06 | OK | Dangerous | Malicious/block | done | A-00, FMT-06 |
| vuln_zip_bomb.zip | malicious | FMT-04 | OK | Dangerous | Needs review/quarantine | done | A-00, FMT-04 |
