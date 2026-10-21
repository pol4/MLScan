#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MLScan i18n — локализация RU/EN для UI, сообщений сервисов и находок.

Только стандартная библиотека. Раскладывается ConfigMap'ом `mlscan-i18n` во все
namespace'ы `mlscan-*` и монтируется в `/opt/i18n` (как `mlscan-authz` → `/opt/auth`).

Уровни выбора языка (от старшего к младшему):
  1. явный запрос: `?lang=xx` (query) или заголовок `X-MLScan-Lang`;
  2. пользовательская настройка: cookie `mlscan_lang` (переключатель в UI);
  3. `Accept-Language` клиента;
  4. ГЛОБАЛЬНАЯ настройка системы: таблица `settings` в PostgreSQL (её меняет
     администратор через UI или `POST /settings/language`), кэш 30 с;
  5. значение при запуске: переменная окружения `MLSCAN_LANG` (ConfigMap/Deployment).

Пункты 4–5 дают «глобально для всей системы»: сообщения всех сервисов возвращаются
на выбранном при запуске языке, а администратор может сменить его на лету.

Две независимые части:
  * `CATALOG` — ключи для UI и собственных сообщений сервисов (`t("ui.overview")`);
  * `_RULES`  — правила перевода «свободных» строк, которые сервисы уже отдали
    как данные (заголовки находок `A-01`/`EXEC-02`/…, `service_reason`, ошибки
    загрузки). Это позволяет показывать в EN в т.ч. ИСТОРИЧЕСКИЕ записи,
    сохранённые в БД/evidence до внедрения i18n.

Канонические идентификаторы (`verdict`, `severity`, `policy.action`, `check_id`)
НЕ переводятся: это машинные значения (по ним фильтруют UI/API и строятся CSS-классы).
"""
from __future__ import annotations

import os
import re
import sys
import threading
import time

SUPPORTED = ("ru", "en")
_DEFAULT = (os.environ.get("MLSCAN_LANG") or "ru").strip().lower()
if _DEFAULT not in SUPPORTED:
    _DEFAULT = "ru"

SETTINGS_KEY = "language"
_CACHE_TTL = 30.0

_lock = threading.Lock()
_cache = {"lang": None, "ts": 0.0}


# ---------------------------------------------------------------------------
# Каталог UI и сообщений сервисов
# ---------------------------------------------------------------------------
CATALOG: dict[str, dict[str, str]] = {
    # --- общая навигация / оболочка страницы
    "ui.brand": {"ru": "MLScan — Analytics", "en": "MLScan — Analytics"},
    "nav.login": {"ru": "вход", "en": "sign in"},
    "nav.logout": {"ru": "выход", "en": "sign out"},
    "nav.json": {"ru": "JSON", "en": "JSON"},
    "nav.evidence": {"ru": "evidence", "en": "evidence"},
    "nav.policy": {"ru": "policy", "en": "policy"},
    "nav.language": {"ru": "Язык", "en": "Language"},
    "nav.lang_ru": {"ru": "Русский", "en": "Russian"},
    "nav.lang_en": {"ru": "Английский", "en": "English"},
    # --- вход
    "login.title": {"ru": "Вход", "en": "Sign in"},
    "login.heading": {"ru": "Вход в MLScan", "en": "Sign in to MLScan"},
    "login.username": {"ru": "Логин", "en": "Username"},
    "login.password": {"ru": "Пароль", "en": "Password"},
    "login.submit": {"ru": "Войти", "en": "Sign in"},
    "login.key_hint": {"ru": "Для CI/скриптов можно войти по API-ключу:",
                       "en": "CI/scripts can sign in with an API key:"},
    "login.key": {"ru": "API-ключ", "en": "API key"},
    "login.key_submit": {"ru": "Войти по ключу", "en": "Sign in with key"},
    "login.session_expired": {"ru": "Сессия истекла — войдите заново",
                              "en": "Your session has expired — please sign in again"},
    "login.err_credentials": {"ru": "Неверный логин или пароль", "en": "Invalid username or password"},
    "login.err_key": {"ru": "Неверный ключ", "en": "Invalid API key"},
    # --- дашборд
    "ui.overview": {"ru": "Обзор", "en": "Overview"},
    "dash.upload": {"ru": "Загрузить модель", "en": "Upload model"},
    "dash.upload_btn": {"ru": "Загрузить и проверить", "en": "Upload and scan"},
    "dash.upload_hint": {"ru": "Поддерживаются большие файлы; формат определяется по расширению.",
                         "en": "Large files are supported; the format is detected by extension."},
    "dash.filter": {"ru": "Фильтр по имени…", "en": "Filter by name…"},
    "dash.all_verdicts": {"ru": "Все вердикты", "en": "All verdicts"},
    "dash.no_verdict": {"ru": "Без вердикта (в процессе)", "en": "No verdict (in progress)"},
    "dash.sort_date_desc": {"ru": "Сортировка: новые сначала", "en": "Sort: newest first"},
    "dash.sort_date_asc": {"ru": "Сортировка: старые сначала", "en": "Sort: oldest first"},
    "dash.sort_size_desc": {"ru": "Сортировка: объём ↓", "en": "Sort: size ↓"},
    "dash.sort_size_asc": {"ru": "Сортировка: объём ↑", "en": "Sort: size ↑"},
    "dash.col.artifact": {"ru": "Артефакт", "en": "Artifact"},
    "dash.col.date": {"ru": "Дата проверки", "en": "Scan date"},
    "dash.col.size": {"ru": "Размер", "en": "Size"},
    "dash.col.progress": {"ru": "Прогресс", "en": "Progress"},
    "dash.col.verdict": {"ru": "Вердикт", "en": "Verdict"},
    "dash.col.score": {"ru": "Скор", "en": "Score"},
    "dash.col.action": {"ru": "Действие", "en": "Action"},
    "dash.total": {"ru": "Всего", "en": "Total"},
    "dash.volume": {"ru": "Объём", "en": "Volume"},
    "dash.shown": {"ru": "Показано: {n} из {m}", "en": "Showing {n} of {m}"},
    "dash.upload_error": {"ru": "Ошибка загрузки", "en": "Upload error"},
    "dash.loading": {"ru": "Загрузка…", "en": "Loading…"},
    "dash.empty": {"ru": "Нет данных", "en": "No data"},
    # --- карточка артефакта
    "art.back": {"ru": "← к обзору", "en": "← back to overview"},
    "art.size": {"ru": "Размер", "en": "Size"},
    "art.bytes": {"ru": "байт", "en": "bytes"},
    "art.risk": {"ru": "Риск-скор", "en": "Risk score"},
    "art.max_severity": {"ru": "max severity", "en": "max severity"},
    "art.policy": {"ru": "Policy", "en": "Policy"},
    "art.timings": {"ru": "Тайминги", "en": "Timings"},
    "art.reason": {"ru": "Причина (сервис)", "en": "Reason (service)"},
    "art.reports": {"ru": "Отчёты", "en": "Reports"},
    "art.col.level": {"ru": "Ур.", "en": "Lvl"},
    "art.col.id": {"ru": "ID", "en": "ID"},
    "art.col.conf": {"ru": "Увер.", "en": "Conf."},
    "art.col.finding": {"ru": "Находка", "en": "Finding"},
    "art.col.evidence": {"ru": "Доказательство", "en": "Evidence"},
    "art.coverage_incomplete": {"ru": "Проверка выполнена не полностью",
                               "en": "The scan is incomplete"},
    "art.coverage_hint": {"ru": "Вердикт отражает только частичный результат.",
                          "en": "The verdict reflects a partial result only."},
    "art.dynamic": {"ru": "Динамический этап (L2/L3)", "en": "Dynamic stage (L2/L3)"},
    "art.dyn.status": {"ru": "Статус", "en": "Status"},
    "art.dyn.load": {"ru": "загрузка", "en": "load"},
    "art.dyn.type": {"ru": "тип", "en": "type"},
    "art.dyn.signals": {"ru": "Сигналы", "en": "Signals"},
    "art.dyn.errors": {"ru": "Ошибки загрузки", "en": "Load errors"},
    "art.running": {"ru": "Проверка выполняется", "en": "Scan in progress"},
    "art.auto_refresh": {"ru": "Страница обновится автоматически, когда результат будет готов.",
                         "en": "This page refreshes automatically once the result is ready."},
    # --- отчёты
    "report.title": {"ru": "MLScan отчёт: {name}", "en": "MLScan report: {name}"},
    "report.scan_id": {"ru": "scan_id", "en": "scan_id"},
    "report.size": {"ru": "Размер", "en": "Size"},
    "report.format": {"ru": "Формат", "en": "Format"},
    "report.verdict": {"ru": "Вердикт", "en": "Verdict"},
    "report.risk": {"ru": "Риск-скор", "en": "Risk score"},
    "report.timings": {"ru": "Тайминги", "en": "Timings"},
    "report.findings": {"ru": "Находки", "en": "Findings"},
    "report.no_findings": {"ru": "Находок нет.", "en": "No findings."},
    "report.col.level": {"ru": "Уровень", "en": "Level"},
    "report.col.id": {"ru": "ID", "en": "ID"},
    "report.col.severity": {"ru": "Severity", "en": "Severity"},
    "report.col.conf": {"ru": "Уверенность", "en": "Confidence"},
    "report.col.finding": {"ru": "Находка", "en": "Finding"},
    # --- настройка языка
    "settings.title": {"ru": "Настройки", "en": "Settings"},
    "settings.language": {"ru": "Язык системы", "en": "System language"},
    "settings.language_hint": {
        "ru": "Глобальный язык сообщений всех сервисов MLScan (для новых и исторических записей).",
        "en": "Global language for messages of all MLScan services (new and historical records)."},
    "settings.save": {"ru": "Сохранить", "en": "Save"},
    "settings.saved": {"ru": "Сохранено: {lang}", "en": "Saved: {lang}"},
    "settings.admin_only": {"ru": "Требуются права администратора", "en": "Administrator rights required"},
    # --- сообщения сервисов
    "msg.unauthorized": {"ru": "требуется аутентификация", "en": "authentication required"},
    "msg.forbidden": {"ru": "недостаточно прав", "en": "insufficient permissions"},
    "msg.not_found": {"ru": "не найдено", "en": "not found"},
    "msg.unknown_format": {"ru": "неизвестный формат", "en": "unknown format"},
    "msg.empty_body_cl": {"ru": "пустое тело (требуется Content-Length)",
                          "en": "empty body (Content-Length required)"},
    "msg.testing_error": {"ru": "ошибка сервиса тестирования: {detail}",
                          "en": "testing service error: {detail}"},
    "msg.local_fallback_unavailable": {"ru": "локальный фолбэк недоступен (RO FS)",
                                       "en": "local fallback unavailable (RO FS)"},
    "msg.format_adapter_error": {"ru": "Ошибка адаптера формата", "en": "Format adapter error"},
    "msg.intel_block": {"ru": "sha256 в списке известных-плохих (threat-intel)",
                        "en": "sha256 is in the known-bad list (threat-intel)"},
    "msg.intel_watch": {"ru": "сработали наблюдения threat-intel: {ids}",
                        "en": "threat-intel watch hits: {ids}"},
    "msg.policy_review": {"ru": "policy quarantine: требуется разбор",
                          "en": "policy quarantine: manual review required"},
    "msg.scan_timeout": {"ru": "таймаут сканирования", "en": "scan timeout"},
    "msg.not_registered": {"ru": "артефакт не зарегистрирован", "en": "artifact is not registered"},
    "msg.need_sha_or_name": {"ru": "укажите sha256 или name", "en": "provide sha256 or name"},
    "msg.alert_pg_down": {"ru": "PostgreSQL недоступен", "en": "PostgreSQL is unavailable"},
    "msg.alert_s3_down": {"ru": "S3 (Garage) недоступен", "en": "S3 (Garage) is unavailable"},
    "msg.alert_db_size": {"ru": "Размер БД {size} превышает порог",
                          "en": "Database size {size} exceeds the threshold"},
    "msg.alert_evidence_broken": {"ru": "Нарушена целостность evidence: {ev}",
                                  "en": "Evidence integrity violated: {ev}"},
    "msg.alert_evidence_unchecked": {"ru": "Не удалось проверить evidence",
                                     "en": "Failed to verify evidence"},
}


# ---------------------------------------------------------------------------
# Правила перевода «свободных» строк (находки, причины, ошибки загрузки)
# ---------------------------------------------------------------------------
def _r(pat: str, en: str) -> tuple[re.Pattern, str]:
    return re.compile(pat), en


_RULES: list[tuple[re.Pattern, str]] = [
    # --- A-* (статика pickle)
    _r(r"Некорректный/незавершённый pickle \((.+)\)", "Malformed/truncated pickle ({0})"),
    _r(r"Опасный глобал (.+) \((.+)\)", "Dangerous global {0} ({1})"),
    _r(r"Неизвестный глобал (.+) \((.+)\)", "Unknown global {0} ({1})"),
    _r(r"Вызовы при десериализации с опасными глобалами \((.+)\)",
       "Calls on deserialization with dangerous globals ({0})"),
    _r(r"Вызовы при десериализации \((.+)\) — без опасных глобалов",
       "Calls on deserialization ({0}) — no dangerous globals"),
    _r(r"Подозрительная подстрока «(.+)» \((.+)\) в (.+)",
       "Suspicious substring “{0}” ({1}) in {2}"),
    # --- B-*/D-* (контейнеры)
    _r(r"Не удалось открыть zip-контейнер", "Failed to open zip container"),
    _r(r"Подозрительный путь в архиве: (.+)", "Suspicious path in archive: {0}"),
    _r(r"Не удалось прочитать член (.+)", "Failed to read member {0}"),
    _r(r"Формат (.+) не является pickle; десериализация pickle не применима",
       "Format {0} is not pickle; pickle deserialization does not apply"),
    _r(r"Zip-контейнер без распознанных pickle-членов",
       "Zip container without recognized pickle members"),
    # --- F-* (динамика/поведение)
    _r(r"Запуск внешних процессов/команд при загрузке \(×(\d+)\)",
       "External process/command execution on load (×{0})"),
    _r(r"Сетевые обращения при загрузке \(×(\d+)\)", "Network access on load (×{0})"),
    _r(r"Исполнение кода в памяти \(exec\) при загрузке \(×(\d+)\)",
       "In-memory code execution (exec) on load (×{0})"),
    _r(r"Запись файлов при загрузке \(×(\d+)\)", "File writes on load (×{0})"),
    _r(r"Модификация builtins при загрузке: (.+)", "builtins modified on load: {0}"),
    _r(r"Удалены элементы builtins: (.+)", "builtins entries removed: {0}"),
    _r(r"Подмена механизма импорта \(sys.meta_path/path_hooks\)",
       "Import machinery hijacked (sys.meta_path/path_hooks)"),
    _r(r"Изменён sys.path при загрузке", "sys.path changed on load"),
    _r(r"Изменено окружение процесса: (.+)", "Process environment changed: {0}"),
    _r(r"Изменён рабочий каталог", "Working directory changed"),
    _r(r"Модификация builtins во время вызова модели", "builtins modified during model call"),
    _r(r"Подозрительные строки в загруженном объекте: (.+)",
       "Suspicious strings in the loaded object: {0}"),
    # --- причины вердикта (service_reason) и их фрагменты
    _r(r"Максимальная серьёзность (.+?); динамика: (.*); поведенческие находки: (.*)",
       "Max severity {0}; dynamics: {1!tr}; behavioral findings: {2}"),
    _r(r"Максимальная серьёзность (.+?); динамика: (.+)",
       "Max severity {0}; dynamics: {1!tr}"),
    _r(r"Опасные конструкции уровня (.+?): (.+) — требуется ручное подтверждение",
       "Dangerous constructs of level {0}: {1!tr} — manual confirmation required"),
    _r(r"Опасные конструкции уровня (.+) — требуется ручное подтверждение",
       "Dangerous constructs of level {0} — manual confirmation required"),
    _r(r"попытки сетевого доступа: (\d+)", "network access attempts: {0}"),
    _r(r"запуск процессов/команд: (\d+)", "process/command execution: {0}"),
    _r(r"исполнение кода в памяти \(exec <string>\): (\d+)",
       "in-memory code execution (exec <string>): {0}"),
    _r(r"загрузка нативных библиотек \(ctypes\): (\d+)", "native library loads (ctypes): {0}"),
    _r(r"запись файлов: (\d+)", "file writes: {0}"),
    _r(r"поведенческие находки: (.+)", "behavioral findings: {0}"),
    _r(r"динамика не выполнена \(нет Docker\)", "dynamics not run (no Docker)"),
    _r(r"превышен таймаут \(возможный DoS/бесконечный цикл\)",
       "timeout exceeded (possible DoS/infinite loop)"),
    _r(r"динамический этап не выполнялся", "dynamic stage was not executed"),
    _r(r"динамический этап завершился без результата", "dynamic stage finished without a result"),
    _r(r"динамический этап выполнен, но жёстких сигналов исполнения \(процессы/сеть/exec\) не зафиксировано",
       "dynamic stage completed but no hard execution signals (processes/network/exec) were observed"),
    _r(r"Только статика: динамика недоступна; неполное покрытие",
       "Static only: dynamics unavailable; incomplete coverage"),
    _r(r"Находки среднего уровня", "Medium-severity findings"),
    _r(r"Опасных признаков не обнаружено", "No dangerous indicators found"),
    _r(r"Динамика: (.+)", "Dynamics: {0!tr}"),
    # --- полнота покрытия (модули проверки)
    _r(r"проверить всеми модулями не получилось \((.+)\); частичный результат: (.+)",
       "not all verification modules could run ({0!tr}); partial result: {1!tr}"),
    _r(r"проверка неполная \((.+)\)", "incomplete scan ({0!tr})"),
    _r(r"статика: (.+)", "static analysis: {0!tr}"),
    _r(r"динамика: (.+)", "dynamic analysis: {0!tr}"),
    _r(r"поведение: (.+)", "behaviour: {0!tr}"),
    _r(r"статика", "static analysis"),
    _r(r"динамика", "dynamic analysis"),
    _r(r"поведение", "behaviour"),
    _r(r"пропущено \(модель не загружена\)", "skipped (model not loaded)"),
    _r(r"пропущено \(динамика недоступна\)", "skipped (dynamic analysis unavailable)"),
    _r(r"модель не загружена", "model not loaded"),
    _r(r"probe не выполнен", "probe not executed"),
    _r(r"не выполнялась \(нет Docker\)", "not run (no Docker)"),
    _r(r"не выполнялась", "not run"),
    _r(r"динамический этап не выполнялся", "dynamic stage was not executed"),
    _r(r"не удалось загрузить модель: (.+)", "failed to load the model: {0}"),

    # --- ошибки загрузки в песочнице
    _r(r"model-as-code: entry-код не найден", "model-as-code: entry code not found"),
    _r(r"(.+) не установлен", "{0} is not installed"),
    _r(r"docker daemon недоступен", "docker daemon unavailable"),
    _r(r"docker недоступен: (.+)", "docker unavailable: {0}"),
    _r(r"не удалось запустить контейнер: (.+)", "failed to start container: {0}"),
    # --- детекторы форматов (EXEC/INJ/AGT/BD/FMT/INT/STEG)
    _r(r"Python-код в артефакте \((.+)\)", "Python code in artifact ({0})"),
    _r(r"Python-код внутри контейнера \((.+)\)", "Python code inside container ({0})"),
    _r(r"Ссылка на удалённый код \(auto_map/trust_remote_code\) в (.+)",
       "Remote-code reference (auto_map/trust_remote_code) in {0}"),
    _r(r"Keras Lambda/custom_objects в (.+)", "Keras Lambda/custom_objects in {0}"),
    _r(r"TorchServe \.mar с handler-кодом \(исполнение при serve\)",
       "TorchServe .mar with handler code (executed on serve)"),
    _r(r"torch\.package/TorchScript с кодом внутри архива",
       "torch.package/TorchScript with code inside the archive"),
    _r(r"HDF5: признаки Lambda/__reduce__/external \((.+)\)",
       "HDF5: Lambda/__reduce__/external indicators ({0})"),
    _r(r"HDF5: внешние ссылки \((.+)\)", "HDF5: external links ({0})"),
    _r(r"ONNX external_data \((.+)\) — риск path traversal/URL",
       "ONNX external_data ({0}) — path traversal/URL risk"),
    _r(r"ONNX custom/contrib ops \((.+)\)", "ONNX custom/contrib ops ({0})"),
    _r(r"ONNX external location \((.+)\)", "ONNX external location ({0})"),
    _r(r"Опасные конструкции в Jinja chat_template \((.+)\)",
       "Dangerous constructs in Jinja chat_template ({0})"),
    _r(r"Найден chat_template \((.+)\) — требуется проверка",
       "chat_template found ({0}) — review required"),
    _r(r"GGUF chat_template с опасными конструкциями \((.+)\)",
       "GGUF chat_template with dangerous constructs ({0})"),
    _r(r"GGUF chat_template присутствует \((.+)\)", "GGUF chat_template present ({0})"),
    _r(r"Повреждённый zip-контейнер", "Corrupted zip container"),
    _r(r"Повреждённый tar-архив", "Corrupted tar archive"),
    _r(r"SafeTensors: файл слишком мал \((.+)\)", "SafeTensors: file too small ({0})"),
    _r(r"SafeTensors: некорректная длина заголовка \((.+)\)",
       "SafeTensors: invalid header length ({0})"),
    _r(r"SafeTensors: нечитаемый заголовок \((.+)\)", "SafeTensors: unreadable header ({0})"),
    _r(r"SafeTensors: выход за границы тензора (.+) \((.+)\)",
       "SafeTensors: tensor out of bounds {0} ({1})"),
    _r(r"SafeTensors: перекрытие тензоров \((.+)\)", "SafeTensors: overlapping tensors ({0})"),
    _r(r"overlap (.+) и (.+)", "overlap {0} and {1}"),
    _r(r"(\d+) лишних байт", "{0} extra bytes"),
    _r(r"SafeTensors: trailing-данные после тензоров \((.+)\)",
       "SafeTensors: trailing data after tensors ({0})"),
    _r(r"Веса: NaN/Inf в тензоре (.+) \((.+)\)", "Weights: NaN/Inf in tensor {0} ({1})"),
    _r(r"Веса: экстремальные значения в тензоре (.+) \((.+)\)",
       "Weights: extreme values in tensor {0} ({1})"),
    _r(r"Архив содержит install-файлы \((.+)\)", "Archive contains install files ({0})"),
    _r(r"Zip: данные после EOCD \((\d+) байт\)", "Zip: data after EOCD ({0} bytes)"),
    _r(r"Zip: подозрительный путь \((.+)\)", "Zip: suspicious path ({0})"),
    _r(r"Zip: высокая степень сжатия \(bomb\)", "Zip: high compression ratio (bomb)"),
    _r(r"Tar: подозрительный путь \((.+)\)", "Tar: suspicious path ({0})"),
    _r(r"Tar: ссылка/жёсткая ссылка \((.+)\)", "Tar: link/hardlink ({0})"),
    _r(r"Tar: чрезмерный суммарный размер \(bomb\)", "Tar: excessive total size (bomb)"),
    _r(r"XML: DOCTYPE/ENTITY \(XXE\) в (.+)", "XML: DOCTYPE/ENTITY (XXE) in {0}"),
    _r(r"YAML: unsafe-тег \((.+)\) в (.+)", "YAML: unsafe tag ({0}) in {1}"),
    _r(r"Токенизатор: переопределение спец-токенов \((.+)\)",
       "Tokenizer: special-token overrides ({0})"),
    _r(r"Токенизатор: потенциальный ReDoS-regex \((.+)\)",
       "Tokenizer: potential ReDoS regex ({0})"),
    _r(r"Prompt-injection в карточке/документе \((.+)\)", "Prompt injection in card/document ({0})"),
    _r(r"Скрытые HTML-комментарии с инструкциями \((.+)\)",
       "Hidden HTML comments with instructions ({0})"),
    _r(r"HTML/JS в документе \((.+)\) — XSS при рендере",
       "HTML/JS in document ({0}) — XSS on render"),
    _r(r"Сетевые ссылки в карточке \((.+)\)", "Network links in card ({0})"),
    _r(r"MCP/agent-манифест с запуском команд \((.+)\)",
       "MCP/agent manifest with command execution ({0})"),
    _r(r"Tool-схема с подозрительными описаниями \((.+)\)",
       "Tool schema with suspicious descriptions ({0})"),
    _r(r"Внешние URL в конфиге/метаданных \((.+)\)", "External URLs in config/metadata ({0})"),
    _r(r"Высокоэнтропийная строка в метаданных \((.+)\)",
       "High-entropy string in metadata ({0})"),
    _r(r"Изображение содержит pickle-поток \((.+)\)", "Image contains a pickle stream ({0})"),
    _r(r"Изображение является zip-контейнером \((.+)\)", "Image is a zip container ({0})"),
    _r(r"Model-as-code артефакт \((.+)\)", "Model-as-code artifact ({0})"),
    _r(r"Ошибка разбора (.+)", "Parse error {0}"),
    _r(r"Несоответствие расширения и формата: (.+) -> (.+)",
       "Extension/format mismatch: {0} -> {1}"),
    # --- доказательства детекторов (короткие русские подписи)
    _r(r"code/ или constants\.pkl", "code/ or constants.pkl"),
    _r(r"install hooks могут выполнять код при установке",
       "install hooks may execute code on install"),
    _r(r"внешний источник может подтягивать код/данные",
       "external source may pull code/data"),
    _r(r"исполняемый артефакт", "executable artifact"),
    _r(r"нет data\.pkl/\*\.pkl", "no data.pkl/*.pkl"),
]


# ---------------------------------------------------------------------------
# Выбор языка
# ---------------------------------------------------------------------------
def normalize(lang: str | None) -> str | None:
    if not lang:
        return None
    tag = str(lang).strip().lower().replace("_", "-")
    base = tag.split("-", 1)[0].split(",", 1)[0].split(";", 1)[0].strip()
    return base if base in SUPPORTED else None


def startup_lang() -> str:
    """Язык, выбранный при запуске сервиса (`MLSCAN_LANG`, по умолчанию `ru`)."""
    return _DEFAULT


# --- глобальная настройка в PostgreSQL (таблица settings) -------------------
_pg_mod = None
_pg_tried = False


def _pg():
    global _pg_mod, _pg_tried
    if not _pg_tried:
        _pg_tried = True
        if os.environ.get("PGHOST"):
            try:
                sys.path.insert(0, "/opt/pg")
                import pgclient  # type: ignore  # noqa: PLC0415
                _pg_mod = pgclient
            except Exception:  # noqa: BLE001
                _pg_mod = None
    return _pg_mod


def _db_call(sql: str):
    mod = _pg()
    if mod is None:
        return None
    try:
        c = mod.Pg(os.environ["PGHOST"], int(os.environ.get("PGPORT", "5432")),
                   os.environ.get("PGUSER", "mlscan"), os.environ.get("PGPASSWORD", ""),
                   os.environ.get("PGDATABASE", "mlscan"), timeout=10)
        c.connect()
        _cols, rows = c.query(sql)
        c.close()
        return rows
    except Exception:  # noqa: BLE001
        return None


def _db_exec(sql: str) -> bool:
    mod = _pg()
    if mod is None:
        return False
    try:
        c = mod.Pg(os.environ["PGHOST"], int(os.environ.get("PGPORT", "5432")),
                   os.environ.get("PGUSER", "mlscan"), os.environ.get("PGPASSWORD", ""),
                   os.environ.get("PGDATABASE", "mlscan"), timeout=10)
        c.connect()
        c.query(sql)
        c.close()
        return True
    except Exception:  # noqa: BLE001
        return False


def global_lang() -> str:
    """Глобальный язык системы: настройка в БД, иначе значение при запуске."""
    now = time.time()
    with _lock:
        if _cache["lang"] and now - _cache["ts"] < _CACHE_TTL:
            return _cache["lang"]
    lang = None
    rows = _db_call("SELECT value FROM settings WHERE key='language'")
    if rows:
        lang = normalize(rows[0][0])
    if lang is None:
        lang = startup_lang()
    with _lock:
        _cache["lang"] = lang
        _cache["ts"] = now
    return lang


def _settings_upsert(lang: str) -> bool:
    sql = ("INSERT INTO settings(key,value,updated_at) VALUES "
           f"('{SETTINGS_KEY}','{lang}',now()) "
           "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()")
    if _db_exec(sql):
        return True
    # таблицы может не быть на БД, инициализированной до внедрения i18n
    if _db_exec("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, "
                "updated_at TIMESTAMPTZ NOT NULL DEFAULT now())"):
        return _db_exec(sql)
    return False


def set_global_lang(lang: str) -> str:
    """Сохраняет глобальный язык (администратор). Возвращает применённое значение."""
    norm = normalize(lang)
    if norm is None:
        return global_lang()
    _settings_upsert(norm)
    with _lock:
        _cache["lang"] = norm
        _cache["ts"] = time.time()
    return norm


def from_headers(headers) -> str | None:
    """Явный заголовок клиента `X-MLScan-Lang` (язык API-запроса)."""
    if headers is None:
        return None
    get = getattr(headers, "get", None)
    if get is None:
        return None
    return normalize(get("X-MLScan-Lang"))


def from_accept_language(headers) -> str | None:
    """Язык браузера — только как последний резерв (ниже глобальной настройки)."""
    if headers is None:
        return None
    get = getattr(headers, "get", None)
    if get is None:
        return None
    return normalize(get("Accept-Language"))


def from_query(query: dict | None) -> str | None:
    if not query:
        return None
    v = query.get("lang")
    if isinstance(v, (list, tuple)):
        v = v[-1] if v else None   # при дублировании параметра побеждает последний
    return normalize(v)


def from_cookie(cookie: str | None) -> str | None:
    """Язык из cookie. Принимает и заголовок Cookie целиком, и уже извлечённое значение."""
    if not cookie:
        return None
    s = str(cookie)
    for part in s.split(";"):
        k, _, v = part.strip().partition("=")
        if k == "mlscan_lang":
            return normalize(v)
    return normalize(s)   # передано само значение (например, "en")


def resolve(headers=None, query: dict | None = None, cookie: str | None = None) -> str:
    """Язык ответа.

    Приоритет: явный запрос (`?lang=`) → заголовок `X-MLScan-Lang` → cookie
    переключателя → **глобальная настройка системы** (БД, иначе `MLSCAN_LANG`).
    Язык браузера (`Accept-Language`) учитывается только как последний резерв:
    выбранный для системы язык не должен перебиваться настройками клиента.
    """
    return (from_query(query) or from_headers(headers) or from_cookie(cookie)
            or global_lang() or from_accept_language(headers) or startup_lang())


# ---------------------------------------------------------------------------
# Перевод
# ---------------------------------------------------------------------------
def t(key: str, lang: str | None = None, **fmt) -> str:
    """Строка каталога по ключу. Неизвестный ключ возвращается как есть."""
    lg = normalize(lang) or global_lang()
    entry = CATALOG.get(key)
    if not entry:
        return key
    text = entry.get(lg) or entry.get("ru") or key
    if fmt:
        try:
            return text.format(**fmt)
        except Exception:  # noqa: BLE001
            return text
    return text


def _fmt_template(tpl: str, groups: tuple, lang: str) -> str:
    def sub(m: re.Match) -> str:
        i = int(m.group(1))
        val = groups[i] if i < len(groups) and groups[i] is not None else ""
        return tr_list(val, lang) if m.group(2) else str(val)

    return re.sub(r"\{(\d+)(!tr)?\}", sub, tpl)


def _has_cyrillic(text) -> bool:
    return bool(re.search(r"[А-Яа-яЁё]", str(text or "")))


def tr_phrase(text, lang: str | None = None) -> str:
    """Перевод составной фразы: целое → части через «; » → «подпись: число»."""
    if text is None:
        return text
    s = str(text)
    whole = tr(s, lang)
    if not _has_cyrillic(whole):
        return whole
    parts = re.split(r";\s+", s)
    if len(parts) > 1:
        return "; ".join(tr_phrase(p, lang) for p in parts)
    label, sep, num = s.rpartition(": ")
    if sep and not _has_cyrillic(num):
        return tr(label, lang) + sep + num
    return whole


def tr_list(text, lang: str | None = None) -> str:
    """Перевод составного значения: сначала целая фраза, затем части через «, »."""
    if text is None:
        return text
    s = str(text)
    whole = tr_phrase(s, lang)
    if not _has_cyrillic(whole):
        return whole
    if ", " not in s:
        return whole
    return ", ".join(tr_phrase(p, lang) for p in s.split(", "))


def _catalog_rule(ru: str, en: str) -> tuple[re.Pattern, str]:
    """Строит правило из пары каталога: {name}-плейсхолдеры → группы захвата."""
    ru_parts = re.split(r"\{(\w+)\}", ru)
    rx = "".join(re.escape(p) if i % 2 == 0 else "(.*?)" for i, p in enumerate(ru_parts))
    order = [p for i, p in enumerate(ru_parts) if i % 2]
    tpl = []
    for i, p in enumerate(re.split(r"\{(\w+)\}", en)):
        if i % 2 == 0:
            tpl.append(p.replace("{", "{{").replace("}", "}}"))
        else:
            tpl.append("{%d}" % (order.index(p) if p in order else 0))
    return re.compile(rx), "".join(tpl)


for _k, _v in CATALOG.items():
    if _k.startswith("msg.") and _v.get("ru") and _v.get("en") and _v["ru"] != _v["en"]:
        _RULES.append(_catalog_rule(_v["ru"], _v["en"]))


def tr(text, lang: str | None = None):
    """Переводит «свободную» строку (находка, причина, ошибка) по правилам."""
    if text is None:
        return text
    lg = normalize(lang) or global_lang()
    if lg == "ru":
        return text
    s = str(text)
    for rx, tpl in _RULES:
        m = rx.fullmatch(s)
        if m:
            return _fmt_template(tpl, m.groups(), lg)
    return s


def finding_title(finding: dict, lang: str | None = None) -> str:
    """Локализованный заголовок находки (dict или объект с title)."""
    if isinstance(finding, dict):
        title = finding.get("title")
    else:
        title = getattr(finding, "title", None)
    return tr(title, lang)


def finding_evidence(finding: dict, lang: str | None = None) -> str:
    if isinstance(finding, dict):
        ev = finding.get("evidence")
    else:
        ev = getattr(finding, "evidence", None)
    return tr(ev, lang)


def localize_findings(findings, lang: str | None = None) -> list[dict]:
    """Копии находок с локализованными title/evidence (для UI/отчётов)."""
    out = []
    for f in findings or []:
        d = dict(f) if isinstance(f, dict) else dict(getattr(f, "__dict__", {}))
        d["title"] = finding_title(f, lang)
        if d.get("evidence"):
            d["evidence"] = finding_evidence(f, lang)
        out.append(d)
    return out


def lang_options() -> list[dict]:
    return [{"code": c, "label": t(f"nav.lang_{c}", c)} for c in SUPPORTED]
