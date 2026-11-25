import { createContext, useContext, useEffect, useState, ReactNode } from "react";

type Lang = "ru" | "en";
type Theme = "dark" | "light";
type Density = "comfortable" | "compact";

const DICT: Record<string, { ru: string; en: string }> = {
  "nav.overview": { ru: "Обзор", en: "Overview" },
  "nav.models": { ru: "Модели", en: "Models" },
  "nav.runs": { ru: "Проверки", en: "Runs" },
  "nav.findings": { ru: "Находки", en: "Findings" },
  "nav.policies": { ru: "Политики", en: "Policies" },
  "nav.catalog": { ru: "Каталог", en: "Catalog" },
  "nav.gate": { ru: "Гейт", en: "Gate" },
  "nav.admin": { ru: "Администрирование", en: "Admin" },
  "ov.attention": { ru: "Требует внимания", en: "Needs attention" },
  "ov.kpi.total": { ru: "Артефактов", en: "Artifacts" },
  "ov.kpi.risky": { ru: "Риск/ревью", en: "Risky/review" },
  "ov.kpi.safe": { ru: "Safe", en: "Safe" },
  "ov.kpi.cache": { ru: "Кэш, ГБ", en: "Cache, GB" },
  "col.name": { ru: "Модель", en: "Model" },
  "col.format": { ru: "Формат", en: "Format" },
  "col.verdict": { ru: "Вердикт", en: "Verdict" },
  "col.status": { ru: "Статус", en: "Status" },
  "col.stage": { ru: "Стадия", en: "Stage" },
  "col.engine": { ru: "Движок", en: "Engine" },
  "col.updated": { ru: "Обновлён", en: "Updated" },
  "col.kind": { ru: "Тип", en: "Kind" },
  "col.repo": { ru: "Репозиторий", en: "Repo" },
  "col.progress": { ru: "Прогресс", en: "Progress" },
  "kind.bundle": { ru: "bundle", en: "bundle" },
  "kind.scan": { ru: "скан", en: "scan" },
  "ov.queue": { ru: "Очередь GPU", en: "GPU queue" },
  "ov.downloads": { ru: "HF-загрузки", en: "HF downloads" },
  "ov.recent": { ru: "Последние прогоны", en: "Recent runs" },
  "common.empty": { ru: "Нет данных", en: "No data" },
  "common.error": { ru: "Ошибка загрузки", en: "Failed to load" },
  "wip": { ru: "Раздел в разработке", en: "Section under construction" },
  "search": { ru: "Поиск (модель, sha…)", en: "Search (model, sha…)" },
  "runs.filters": { ru: "Фильтры", en: "Filters" },
  "runs.state": { ru: "Состояние", en: "State" },
  "runs.saved": { ru: "Сохранить вид", en: "Save view" },
  "runs.onlyattn": { ru: "Только риск/сбои", en: "Risk/failed only" },
  "run.open": { ru: "Открыть", en: "Open" },
  "run.tab.summary": { ru: "Сводка", en: "Summary" },
  "run.tab.cases": { ru: "Кейсы", en: "Cases" },
  "run.tab.obs": { ru: "Наблюдение", en: "Observation" },
  "run.tab.evidence": { ru: "Доказательства", en: "Evidence" },
  "run.tab.review": { ru: "Ревью", en: "Review" },
  "run.reason": { ru: "Обоснование", en: "Reason" },
  "run.apply": { ru: "Установить вердикт", en: "Set verdict" },
  "run.export": { ru: "Экспорт CSV", en: "Export CSV" },
  "run.onlyfailed": { ru: "Только не пройденные", en: "Failed only" },
  "col.question": { ru: "Вопрос", en: "Question" },
  "col.answer": { ru: "Ответ", en: "Answer" },
  "col.criticality": { ru: "Крит", en: "Crit" },
  "col.passed": { ru: "Пройден", en: "Passed" },
  "col.flags": { ru: "Флаги", en: "Flags" },
  "col.policy": { ru: "Политика", en: "Policy" },
  "col.coverage": { ru: "Охват", en: "Coverage" },
  "run.manual": { ru: "Ручной вердикт (ревью, admin)", en: "Manual verdict (review, admin)" },
  "nav.compare": { ru: "Сравнение", en: "Compare" },
  "cmp.title": { ru: "Сравнение прогонов и тренды", en: "Run comparison and trends" },
  "cmp.pick": { ru: "Выберите прогоны для сравнения (в «Проверках»)", en: "Pick runs in Runs list" },
  "cmp.metrics": { ru: "Метрики", en: "Metrics" },
  "cmp.diff": { ru: "Дифф кейсов", en: "Case diff" },
  "cmp.trends": { ru: "Тренды по модели", en: "Trends by model" },
  "cmp.model": { ru: "Модель", en: "Model" },
  "cmp.changed": { ru: "Изменилось", en: "Changed" },
  "runs.compare": { ru: "Сравнить", en: "Compare" },
  "nav.upload": { ru: "Загрузка", en: "Upload" },
  "models.title": { ru: "Модели", en: "Models" },
  "model.info": { ru: "Артефакт", en: "Artifact" },
  "model.runs": { ru: "Проверки модели", en: "Model runs" },
  "model.cache": { ru: "Кэш", en: "Cache" },
  "model.run": { ru: "Запустить проверку", en: "Run check" },
  "col.size": { ru: "Размер", en: "Size" },
  "onb.title": { ru: "Загрузка модели", en: "Model upload" },
  "onb.query": { ru: "Поиск на Hugging Face", en: "Search Hugging Face" },
  "onb.search": { ru: "Найти", en: "Search" },
  "onb.download": { ru: "Скачать", en: "Download" },
  "onb.local": { ru: "Локальный файл", en: "Local file" },
  "onb.upload": { ru: "Загрузить", en: "Upload" },
  "onb.engine": { ru: "Движок инференса", en: "Inference engine" },
};

const Ctx = createContext<{ lang: Lang; t: (k: string) => string; setLang: (l: Lang) => void;
  theme: Theme; setTheme: (t: Theme) => void; density: Density; setDensity: (d: Density) => void }>(
  { lang: "ru", t: (k) => k, setLang: () => {}, theme: "dark", setTheme: () => {}, density: "comfortable", setDensity: () => {} });

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLang] = useState<Lang>((localStorage.getItem("mlscan_lang") as Lang) || "ru");
  const [theme, setTheme] = useState<Theme>((localStorage.getItem("mlscan_theme") as Theme) || "dark");
  const [density, setDensity] = useState<Density>((localStorage.getItem("mlscan_density") as Density) || "comfortable");
  useEffect(() => { localStorage.setItem("mlscan_lang", lang); }, [lang]);
  useEffect(() => { localStorage.setItem("mlscan_theme", theme); document.documentElement.dataset.theme = theme; }, [theme]);
  useEffect(() => { localStorage.setItem("mlscan_density", density); document.documentElement.dataset.density = density; }, [density]);
  const t = (k: string) => DICT[k]?.[lang] ?? k;
  return <Ctx.Provider value={{ lang, t, setLang, theme, setTheme, density, setDensity }}>{children}</Ctx.Provider>;
}
export const useI18n = () => useContext(Ctx);
