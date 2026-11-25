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
  "common.empty": { ru: "Нет данных", en: "No data" },
  "common.error": { ru: "Ошибка загрузки", en: "Failed to load" },
  "wip": { ru: "Раздел в разработке", en: "Section under construction" },
  "search": { ru: "Поиск (модель, sha…)", en: "Search (model, sha…)" },
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
