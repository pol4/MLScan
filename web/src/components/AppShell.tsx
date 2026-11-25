import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useI18n } from "../i18n";

const NAV: { to: string; key: string }[] = [
  { to: "/", key: "nav.overview" },
  { to: "/models", key: "nav.models" },
  { to: "/onboarding", key: "nav.upload" },
  { to: "/runs", key: "nav.runs" },
  { to: "/compare", key: "nav.compare" },
  { to: "/findings", key: "nav.findings" },
  { to: "/policies", key: "nav.policies" },
  { to: "/catalog", key: "nav.catalog" },
  { to: "/gate", key: "nav.gate" },
  { to: "/admin", key: "nav.admin" },
];

export default function AppShell() {
  const { t, lang, setLang, theme, setTheme, density, setDensity } = useI18n();
  const nav = useNavigate();
  return (
    <div style={{ minHeight: "100%" }}>
      <header style={{ display: "flex", alignItems: "center", gap: 12, padding: "12px 20px",
        background: "var(--bg-elev)", borderBottom: "1px solid var(--border)", position: "sticky", top: 0, zIndex: 5 }}>
        <strong style={{ fontSize: 18 }}>MLScan</strong>
        <input placeholder={t("search")} aria-label={t("search")} onKeyDown={(e) => { if (e.key === "Enter") nav(`/models?q=${encodeURIComponent((e.target as HTMLInputElement).value)}`); }}
          style={{ flex: "0 1 360px", background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 10px" }} />
        <div style={{ marginLeft: "auto", display: "flex", gap: 10, alignItems: "center", color: "var(--fg-soft)" }}>
          <a href="/legacy" title="старый интерфейс">legacy</a>
          <select aria-label="lang" value={lang} onChange={(e) => setLang(e.target.value as any)}
            style={{ background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 6 }}>
            <option value="ru">RU</option><option value="en">EN</option></select>
          <select aria-label="density" value={density} onChange={(e) => setDensity(e.target.value as any)}
            style={{ background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 6 }}>
            <option value="comfortable">Comfort</option><option value="compact">Compact</option></select>
          <button onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label="theme"
            style={{ background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 6, padding: "5px 9px" }}>
            {theme === "dark" ? "☾" : "☀"}</button>
        </div>
      </header>
      <div style={{ display: "flex", minHeight: "calc(100vh - 53px)" }}>
        <nav aria-label="main" style={{ width: 220, borderRight: "1px solid var(--border)", padding: 12, flex: "0 0 auto" }}>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"}
              style={({ isActive }) => ({ display: "block", padding: "8px 10px", borderRadius: "var(--radius-sm)", marginBottom: 4,
                color: isActive ? "var(--accent)" : "var(--fg)", background: isActive ? "var(--accent-bg)" : "transparent" })}>
              {t(n.key)}
            </NavLink>))}
        </nav>
        <main style={{ flex: 1, padding: 20, minWidth: 0 }}><Outlet /></main>
      </div>
    </div>
  );
}
