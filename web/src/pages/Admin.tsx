import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Card, EmptyState } from "../components/ui";
import { useI18n } from "../i18n";

export default function Admin() {
  const { t } = useI18n();
  const judge = useQuery({ queryKey: ["judge"], queryFn: () => api<any>("/v4/judge"), retry: false });
  const imgs = useQuery({ queryKey: ["images"], queryFn: () => api<any>("/images/list"), retry: false });
  const engines = ((imgs.data?.images as any[]) || []).filter((i) => (i.type || "") === "llm");

  const [engine, setEngine] = useState("");
  const [model, setModel] = useState("");
  const [min, setMin] = useState("0.6");
  const [template, setTemplate] = useState("Оцени ответ 0..1 относительно вопроса и эталона.");
  const [enabled, setEnabled] = useState(false);
  const [msg, setMsg] = useState("");
  useEffect(() => {
    const c = judge.data?.config;
    if (c && Object.keys(c).length) {
      setEngine(c.engine || ""); setModel(c.model || ""); setMin(String(c.min ?? "0.6"));
      setTemplate(c.template || template); setEnabled(!!c.enabled);
    }
  }, [judge.data]); // eslint-disable-line react-hooks/exhaustive-deps

  const save = async () => {
    setMsg("сохранение…");
    try { await api("/v4/judge", { method: "POST", body: JSON.stringify({ engine, model, min: Number(min), template, enabled }) });
      setMsg("сохранено (применение судьи в скоринге — точка расширения)"); judge.refetch();
    } catch (e) { setMsg("ERR " + String((e as any)?.message || e)); }
  };

  return (
    <div>
      <Card title={t("admin.title")}>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <Link to="/policies">{t("pol.title")}</Link>
          <Link to="/catalog">{t("nav.catalog")}</Link>
        </div>
      </Card>

      <Card title={t("judge.title")} right={<span style={{ color: "var(--fg-soft)" }}>{judge.data?.config?._updated || ""}</span>}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div>
            <div style={{ color: "var(--fg-soft)" }}>{t("judge.engine")}</div>
            <select value={engine} onChange={(e) => setEngine(e.target.value)} style={{ ...inp, width: "100%" }}>
              <option value="">—</option>
              {engines.map((i) => <option key={i.digest} value={i.ref}>{(i.ref || i.digest).split("@")[0].split("/").pop()}{i.signature ? " ✓" : ""}</option>)}
            </select>
            <div style={{ color: "var(--fg-soft)", marginTop: 8 }}>{t("judge.model")}</div>
            <input value={model} onChange={(e) => setModel(e.target.value)} placeholder="напр. Qwen3-8B" style={{ ...inp, width: "100%" }} />
            <div style={{ color: "var(--fg-soft)", marginTop: 8 }}>{t("judge.min")}</div>
            <input value={min} onChange={(e) => setMin(e.target.value)} style={{ ...inp, width: 120 }} />
            <label style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 8 }}><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />{t("judge.enabled")}</label>
          </div>
          <div>
            <div style={{ color: "var(--fg-soft)" }}>{t("judge.template")}</div>
            <textarea value={template} onChange={(e) => setTemplate(e.target.value)} style={{ ...inp, width: "100%", height: 220, fontFamily: "var(--mono)" }} />
          </div>
        </div>
        <div style={{ marginTop: 10, display: "flex", gap: 8, alignItems: "center" }}>
          <button onClick={save} style={{ background: "#3d7dd8", color: "#fff", border: 0, borderRadius: 6, padding: "8px 14px" }}>{t("judge.save")}</button>
          <span style={{ color: "var(--fg-soft)" }}>{msg}</span>
        </div>
        {!engines.length ? <EmptyState text="Нет доступных LLM-движков" /> : null}
      </Card>
    </div>
  );
}
const inp: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 10px" };
