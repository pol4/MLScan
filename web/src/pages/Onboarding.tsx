import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Card, Table, Td, EmptyState, ErrorState } from "../components/ui";
import { useI18n } from "../i18n";

export default function Onboarding() {
  const { t } = useI18n();
  const [engine, setEngine] = useState("");
  const [query, setQuery] = useState("Qwen");
  const [found, setFound] = useState<any[]>([]);
  const [repo, setRepo] = useState("");
  const [dlId, setDlId] = useState("");
  const [msg, setMsg] = useState("");
  const imgs = useQuery({ queryKey: ["images"], queryFn: () => api<any>("/images/list"), retry: false });
  const engines = ((imgs.data?.images as any[]) || []).filter((i) => (i.type || "") === "llm");

  const dl = useQuery({ queryKey: ["dl", dlId], enabled: !!dlId, refetchInterval: 4000,
    queryFn: () => api<any>(`/hf/downloads/${encodeURIComponent(dlId)}`) });

  const search = async () => {
    setMsg("поиск…");
    try { const r = await api<any>("/hf/search", { method: "POST", body: JSON.stringify({ query, type: "text-generation" }) });
      setFound(r.models || r.items || []); setMsg(`найдено: ${(r.models || r.items || []).length}`); }
    catch (e) { setMsg("ERR " + String((e as any)?.message || e)); }
  };
  const download = async (id: string) => {
    if (!engine) { setMsg("Выберите движок"); return; }
    setMsg("запуск загрузки…");
    try { const r = await api<any>("/hf/downloads", { method: "POST", body: JSON.stringify({ repo_id: id, kind: "llm", engine_image: engine }) });
      setRepo(id); setDlId(r.id); setMsg("загрузка запущена"); }
    catch (e) { setMsg("ERR " + String((e as any)?.message || e)); }
  };
  const upload = async (f: File) => {
    if (!engine) { setMsg("Выберите движок (для LLM)"); return; }
    setMsg("загрузка файла…");
    try { const r = await fetch(`/upload?name=${encodeURIComponent(f.name)}&fmt=${encodeURIComponent((f.name.split(".").pop() || "").toLowerCase())}`, { method: "POST", body: f });
      const j = await r.json().catch(() => ({})); setMsg(r.ok ? "загружено" : "ERR " + (j.error || r.status)); }
    catch (e) { setMsg("ERR " + String((e as any)?.message || e)); }
  };

  const d = dl.data || {};
  const pct = d.bytes_total ? Math.round((Number(d.bytes_done || 0) / Number(d.bytes_total)) * 100) : 0;

  return (
    <div>
      <Card title={t("onb.title")} right={<Link to="/models">← {t("models.title")}</Link>}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 10 }}>
          <b>{t("onb.engine")}:</b>
          <select value={engine} onChange={(e) => setEngine(e.target.value)} style={inp}>
            <option value="">выберите движок</option>
            {engines.map((i) => <option key={i.digest} value={i.ref}>{(i.ref || i.digest).split("@")[0].split("/").pop()}{i.signature ? " ✓" : ""}</option>)}
          </select>
        </div>

        <h4>{t("onb.query")}</h4>
        <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
          <input value={query} onChange={(e) => setQuery(e.target.value)} style={{ ...inp, flex: "1 1 320px" }} />
          <button onClick={search} style={btn}>{t("onb.search")}</button>
        </div>
        {found.length ? <Table head={[t("col.name"), ""]}>
          {found.slice(0, 30).map((m, i) => (<tr key={m.id || i}><Td>{m.id || m.modelId}</Td>
            <Td><button onClick={() => download(m.id || m.modelId)} style={btn}>{t("onb.download")}</button></Td></tr>))}
        </Table> : <EmptyState text={t("common.empty")} />}

        {dlId && <div style={{ marginTop: 10 }}>
          <div>{repo}: {d.status || "…"} {pct ? `· ${pct}%` : ""} {d.error ? `· ${d.error}` : ""}</div>
          {d.status === "done" && <Link to="/models">{t("models.title")} →</Link>}
        </div>}

        <h4 style={{ marginTop: 16 }}>{t("onb.local")}</h4>
        <input type="file" onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); }} />

        <div style={{ marginTop: 10, color: "var(--fg-soft)" }}>{msg}</div>
      </Card>
    </div>
  );
}
const inp: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 10px" };
const btn: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 12px" };
