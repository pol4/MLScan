import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import { api } from "../api";
import { Card, VerdictBadge, StatusChip, Table, Td, EmptyState, ErrorState } from "../components/ui";
import { useI18n } from "../i18n";

const gb = (n?: number) => (n ? (n / 1e9).toFixed(2) + " GB" : "—");
const fmtT = (s?: number) => (s ? new Date(s * 1000).toLocaleString() : "—");

export default function ModelDetail() {
  const { t } = useI18n();
  const { sha = "" } = useParams();
  const [engine, setEngine] = useState("");
  const [msg, setMsg] = useState("");
  const [runId, setRunId] = useState("");

  const arts = useQuery({ queryKey: ["artifacts"], queryFn: () => api<any>("/v3/artifacts?limit=300") });
  const runsQ = useQuery({ queryKey: ["runs", "200"], queryFn: () => api<any>("/runs?limit=200") });
  const cache = useQuery({ queryKey: ["cache"], queryFn: () => api<any>("/v4/model-cache"), retry: false });
  const imgs = useQuery({ queryKey: ["images"], queryFn: () => api<any>("/images/list"), retry: false });

  const art = ((arts.data?.artifacts as any[]) || []).find((a) => a.sha256 === sha);
  const runs = ((runsQ.data?.runs as any[]) || []).filter((r) => r.model_sha256 === sha);
  const cacheEntry = ((cache.data?.entries as any[]) || []).find((e) => e.sha === sha);
  const engines = ((imgs.data?.images as any[]) || []).filter((i) => (i.type || "") === "llm");

  const start = async () => {
    if (!engine) { setMsg("Выберите движок"); return; }
    setMsg("запуск…");
    try {
      const b = await api<any>("/bundles", { method: "POST", body: JSON.stringify({ engine_image: engine, model_sha256: sha }) });
      const bid = b.bundle_id;
      await api<any>(`/bundles/${encodeURIComponent(bid)}/test`, { method: "POST", body: JSON.stringify({ gpu: true, runtime_class: "kata-gpu", ebpf: true }) });
      setRunId(bid); setMsg("тест запущен");
    } catch (e) { setMsg("ERR " + String((e as any)?.message || e)); }
  };

  return (
    <div>
      <div style={{ marginBottom: 10 }}><Link to="/models">← {t("models.title")}</Link></div>
      <Card title={t("model.info")}>
        {!art ? <EmptyState text="—" /> :
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap" }}>
            <div><b>{art.filename}</b></div><div>{t("col.format")}: {art.format}</div>
            <div>{t("col.size")}: {gb(art.size)}</div><div>{t("col.verdict")}: <VerdictBadge verdict={art.verdict} /></div>
            <div><code>{sha}</code></div>
          </div>}
      </Card>

      <Card title={`${t("model.runs")} (${runs.length})`}>
        {!runs.length ? <EmptyState text={t("common.empty")} />
          : <Table head={[t("col.kind"), t("col.status"), t("col.verdict"), t("col.updated"), ""]}>
            {runs.map((r) => (
              <tr key={r.id}><Td>{t("kind." + r.kind)}</Td><Td><StatusChip status={r.status} stage={r.stage} /></Td>
                <Td><VerdictBadge verdict={r.verdict} /></Td><Td>{fmtT(r.updated)}</Td>
                <Td><Link to={`/runs/${encodeURIComponent(r.id)}?kind=${r.kind}`}>{t("run.open")}</Link></Td></tr>))}
          </Table>}
      </Card>

      <Card title={t("model.cache")}>
        {!cacheEntry ? <EmptyState text="нет в кэше" /> :
          <div>{t("col.size")}: {gb(cacheEntry.size)} · last_used: {fmtT(cacheEntry.last_used)}</div>}
      </Card>

      <Card title={t("model.run")}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <select value={engine} onChange={(e) => setEngine(e.target.value)} style={inp}>
            <option value="">{t("onb.engine")}: выберите</option>
            {engines.map((i) => <option key={i.digest} value={i.ref}>{(i.ref || i.digest).split("@")[0].split("/").pop()}{i.signature ? " ✓" : ""}</option>)}
          </select>
          <button onClick={start} style={{ background: "#3d7dd8", color: "#fff", border: 0, borderRadius: 6, padding: "8px 14px" }}>{t("model.run")}</button>
          <span style={{ color: "var(--fg-soft)" }}>{msg}</span>
          {runId && <Link to={`/runs/${encodeURIComponent(runId)}?kind=bundle`}>{t("run.open")}</Link>}
        </div>
      </Card>
    </div>
  );
}
const inp: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 10px" };
