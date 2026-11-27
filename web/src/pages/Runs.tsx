import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Card, StatusChip, VerdictBadge, Table, Td, EmptyState, ErrorState } from "../components/ui";
import { useI18n } from "../i18n";

type Run = { id: string; kind: string; model?: string; model_sha256?: string; engine?: string; status?: string;
  stage?: string; verdict?: string; action?: string; error?: string; gpu?: boolean; updated?: number; policy_version?: number };

const RISKY = ["Malicious", "Dangerous", "Needs review", "Inconclusive"];
const fmtT = (s?: number) => (s ? new Date(s * 1000).toLocaleString() : "—");
const eng = (e?: string) => (e || "—").split("@")[0].split("/").pop();

export default function Runs() {
  const { t } = useI18n();
  const [sp, setSp] = useSearchParams();
  const [state, setState] = useState(sp.get("state") || "");
  const [verdict, setVerdict] = useState(sp.get("verdict") || "");
  const [kind, setKind] = useState(sp.get("kind") || "");
  const [q, setQ] = useState(sp.get("q") || "");
  const [attn, setAttn] = useState(sp.get("attn") === "1");
  const [sel, setSel] = useState<string[]>([]);
  const nav = useNavigate();
  const toggle = (id: string, on: boolean) => setSel((s) => on ? [...s, id] : s.filter((x) => x !== id));

  const runsQ = useQuery({ queryKey: ["runs", "200"], queryFn: () => api<any>("/runs?limit=200"), refetchInterval: 15000 });
  const runs: Run[] = (runsQ.data?.runs as Run[]) || [];

  const filtered = useMemo(() => runs.filter((r) => {
    if (state && r.status !== state) return false;
    if (kind && r.kind !== kind) return false;
    if (verdict === "risky" && !RISKY.includes(r.verdict || "")) return false;
    if (verdict && verdict !== "risky" && r.verdict !== verdict) return false;
    if (attn && !(r.status === "failed" || RISKY.includes(r.verdict || ""))) return false;
    if (q && !((r.model || "") + " " + (r.model_sha256 || "") + " " + (r.id || "")).toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  }), [runs, state, verdict, kind, q, attn]);

  const saveView = () => {
    const name = prompt(t("runs.viewName"), `${kind || "all"}/${state || "all"}/${verdict || "all"}`);
    if (!name) return;
    const views = JSON.parse(localStorage.getItem("mlscan_runs_views") || "{}");
    views[name] = { state, verdict, kind, q, attn };
    localStorage.setItem("mlscan_runs_views", JSON.stringify(views));
    alert(t("runs.savedMsg") + " " + name);
  };

  return (
    <Card title={t("nav.runs")} right={<span style={{ color: "var(--fg-soft)" }}>{filtered.length}/{runs.length}</span>}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        <input placeholder={t("search")} value={q} onChange={(e) => setQ(e.target.value)} style={inp} />
        <select value={kind} onChange={(e) => setKind(e.target.value)} style={inp}><option value="">{t("col.kind")}: {t("common.all")}</option><option value="bundle">bundle</option><option value="scan">scan</option></select>
        <select value={state} onChange={(e) => setState(e.target.value)} style={inp}>
          <option value="">{t("runs.state")}: {t("common.all")}</option>{["done", "failed", "running", "preparing"].map((s) => <option key={s} value={s}>{s}</option>)}</select>
        <select value={verdict} onChange={(e) => setVerdict(e.target.value)} style={inp}>
          <option value="">{t("col.verdict")}: {t("common.all")}</option><option value="risky">{t("runs.risky")}</option>
          {["Safe", "Needs review", "Malicious", "Inconclusive"].map((s) => <option key={s} value={s}>{s}</option>)}</select>
        <label style={{ display: "flex", gap: 6, alignItems: "center" }}><input type="checkbox" checked={attn} onChange={(e) => setAttn(e.target.checked)} />{t("runs.onlyattn")}</label>
        <button onClick={saveView} style={btn}>{t("runs.saved")}</button>
        <button disabled={sel.length < 2} onClick={() => nav(`/compare?ids=${sel.join(",")}`)} style={{ ...btn, opacity: sel.length < 2 ? 0.5 : 1 }}>{t("runs.compare")} ({sel.length})</button>
        <button onClick={() => { setState(""); setVerdict(""); setKind(""); setQ(""); setAttn(false); setSp({}); }} style={btn}>{t("common.reset")}</button>
      </div>
      {runsQ.isError ? <ErrorState error={runsQ.error} onRetry={() => runsQ.refetch()} />
        : !filtered.length ? <EmptyState text={t("common.empty")} />
        : <Table head={["", t("col.name"), t("col.kind"), t("col.engine"), t("col.status"), t("col.verdict"), t("col.updated"), ""]}>
          {filtered.map((r) => (
            <tr key={r.id + r.kind}>
              <Td>{r.kind === "bundle" ? <input type="checkbox" checked={sel.includes(r.id)} onChange={(e) => toggle(r.id, e.target.checked)} /> : null}</Td>
              <Td>{r.model || r.id}</Td>
              <Td>{t("kind." + r.kind)}</Td>
              <Td>{eng(r.engine)}</Td>
              <Td><StatusChip status={r.status} stage={r.stage} /></Td>
              <Td><VerdictBadge verdict={r.verdict} /></Td>
              <Td>{fmtT(r.updated)}</Td>
              <Td><Link to={`/runs/${encodeURIComponent(r.id)}?kind=${r.kind}`}>{t("run.open")}</Link></Td>
            </tr>))}
        </Table>}
    </Card>
  );
}

const inp: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 10px" };
const btn: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 12px" };
