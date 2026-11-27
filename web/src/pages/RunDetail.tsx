import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams, useSearchParams, Link } from "react-router-dom";
import { api } from "../api";
import { Card, StatusChip, VerdictBadge, Table, Td, EmptyState, ErrorState, SeverityTag } from "../components/ui";
import { useI18n } from "../i18n";

const fmtT = (s?: number) => (s ? new Date(s * 1000).toLocaleString() : "—");
const RISKY = ["Malicious", "Dangerous", "Needs review", "Inconclusive"];

function csv(rows: string[][]): string {
  return rows.map((r) => r.map((c) => `"${String(c ?? "").replace(/"/g, '""')}"`).join(",")).join("\n");
}

export default function RunDetail() {
  const { t } = useI18n();
  const { id = "" } = useParams();
  const [sp] = useSearchParams();
  const kind = sp.get("kind") || "bundle";
  const [tab, setTab] = useState("summary");
  const [onlyFailed, setOnlyFailed] = useState(false);

  const me = useQuery({ queryKey: ["me"], queryFn: () => api<any>("/api/me"), retry: false });
  const isAdmin = (me.data?.roles || []).includes("admin");

  const bundle = useQuery({ queryKey: ["report", id], enabled: kind === "bundle",
    queryFn: () => api<any>(`/bundles/${encodeURIComponent(id)}/report.json`), refetchInterval: 15000 });
  const runsAll = useQuery({ queryKey: ["runs", "200"], enabled: kind === "scan", queryFn: () => api<any>("/runs?limit=200") });

  if (kind === "scan") {
    const r = ((runsAll.data?.runs as any[]) || []).find((x) => x.id === id);
    return (<Card title={`${t("run.scan")} ${id}`} right={<Link to="/runs">← {t("nav.runs")}</Link>}>
      {!runsAll.isSuccess ? <EmptyState text="…" />
        : !r ? <EmptyState text={t("common.empty")} />
        : <div>
          <div style={{ marginBottom: 8 }}><b>{r.model || id}</b> · <StatusChip status={r.status} stage={r.stage} /> · <VerdictBadge verdict={r.verdict} /></div>
          <div style={{ color: "var(--fg-soft)" }}>{t("run.legacyDetails")} <a href={`/legacy/artifact/${encodeURIComponent(r.model_sha256 || "")}`}>{t("run.open")}</a></div>
        </div>}
    </Card>);
  }

  const d = bundle.data || {};
  const b = d.bundle || {}, test = d.test || {}, v = d.verdict || {}, s = d.summary || {}, pol = d.policy || {};
  const m = v.metrics || {}, bc = m.by_criticality || {};
  const cases: any[] = d.cases || [];
  const findings: any[] = d.findings || [];
  const shown = onlyFailed ? cases.filter((c) => !c.passed) : cases;

  const exportCsv = () => {
    const rows = [[t("col.question"), t("col.answer"), t("col.criticality"), t("col.passed"), t("col.flags")]];
    for (const c of cases) {
      const det = (c.detail || [])[0] || {};
      rows.push([c.prompt || "", (c.answers || [])[0] || "", String(c.criticality ?? ""), c.passed ? "yes" : "no", (det.details || []).join("; ")]);
    }
    const blob = new Blob([csv(rows)], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `${id}.csv`; a.click();
  };

  const Tab = ({ k, label }: { k: string; label: string }) => (
    <button onClick={() => setTab(k)} style={{ background: tab === k ? "var(--accent-bg)" : "transparent",
      color: tab === k ? "var(--accent)" : "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "6px 12px" }}>{label}</button>);

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 10 }}>
        <Link to="/runs">← {t("nav.runs")}</Link>
        <b>{b.model_sha256 ? (b.model_sha256 || "").slice(0, 12) + "…" : id}</b>
        <span style={{ color: "var(--fg-soft)" }}>{(b.engine_image || "").split("@")[0].split("/").pop()}</span>
        <span>{test.gpu ? "GPU" : ""}</span>
      </div>

      <Card title={t("col.status")}>
        {bundle.isError ? <ErrorState error={bundle.error} onRetry={() => bundle.refetch()} />
          : <div>
            <StatusChip status={test.status || "—"} stage={test.stage || ""} />
            {test.error ? <div style={{ color: "var(--err)", marginTop: 6 }}>{test.error}</div> : null}
          </div>}
      </Card>

      <div style={{ display: "flex", gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
        <Tab k="summary" label={t("run.tab.summary")} /><Tab k="cases" label={t("run.tab.cases")} />
        <Tab k="obs" label={t("run.tab.obs")} /><Tab k="evidence" label={t("run.tab.evidence")} />
        {isAdmin && <Tab k="review" label={t("run.tab.review")} />}
      </div>

      {tab === "summary" && (
        <Card title={t("run.tab.summary")}>
          <div style={{ marginBottom: 8 }}>{t("col.verdict")}: <b><VerdictBadge verdict={v.verdict} /></b> · {t("run.action")}: <b>{v.action || "—"}</b>
            {m.manual ? <b style={{ color: "var(--warn)" }}> ({t("run.manualMark")}: {m.auto_verdict} → {v.verdict}, {m.reviewed_by})</b> : null}</div>
          <div style={{ color: "var(--fg-soft)", marginBottom: 8 }}>{t("col.policy")}: {pol.id || "default"}@{pol.version} · {t("run.promptSetLabel")} {b.prompt_set || s.prompt_set || "—"} · {t("run.attestation")} <code>{(v.attestation_digest || "").slice(0, 20)}…</code></div>
          <div style={{ marginBottom: 8 }}>{t("run.result")}: passed {s.passed ?? m.passed ?? "—"} / {s.total ?? m.total ?? "—"} · safety_fail {s.safety_fail ?? m.safety_fail ?? "—"} · pass_rate {s.pass_rate ?? m.pass_rate ?? "—"}</div>
          {m.judge_agreement ? <div style={{ color: "var(--fg-soft)", marginBottom: 8 }}>{t("run.judgeAgree")}: {m.judge_agreement.agree}/{m.judge_agreement.n} ({m.judge_agreement.rate})</div> : null}
          {Object.keys(bc).length ? <Table head={[t("col.criticality"), "total", t("col.passed"), "pass_rate"]}>
            {Object.keys(bc).sort().map((k) => (<tr key={k}><Td>{k}</Td><Td>{bc[k].total ?? ""}</Td><Td>{bc[k].passed ?? ""}</Td><Td>{bc[k].pass_rate ?? ""}</Td></tr>))}
          </Table> : <EmptyState text={t("common.empty")} />}
        </Card>)}

      {tab === "cases" && (
        <Card title={`${t("run.tab.cases")} (${cases.length})`} right={
          <span><label style={{ marginRight: 10 }}><input type="checkbox" checked={onlyFailed} onChange={(e) => setOnlyFailed(e.target.checked)} /> {t("run.onlyfailed")}</label>
            <button onClick={exportCsv} style={{ background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 6, padding: "5px 10px" }}>{t("run.export")}</button></span>}>
          {!cases.length ? <EmptyState text={t("run.noCases")} />
            : <div style={{ maxHeight: 520, overflow: "auto" }}>
              <Table head={["id", t("col.criticality"), t("col.passed"), t("col.flags"), t("col.question"), t("col.answer")]}>
                {shown.map((c) => { const det = (c.detail || [])[0] || {};
                  return (<tr key={c.id} style={c.passed ? undefined : { background: "color-mix(in srgb, var(--err) 12%, transparent)" }}>
                    <Td>{c.id}</Td><Td>{c.criticality}</Td><Td style={{ color: c.passed ? "var(--ok)" : "var(--err)", fontWeight: 600 }}>{c.passed ? t("common.yes") : t("common.no")}</Td>
                    <Td>{(det.details || []).join(", ")}{det.judge_score != null ? ` · judge=${det.judge_score}` : ""}</Td>
                    <Td><div style={{ maxWidth: 340, whiteSpace: "pre-wrap" }}>{(c.prompt || "").slice(0, 300)}</div></Td>
                    <Td><div style={{ maxWidth: 460, whiteSpace: "pre-wrap" }}>{(((c.answers || [])[0]) || "—").slice(0, 600)}</div></Td>
                  </tr>); })}
              </Table></div>}
        </Card>)}

      {tab === "obs" && (
        <Card title={t("run.tab.obs")}>
          {!findings.length ? <EmptyState text={t("common.empty")} />
            : <Table head={["rule", "severity", t("run.phase"), t("run.count"), t("run.example")]}>
              {findings.map((f, i) => (<tr key={i}><Td>{f.check_id}</Td><Td><SeverityTag sev={f.severity} /></Td><Td>{f.phase}</Td><Td>{f.count}</Td>
                <Td>{(f.samples || []).join(" | ").slice(0, 160)}</Td></tr>))}
            </Table>}
        </Card>)}

      {tab === "evidence" && (
        <Card title={t("run.tab.evidence")} right={<a download={`${id}.statement.json`} href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(v.statement || {}, null, 2))}`}>download</a>}>
          <div style={{ color: "var(--fg-soft)", marginBottom: 6 }}>digest <code>{v.attestation_digest}</code> · {t("run.signature")} <code>{(v.signature || "").slice(0, 24)}…</code></div>
          <pre style={{ maxHeight: 420, overflow: "auto", background: "var(--bg-soft)", padding: 12, borderRadius: 8 }}>{JSON.stringify(v.statement || {}, null, 2)}</pre>
        </Card>)}

      {tab === "review" && isAdmin && <ReviewForm id={id} onDone={() => bundle.refetch()} />}
    </div>
  );
}

function ReviewForm({ id, onDone }: { id: string; onDone: () => void }) {
  const { t } = useI18n();
  const [verdict, setVerdict] = useState("Needs review");
  const [reason, setReason] = useState("");
  const [msg, setMsg] = useState("");
  const apply = async () => {
    setMsg(t("common.sending"));
    try {
      const r = await api<any>(`/bundles/${encodeURIComponent(id)}/review`, { method: "POST", body: JSON.stringify({ verdict, reason }) });
      setMsg(`${t("common.applied")}: ${r.verdict} / ${r.action}`); onDone();
    } catch (e) { setMsg("ERR " + String((e as any)?.message || e)); }
  };
  return (
    <Card title={t("run.manual")}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <select value={verdict} onChange={(e) => setVerdict(e.target.value)} style={{ background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 6, padding: 7 }}>
          {["Safe", "Needs review", "Malicious", "Inconclusive"].map((x) => <option key={x} value={x}>{x}</option>)}</select>
        <input placeholder={t("run.reason")} value={reason} onChange={(e) => setReason(e.target.value)} style={{ flex: "1 1 320px", background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 6, padding: "7px 10px" }} />
        <button onClick={apply} style={{ background: "#3d7dd8", color: "#fff", border: 0, borderRadius: 6, padding: "8px 14px" }}>{t("run.apply")}</button>
        <span style={{ color: "var(--fg-soft)" }}>{msg}</span>
      </div>
    </Card>);
}
