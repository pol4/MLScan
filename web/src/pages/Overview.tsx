import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { Card, KpiCard, VerdictBadge, StatusChip, Table, Td, EmptyState, ErrorState } from "../components/ui";
import { useI18n } from "../i18n";

type Run = { id: string; kind: string; model?: string; engine?: string; status?: string; stage?: string;
  verdict?: string; action?: string; error?: string; gpu?: boolean; updated?: number; policy_version?: number };
type Art = { sha256?: string; filename?: string; format?: string; verdict?: string };

const RISKY = ["Malicious", "Dangerous", "Needs review", "Inconclusive"];
const listOf = (d: any, k: string): any[] => (Array.isArray(d) ? d : Array.isArray(d?.[k]) ? d[k] : []);
const fmtT = (s?: number) => (s ? new Date(s * 1000).toLocaleString() : "—");

export default function Overview() {
  const { t } = useI18n();
  const runsQ = useQuery({ queryKey: ["runs"], queryFn: () => api<any>("/runs?limit=100"), refetchInterval: 15000 });
  const artsQ = useQuery({ queryKey: ["artifacts"], queryFn: () => api<any>("/v3/artifacts?limit=200") });
  const dlQ = useQuery({ queryKey: ["hfd"], queryFn: () => api<any>("/hf/downloads"), refetchInterval: 15000, retry: false });
  const cacheQ = useQuery({ queryKey: ["cache"], queryFn: () => api<any>("/v4/model-cache"), retry: false });

  const runs: Run[] = listOf(runsQ.data, "runs");
  const arts: Art[] = listOf(artsQ.data, "artifacts");
  const dls: any[] = listOf(dlQ.data, "downloads");
  const attention = runs.filter((r) => r.status === "failed" || RISKY.includes(r.verdict || ""));
  const queue = runs.filter((r) => r.status === "preparing" || r.status === "running");
  const safeCount = arts.filter((a) => a.verdict === "Safe").length;
  const riskyArts = arts.filter((a) => RISKY.includes(a.verdict || "")).length;
  const cacheGb = cacheQ.data ? Math.round(((cacheQ.data.total_bytes || 0) / 1e9) * 10) / 10 : "—";

  return (
    <div>
      <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginBottom: 16 }}>
        <KpiCard label={t("ov.kpi.total")} value={artsQ.isSuccess ? arts.length : "…"} />
        <KpiCard label={t("ov.kpi.safe")} value={artsQ.isSuccess ? safeCount : "…"} tone="ok" />
        <KpiCard label={t("ov.kpi.risky")} value={artsQ.isSuccess ? riskyArts : "…"} tone="err" />
        <KpiCard label={t("ov.kpi.cache")} value={cacheGb} />
      </div>

      <Card title={t("ov.attention")} right={attention.length ? <span style={{ color: "var(--err)" }}>{attention.length}</span> : undefined}>
        {runsQ.isError ? <ErrorState error={runsQ.error} onRetry={() => runsQ.refetch()} />
          : !attention.length ? <EmptyState text={t("common.empty")} />
          : <Table head={[t("col.name"), t("col.kind"), t("col.status"), t("col.verdict"), t("col.updated")]}>
            {attention.slice(0, 20).map((r) => (
              <tr key={r.id + r.kind}>
                <Td><a href={`/app/runs?id=${encodeURIComponent(r.id)}`}>{r.model || r.id}</a></Td>
                <Td>{t("kind." + r.kind)}</Td>
                <Td><StatusChip status={r.status} stage={r.stage} />{r.error ? <div style={{ color: "var(--fg-soft)", fontSize: 12 }}>{r.error.slice(0, 120)}</div> : null}</Td>
                <Td><VerdictBadge verdict={r.verdict} /></Td>
                <Td>{fmtT(r.updated)}</Td>
              </tr>))}
          </Table>}
      </Card>

      <Card title={t("ov.queue")}>
        {!queue.length ? <EmptyState text={t("common.empty")} />
          : <Table head={[t("col.name"), t("col.engine"), t("col.status"), t("col.stage")]}>
            {queue.map((r) => (
              <tr key={r.id}><Td>{r.model || r.id}</Td><Td>{(r.engine || "—").split("@")[0].split("/").pop()}</Td>
                <Td><StatusChip status={r.status} />{r.gpu ? " · GPU" : ""}</Td><Td>{r.stage || "—"}</Td></tr>))}
          </Table>}
      </Card>

      <Card title={t("ov.downloads")}>
        {dlQ.isError ? <ErrorState error={dlQ.error} onRetry={() => dlQ.refetch()} />
          : !dls.length ? <EmptyState text={t("common.empty")} />
          : <Table head={[t("col.repo"), t("col.status"), t("col.progress")]}>
            {dls.slice(0, 10).map((d, i) => {
              const tot = Number(d.bytes_total || 0), done = Number(d.bytes_done || 0);
              const pct = tot ? Math.round((done / tot) * 100) : 0;
              return (<tr key={d.id || i}><Td>{d.repo_id || "—"}</Td><Td>{d.status || "—"}</Td>
                <Td>{tot ? `${pct}% (${(done / 1e9).toFixed(2)}/${(tot / 1e9).toFixed(2)} GB)` : `${(done / 1e9).toFixed(2)} GB`}</Td></tr>);
            })}
          </Table>}
      </Card>

      <Card title={t("ov.recent")}>
        {runsQ.isSuccess && runs.length
          ? <Table head={[t("col.name"), t("col.kind"), t("col.status"), t("col.verdict"), t("col.updated")]}>
            {runs.slice(0, 12).map((r) => (
              <tr key={r.id + r.kind}><Td>{r.model || r.id}</Td><Td>{t("kind." + r.kind)}</Td>
                <Td><StatusChip status={r.status} stage={r.stage} /></Td><Td><VerdictBadge verdict={r.verdict} /></Td>
                <Td>{fmtT(r.updated)}</Td></tr>))}
          </Table>
          : <EmptyState text={runsQ.isError ? t("common.error") : t("common.empty")} />}
      </Card>
    </div>
  );
}
