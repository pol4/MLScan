import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Card, StatusChip, VerdictBadge, Table, Td, EmptyState, ErrorState } from "../components/ui";
import LineChart from "../components/LineChart";
import { useI18n } from "../i18n";

type Run = { id: string; kind: string; model?: string; model_sha256?: string; engine?: string; status?: string;
  verdict?: string; updated?: number; policy_version?: number; pass_rate?: number; safety_fail?: number; total?: number };

export default function Compare() {
  const { t } = useI18n();
  const [sp] = useSearchParams();
  const ids = (sp.get("ids") || "").split(",").map((s) => s.trim()).filter(Boolean).slice(0, 6);
  const [model, setModel] = useState(sp.get("model") || "");

  const runsQ = useQuery({ queryKey: ["runs", "200"], queryFn: () => api<any>("/runs?limit=200") });
  const runs: Run[] = (runsQ.data?.runs as Run[]) || [];

  const reports = useQuery({
    queryKey: ["cmp", ids.join(",")], enabled: ids.length > 0,
    queryFn: async () => Promise.all(ids.map((id) => api<any>(`/bundles/${encodeURIComponent(id)}/report.json`))),
  });

  const models = useMemo(() => {
    const m = new Map<string, string>();
    runs.filter((r) => r.kind === "bundle" && r.model_sha256).forEach((r) => m.set(r.model_sha256!, r.model || r.model_sha256!));
    return Array.from(m.entries());
  }, [runs]);

  // Тренды: по выбранной модели (или по всем), ряды pass_rate и safety_fail во времени.
  const trendRuns = runs.filter((r) => r.kind === "bundle" && (!model || r.model_sha256 === model) && r.pass_rate != null)
    .sort((a, b) => (a.updated || 0) - (b.updated || 0));
  const series = [
    { label: "pass_rate", color: "var(--ok)", points: trendRuns.map((r) => [r.updated || 0, (r.pass_rate || 0) * 100] as [number, number]) },
    { label: "safety_fail", color: "var(--err)", points: trendRuns.map((r) => [r.updated || 0, r.safety_fail || 0] as [number, number]) },
  ];

  const cols = (reports.data || []) as any[];

  return (
    <div>
      <Card title={t("cmp.title")}>
        {!ids.length ? <EmptyState text={t("cmp.pick")} />
          : reports.isError ? <ErrorState error={reports.error} onRetry={() => reports.refetch()} />
          : !reports.isSuccess ? <EmptyState text="…" />
          : <Table head={["", ...cols.map((d) => (d.bundle?.model_sha256 || d.bundle?.bundle_id || "").slice(0, 12) + "…")]}>
            <Row label="Вердикт" cells={cols.map((d) => <VerdictBadge verdict={d.verdict?.verdict} />)} />
            <Row label="Статус" cells={cols.map((d) => <StatusChip status={d.test?.status} stage={d.test?.stage} />)} />
            <Row label={t("col.engine")} cells={cols.map((d) => (d.bundle?.engine_image || "").split("@")[0].split("/").pop())} />
            <Row label={t("col.policy")} cells={cols.map((d) => `${d.policy?.id || "default"}@${d.policy?.version}`)} />
            <Row label="passed/total" cells={cols.map((d) => `${d.summary?.passed ?? "—"}/${d.summary?.total ?? "—"}`)} />
            <Row label="pass_rate" cells={cols.map((d) => d.summary?.pass_rate ?? "—")} />
            <Row label="safety_fail" cells={cols.map((d) => d.summary?.safety_fail ?? "—")} />
            <Row label={t("col.updated")} cells={cols.map((d) => d.test?.updated ? new Date(d.test.updated).toLocaleString() : "—")} />
          </Table>}
      </Card>

      {cols.length >= 2 && <Card title={t("cmp.diff")}>
        <CaseDiff cols={cols} ids={ids} />
      </Card>}

      <Card title={t("cmp.trends")} right={
        <select value={model} onChange={(e) => setModel(e.target.value)} style={{ background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 6, padding: 6 }}>
          <option value="">{t("cmp.model")}: все</option>
          {models.map(([sha, name]) => <option key={sha} value={sha}>{name}</option>)}
        </select>}>
        {trendRuns.length < 2 ? <EmptyState text="Недостаточно данных для тренда (нужно ≥2 прогона с метриками)" /> : <LineChart series={series} />}
      </Card>
    </div>
  );
}

function Row({ label, cells }: { label: string; cells: React.ReactNode[] }) {
  return <tr><Td><b>{label}</b></Td>{cells.map((c, i) => <Td key={i}>{c}</Td>)}</tr>;
}

function CaseDiff({ cols, ids }: { cols: any[]; ids: string[] }) {
  const { t } = useI18n();
  const maps = cols.map((d) => {
    const m = new Map<string, any>();
    (d.cases || []).forEach((c: any) => m.set(String(c.id), c));
    return m;
  });
  const allIds = Array.from(new Set(maps.flatMap((m) => Array.from(m.keys()))));
  const rows = allIds.map((cid) => {
    const cs = maps.map((m) => m.get(cid));
    const passed = cs.map((c) => c?.passed);
    const flags = cs.map((c) => (((c?.detail || [])[0] || {}).details || []).join(","));
    const answers = cs.map((c) => String(((c?.answers || [])[0]) || "").slice(0, 80));
    const changed = new Set(flags).size > 1 || new Set(answers).size > 1 || new Set(passed).size > 1;
    return { cid, cs, passed, flags, changed };
  }).filter((r) => r.changed);

  if (!rows.length) return <EmptyState text="Различий по кейсам не найдено" />;
  return (
    <div style={{ maxHeight: 420, overflow: "auto" }}>
      <Table head={["id", "crit", ...ids.map((i) => i.slice(0, 10) + "…"), t("col.flags")]}>
        {rows.slice(0, 200).map((r) => (
          <tr key={r.cid}>
            <Td>{r.cid}</Td><Td>{r.cs[0]?.criticality}</Td>
            {r.passed.map((p, i) => <Td key={i} style={{ color: p ? "var(--ok)" : "var(--err)" }}>{p ? "✓" : "✗"}</Td>)}
            <Td>{r.flags.filter((f, i) => f !== r.flags[0] || i === 0).join(" | ")}</Td>
          </tr>))}
      </Table></div>);
}
