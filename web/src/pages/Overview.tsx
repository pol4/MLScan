import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { Card, KpiCard, VerdictBadge, Table, Td, EmptyState, ErrorState } from "../components/ui";
import { useI18n } from "../i18n";

type Art = { sha256?: string; filename?: string; format?: string; size?: number; verdict?: string; state?: string };

function listOf(d: any): Art[] {
  if (Array.isArray(d)) return d;
  if (Array.isArray(d?.artifacts)) return d.artifacts;
  if (Array.isArray(d?.items)) return d.items;
  return [];
}

export default function Overview() {
  const { t } = useI18n();
  const arts = useQuery({ queryKey: ["artifacts"], queryFn: () => api<any>("/v3/artifacts?limit=200") });
  const cache = useQuery({ queryKey: ["cache"], queryFn: () => api<any>("/v4/model-cache"), retry: false });

  const items = listOf(arts.data);
  const by = (v: string) => items.filter((a) => a.verdict === v).length;
  const risky = items.filter((a) => ["Malicious", "Dangerous", "Needs review", "Inconclusive"].includes(a.verdict || "")).length;
  const cacheGb = cache.data ? Math.round(((cache.data.total_bytes || 0) / 1e9) * 10) / 10 : "—";

  return (
    <div>
      <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginBottom: 16 }}>
        <KpiCard label={t("ov.kpi.total")} value={arts.isSuccess ? items.length : "…"} />
        <KpiCard label={t("ov.kpi.safe")} value={arts.isSuccess ? by("Safe") : "…"} tone="ok" />
        <KpiCard label={t("ov.kpi.risky")} value={arts.isSuccess ? risky : "…"} tone="err" />
        <KpiCard label={t("ov.kpi.cache")} value={cacheGb} />
      </div>

      <Card title={t("ov.attention")}>
        {arts.isError ? <ErrorState error={arts.error} onRetry={() => arts.refetch()} />
          : !arts.isSuccess ? <EmptyState text="…" />
          : items.filter((a) => ["Malicious", "Dangerous", "Needs review", "Inconclusive"].includes(a.verdict || "")).length === 0
            ? <EmptyState text={t("common.empty")} />
            : <Table head={[t("col.name"), t("col.format"), t("col.verdict")]}>
              {items.filter((a) => ["Malicious", "Dangerous", "Needs review", "Inconclusive"].includes(a.verdict || "")).slice(0, 20).map((a) => (
                <tr key={a.sha256}>
                  <Td>{a.filename || "—"}</Td><Td>{a.format || "—"}</Td><Td><VerdictBadge verdict={a.verdict} /></Td>
                </tr>))}
            </Table>}
      </Card>

      <Card title="Последние артефакты">
        {arts.isSuccess && items.length
          ? <Table head={[t("col.name"), t("col.format"), t("col.verdict")]}>
            {items.slice(0, 15).map((a) => (
              <tr key={a.sha256}><Td>{a.filename || "—"}</Td><Td>{a.format || "—"}</Td><Td><VerdictBadge verdict={a.verdict} /></Td></tr>))}
          </Table>
          : <EmptyState text={arts.isError ? t("common.error") : t("common.empty")} />}
      </Card>
    </div>
  );
}
