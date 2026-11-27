import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Card, VerdictBadge, Table, Td, EmptyState, ErrorState } from "../components/ui";
import { useI18n } from "../i18n";

type Art = { sha256?: string; filename?: string; format?: string; size?: number; verdict?: string };
const listOf = (d: any): Art[] => (Array.isArray(d) ? d : Array.isArray(d?.artifacts) ? d.artifacts : []);
const gb = (n?: number) => (n ? (n / 1e9).toFixed(2) + " GB" : "—");

export default function Models() {
  const { t } = useI18n();
  const [sp] = useSearchParams();
  const [q, setQ] = useState(sp.get("q") || "");
  const [fmt, setFmt] = useState("");
  const [verdict, setVerdict] = useState("");
  const artsQ = useQuery({ queryKey: ["artifacts"], queryFn: () => api<any>("/v3/artifacts?limit=300"), refetchInterval: 20000 });
  const items = listOf(artsQ.data);
  const filtered = useMemo(() => items.filter((a) => {
    if (fmt && (a.format || "") !== fmt) return false;
    if (verdict && (a.verdict || "") !== verdict) return false;
    if (q && !((a.filename || "") + " " + (a.sha256 || "")).toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  }), [items, q, fmt, verdict]);
  const fmts = Array.from(new Set(items.map((a) => a.format || "").filter(Boolean))).sort();

  return (
    <Card title={t("models.title")} right={<Link to="/onboarding">+ {t("nav.upload")}</Link>}>
      <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
        <input placeholder={t("search")} value={q} onChange={(e) => setQ(e.target.value)} style={inp} />
        <select value={fmt} onChange={(e) => setFmt(e.target.value)} style={inp}><option value="">{t("col.format")}: {t("common.all")}</option>{fmts.map((f) => <option key={f} value={f}>{f}</option>)}</select>
        <select value={verdict} onChange={(e) => setVerdict(e.target.value)} style={inp}><option value="">{t("col.verdict")}: {t("common.all")}</option>
          {["Safe", "Needs review", "Malicious", "Inconclusive"].map((v) => <option key={v} value={v}>{v}</option>)}</select>
        <span style={{ color: "var(--fg-soft)" }}>{filtered.length}/{items.length}</span>
      </div>
      {artsQ.isError ? <ErrorState error={artsQ.error} onRetry={() => artsQ.refetch()} />
        : !filtered.length ? <EmptyState text={t("common.empty")} />
        : <Table head={[t("col.name"), t("col.format"), t("col.size"), t("col.verdict"), "sha"]}>
          {filtered.slice(0, 200).map((a) => (
            <tr key={a.sha256}>
              <Td><Link to={`/models/${encodeURIComponent(a.sha256 || "")}`}>{a.filename || "—"}</Link></Td>
              <Td>{a.format || "—"}</Td><Td>{gb(a.size)}</Td><Td><VerdictBadge verdict={a.verdict} /></Td>
              <Td><code>{(a.sha256 || "").slice(0, 12)}…</code></Td>
            </tr>))}
        </Table>}
    </Card>
  );
}
const inp: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 10px" };
