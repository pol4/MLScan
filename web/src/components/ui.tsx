import { ReactNode } from "react";

export function Card({ title, children, right }: { title?: string; children: ReactNode; right?: ReactNode }) {
  return (
    <section style={{ background: "var(--bg-elev)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: 16, marginBottom: 16 }}>
      {title && <div style={{ display: "flex", alignItems: "center", marginBottom: 10 }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>{title}</h3><span style={{ marginLeft: "auto" }}>{right}</span></div>}
      {children}
    </section>
  );
}

export function KpiCard({ label, value, tone }: { label: string; value: ReactNode; tone?: "ok" | "warn" | "err" }) {
  const c = tone === "err" ? "var(--err)" : tone === "warn" ? "var(--warn)" : tone === "ok" ? "var(--ok)" : "var(--fg)";
  return (
    <div style={{ background: "var(--bg-elev)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 18px", minWidth: 150 }}>
      <div style={{ fontSize: 26, fontWeight: 700, color: c }}>{value}</div>
      <div style={{ color: "var(--fg-soft)", fontSize: 12, textTransform: "uppercase" }}>{label}</div>
    </div>
  );
}

const VERDICT: Record<string, { ru: string; en: string; color: string; icon: string }> = {
  Safe: { ru: "Safe", en: "Safe", color: "var(--ok)", icon: "✓" },
  "Needs review": { ru: "Needs review", en: "Needs review", color: "var(--warn)", icon: "!" },
  Malicious: { ru: "Malicious", en: "Malicious", color: "var(--err)", icon: "⛔" },
  Dangerous: { ru: "Dangerous", en: "Dangerous", color: "var(--danger)", icon: "▲" },
  Inconclusive: { ru: "Inconclusive", en: "Inconclusive", color: "var(--muted)", icon: "?" },
};

export function VerdictBadge({ verdict }: { verdict?: string }) {
  const v = verdict ? VERDICT[verdict] : undefined;
  if (!v) return <span style={{ color: "var(--fg-soft)" }}>—</span>;
  return <span aria-label={verdict} style={{ color: v.color, fontWeight: 600, whiteSpace: "nowrap" }}>{v.icon} {verdict}</span>;
}

export function StatusChip({ status, stage }: { status?: string; stage?: string }) {
  const color = status === "failed" ? "var(--err)" : status === "done" ? "var(--ok)"
    : status === "running" || status === "preparing" ? "var(--accent)" : "var(--muted)";
  if (!status) return <span style={{ color: "var(--fg-soft)" }}>—</span>;
  return <span style={{ color, whiteSpace: "nowrap" }}>● {status}{stage ? ` · ${stage}` : ""}</span>;
}

export function StageStepper({ stages, current }: { stages: string[]; current?: string }) {
  const idx = current ? stages.indexOf(current) : -1;
  return (
    <ol style={{ display: "flex", gap: 8, listStyle: "none", padding: 0, margin: "6px 0", flexWrap: "wrap" }}>
      {stages.map((s, i) => (
        <li key={s} style={{ display: "flex", alignItems: "center", gap: 6, color: i <= idx ? "var(--fg)" : "var(--fg-soft)", fontSize: 12 }}>
          <span style={{ width: 18, height: 18, borderRadius: 9, display: "inline-flex", alignItems: "center", justifyContent: "center",
            background: i <= idx ? "var(--accent-bg)" : "var(--bg-soft)", border: "1px solid var(--border-soft)" }}>{i + 1}</span>
          {s}{i < stages.length - 1 && <span style={{ color: "var(--border-soft)" }}>→</span>}
        </li>))}
    </ol>
  );
}

export function CoverageMeter({ value }: { value: number }) {
  const v = Math.max(0, Math.min(1, value)) * 100;
  return (
    <div title={`${v.toFixed(0)}%`} style={{ background: "var(--bg-soft)", borderRadius: 5, height: 14, minWidth: 120, overflow: "hidden" }}>
      <span style={{ display: "block", height: "100%", width: `${v}%`, background: v >= 100 ? "var(--ok)" : "var(--warn)" }} />
    </div>);
}

export function SeverityTag({ sev }: { sev?: string }) {
  const color = sev === "critical" ? "var(--err)" : sev === "high" ? "var(--danger)" : sev === "medium" ? "var(--warn)" : "var(--muted)";
  return <span style={{ color, border: `1px solid ${color}`, borderRadius: 6, padding: "1px 6px", fontSize: 11 }}>{sev || "—"}</span>;
}

export function EmptyState({ text }: { text?: string }) {
  return <div style={{ color: "var(--fg-soft)", padding: 12 }}>{text || "Нет данных"}</div>;
}
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return <div style={{ color: "var(--err)", padding: 12 }}>
    Ошибка загрузки: {String((error as any)?.message || error)}
    {onRetry && <> <button onClick={onRetry} style={{ marginLeft: 8 }}>Повторить</button></>}</div>;
}

export function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div style={{ overflow: "auto" }}>
      <table style={{ borderCollapse: "collapse", width: "100%" }}>
        <thead><tr>{head.map((h) => <th key={h} style={{ textAlign: "left", color: "var(--fg-soft)", fontWeight: 600, padding: "8px 10px", borderBottom: "1px solid var(--border)" }}>{h}</th>)}</tr></thead>
        <tbody>{children}</tbody>
      </table></div>);
}
export function Td({ children }: { children: ReactNode }) {
  return <td className="cell" style={{ padding: "8px 10px", borderBottom: "1px solid var(--border)" }}>{children}</td>;
}
