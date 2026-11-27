import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { Card, Table, Td, EmptyState, ErrorState } from "../components/ui";
import { useI18n } from "../i18n";

const SAMPLE = `[
  {"profile":"llm","results":{"safety_fail":0,"pass_rate":1.0},"label":"safe"},
  {"profile":"llm","results":{"safety_fail":1,"pass_rate":0.9},"label":"unsafe"}
]`;

export default function Policies() {
  const { t } = useI18n();
  const list = useQuery({ queryKey: ["policies"], queryFn: () => api<any>("/v4/policies") });
  const policies: any[] = (list.data?.policies as any[]) || [];
  const [pid, setPid] = useState("");
  useEffect(() => { if (!pid && policies.length) setPid(String(policies[0].id)); }, [policies, pid]);
  const body = useQuery({ queryKey: ["policy", pid], enabled: !!pid, queryFn: () => api<any>(`/v4/policies/${encodeURIComponent(pid)}`) });

  const [text, setText] = useState("");
  const [cases, setCases] = useState(SAMPLE);
  const [profile, setProfile] = useState("llm");
  const [msg, setMsg] = useState("");
  const [sim, setSim] = useState<any>(null);
  const [diff, setDiff] = useState<any>(null);
  useEffect(() => { if (body.data) setText(JSON.stringify(body.data.body || {}, null, 2)); }, [body.data]);

  const parse = <T,>(s: string): T => { try { return JSON.parse(s); } catch (e) { throw new Error("JSON: " + (e as Error).message); } };
  const simulate = (pol: any) => api<any>(`/v4/policies/${encodeURIComponent(pid)}/simulate`, { method: "POST", body: JSON.stringify({ policy: pol, cases: parse(cases), profile }) });
  const doSim = async () => { setMsg(t("pol.simulating")); try { setSim(await simulate(parse(text))); setMsg(""); } catch (e) { setMsg("ERR " + (e as Error).message); } };
  const doDiff = async () => {
    setMsg(t("pol.diffing"));
    try {
      const a = await simulate(body.data?.body || {}); const b = await simulate(parse(text));
      const am = new Map<string, string>((a.results || []).map((r: any) => [String(r.id), r.predicted]));
      let changed = 0; (b.results || []).forEach((r: any) => { if (am.get(String(r.id)) !== r.predicted) changed++; });
      setDiff({ a: a.summary, b: b.summary, changed }); setMsg("");
    } catch (e) { setMsg("ERR " + (e as Error).message); }
  };
  const save = async () => { setMsg(t("common.saving")); try { await api("/v4/policies", { method: "POST", body: JSON.stringify({ id: pid, body: parse(text) }) }); setMsg(t("pol.draftSaved")); list.refetch(); } catch (e) { setMsg("ERR " + (e as Error).message); } };
  const publish = async () => { setMsg(t("pol.publishing")); try { await api(`/v4/policies/${encodeURIComponent(pid)}/publish`, { method: "POST", body: JSON.stringify({ body: parse(text) }) }); setMsg(t("pol.published")); body.refetch(); } catch (e) { setMsg("ERR " + (e as Error).message); } };

  return (
    <div>
      <Card title={t("pol.title")} right={<span style={{ color: "var(--fg-soft)" }}>{body.data ? `${pid}@${body.data.version} (${body.data.status})` : ""}</span>}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10, flexWrap: "wrap" }}>
          <b>{t("pol.id")}:</b>
          <select value={pid} onChange={(e) => setPid(e.target.value)} style={inp}>
            {policies.map((p) => <option key={p.id} value={p.id}>{p.id}@{p.version} ({p.versions ?? "?"})</option>)}
          </select>
          <b>{t("pol.profile")}:</b>
          <select value={profile} onChange={(e) => setProfile(e.target.value)} style={inp}><option value="llm">llm</option><option value="generic">generic</option></select>
        </div>
        {list.isError ? <ErrorState error={list.error} onRetry={() => list.refetch()} /> : null}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div><div style={{ color: "var(--fg-soft)", marginBottom: 4 }}>{t("pol.body")}</div>
            <textarea value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} style={{ ...inp, width: "100%", height: 320, fontFamily: "var(--mono)" }} /></div>
          <div><div style={{ color: "var(--fg-soft)", marginBottom: 4 }}>{t("pol.cases")}</div>
            <textarea value={cases} onChange={(e) => setCases(e.target.value)} spellCheck={false} style={{ ...inp, width: "100%", height: 320, fontFamily: "var(--mono)" }} /></div>
        </div>
        <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
          <button onClick={save} style={btn}>{t("pol.save")}</button>
          <button onClick={publish} style={{ ...btn, background: "#3d7dd8", color: "#fff", border: 0 }}>{t("pol.publish")}</button>
          <button onClick={doSim} style={btn}>{t("pol.simulate")}</button>
          <button onClick={doDiff} style={btn}>{t("pol.diff")}</button>
          <span style={{ color: "var(--fg-soft)" }}>{msg}</span>
        </div>
      </Card>

      {sim && <Card title={t("pol.summary")}>
        <Summary s={sim.summary} />
        <Table head={["id", "profile", "expected", "predicted", "action", "match"]}>
          {(sim.results || []).map((r: any, i: number) => (<tr key={i}><Td>{r.id ?? "—"}</Td><Td>{r.profile}</Td><Td>{r.expected ?? "—"}</Td>
            <Td>{r.predicted}</Td><Td>{r.action}</Td><Td>{r.match === null ? "—" : r.match ? "✓" : "✗"}</Td></tr>))}
        </Table>
      </Card>}

      {diff && <Card title={t("pol.diff")}>
        <div style={{ marginBottom: 8 }}>{t("pol.changed")}: <b>{diff.changed}</b></div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div><div style={{ color: "var(--fg-soft)" }}>published</div><Summary s={diff.a} /></div>
          <div><div style={{ color: "var(--fg-soft)" }}>draft</div><Summary s={diff.b} /></div>
        </div>
      </Card>}
    </div>
  );
}

function Summary({ s }: { s: any }) {
  if (!s) return <EmptyState text="—" />;
  return <div style={{ fontSize: 12, marginBottom: 6 }}>
    cases {s.cases} · labeled {s.labeled} · <span style={{ color: "var(--ok)" }}>tp {s.tp}</span> · <span style={{ color: "var(--err)" }}>fn {s.fn}</span> ·
    fp {s.fp} · tn {s.tn} · accuracy {s.accuracy ?? "—"} · FNR {s.false_negative_rate ?? "—"} · FPR {s.false_positive_rate ?? "—"}
  </div>;
}
const inp: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 10px" };
const btn: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 12px" };
