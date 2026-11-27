import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Card, EmptyState } from "../components/ui";
import { useI18n } from "../i18n";

export default function Admin() {
  const { t } = useI18n();
  const judge = useQuery({ queryKey: ["judge"], queryFn: () => api<any>("/v4/judge"), retry: false });
  const imgs = useQuery({ queryKey: ["images"], queryFn: () => api<any>("/images/list"), retry: false });
  const quota = useQuery({ queryKey: ["quota"], queryFn: () => api<any>("/hf/quota"), retry: false });
  const egress = useQuery({ queryKey: ["egress"], queryFn: () => api<any>("/hf/egress?limit=20"), retry: false });
  const audit = useQuery({ queryKey: ["audit"], queryFn: () => api<any>("/api/evidence/verify"), retry: false });
  const cache = useQuery({ queryKey: ["cache"], queryFn: () => api<any>("/v4/model-cache"), retry: false });
  const hftok = useQuery({ queryKey: ["hftoken"], queryFn: () => api<any>("/hf/token"), retry: false });
  const dcls = useQuery({ queryKey: ["domainclass"], queryFn: () => api<any>("/domain-class"), retry: false });
  const engines = ((imgs.data?.images as any[]) || []).filter((i) => (i.type || "") === "llm");

  const [engine, setEngine] = useState("");
  const [model, setModel] = useState("");
  const [jurl, setJurl] = useState("");
  const [min, setMin] = useState("0.6");
  const [template, setTemplate] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [msg, setMsg] = useState("");
  useEffect(() => {
    const c = judge.data?.config;
    if (c && Object.keys(c).length) {
      setEngine(c.engine || ""); setModel(c.model || ""); setJurl(c.url || ""); setMin(String(c.min ?? "0.6"));
      setTemplate(c.template || ""); setEnabled(!!c.enabled);
    }
  }, [judge.data]); // eslint-disable-line react-hooks/exhaustive-deps

  const save = async () => {
    setMsg(t("common.saving"));
    try { await api("/v4/judge", { method: "POST", body: JSON.stringify({ engine, model, url: jurl, min: Number(min), template: template || t("judge.templateDefault"), enabled }) });
      setMsg(t("admin.judgeSaved")); judge.refetch();
    } catch (e) { setMsg("ERR " + String((e as any)?.message || e)); }
  };

  // Дополнительные админ-операции (паритет с прежним UI).
  const [tokIn, setTokIn] = useState("");
  const [tokMsg, setTokMsg] = useState("");
  const [syncMsg, setSyncMsg] = useState("");
  const [dcDomain, setDcDomain] = useState("");
  const [dcClass, setDcClass] = useState("");
  const [dcMsg, setDcMsg] = useState("");
  const [quotaBytes, setQuotaBytes] = useState("");
  const [quotaMsg, setQuotaMsg] = useState("");
  const [rlRps, setRlRps] = useState("");
  const [rlBurst, setRlBurst] = useState("");
  const [rlMsg, setRlMsg] = useState("");
  const [signDigest, setSignDigest] = useState("");
  const [signMsg, setSignMsg] = useState("");

  const post = async (path: string, body: unknown, set: (s: string) => void, ok: string) => {
    set("…");
    try { const r = await api<any>(path, { method: "POST", body: JSON.stringify(body) });
      set(ok + " " + JSON.stringify(r).slice(0, 160));
    } catch (e) { set("ERR " + String((e as any)?.message || e)); }
  };

  return (
    <div>
      <Card title={t("admin.title")}>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <Link to="/policies">{t("pol.title")}</Link>
          <Link to="/catalog">{t("nav.catalog")}</Link>
        </div>
      </Card>

      <Card title={t("judge.title")} right={<span style={{ color: "var(--fg-soft)" }}>{judge.data?.config?._updated || ""}</span>}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div>
            <div style={{ color: "var(--fg-soft)" }}>{t("judge.engine")}</div>
            <select value={engine} onChange={(e) => setEngine(e.target.value)} style={{ ...inp, width: "100%" }}>
              <option value="">—</option>
              {engines.map((i) => <option key={i.digest} value={i.ref}>{(i.ref || i.digest).split("@")[0].split("/").pop()}{i.signature ? " ✓" : ""}</option>)}
            </select>
            <div style={{ color: "var(--fg-soft)", marginTop: 8 }}>{t("judge.model")}</div>
            <input value={model} onChange={(e) => setModel(e.target.value)} placeholder={t("admin.modelPlaceholder")} style={{ ...inp, width: "100%" }} />
            <div style={{ color: "var(--fg-soft)", marginTop: 8 }}>{t("judge.url")}</div>
            <input value={jurl} onChange={(e) => setJurl(e.target.value)} placeholder="http://judge-engine:8000" style={{ ...inp, width: "100%" }} />
            <div style={{ color: "var(--fg-soft)", marginTop: 8 }}>{t("judge.min")}</div>
            <input value={min} onChange={(e) => setMin(e.target.value)} style={{ ...inp, width: 120 }} />
            <label style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 8 }}><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />{t("judge.enabled")}</label>
          </div>
          <div>
            <div style={{ color: "var(--fg-soft)" }}>{t("judge.template")}</div>
            <textarea value={template || t("judge.templateDefault")} onChange={(e) => setTemplate(e.target.value)} style={{ ...inp, width: "100%", height: 220, fontFamily: "var(--mono)" }} />
          </div>
        </div>
        <div style={{ marginTop: 10, display: "flex", gap: 8, alignItems: "center" }}>
          <button onClick={save} style={btn}>{t("common.save")}</button>
          <span style={{ color: "var(--fg-soft)" }}>{msg}</span>
        </div>
        {!engines.length ? <EmptyState text={t("admin.noEngines")} /> : null}
      </Card>

      <Card title={t("admin.other")}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <div>
            <div style={{ color: "var(--fg-soft)" }}>{t("admin.hfToken")}</div>
            <div style={{ color: "var(--fg-soft)", fontSize: 12 }}>{t("common.now")}: {hftok.data?.masked || "—"}</div>
            <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
              <input value={tokIn} onChange={(e) => setTokIn(e.target.value)} placeholder="hf_…" style={{ ...inp, flex: 1 }} />
              <button onClick={() => post("/hf/token", { token: tokIn }, setTokMsg, "ok").then(() => hftok.refetch())} style={btn}>{t("common.save")}</button>
              <button onClick={() => post("/hf/token", { token: "" }, setTokMsg, "ok").then(() => hftok.refetch())} style={btn2}>{t("common.delete")}</button>
            </div>
            <div style={{ color: "var(--fg-soft)", marginTop: 4 }}>{tokMsg}</div>

            <div style={{ color: "var(--fg-soft)", marginTop: 12 }}>{t("admin.domainMap")}</div>
            <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
              <input value={dcDomain} onChange={(e) => setDcDomain(e.target.value)} placeholder="domain" style={{ ...inp, flex: 1 }} />
              <input value={dcClass} onChange={(e) => setDcClass(e.target.value)} placeholder="class" style={{ ...inp, width: 140 }} />
              <button onClick={() => post("/domain-class", { domain: dcDomain, policy_class: dcClass }, setDcMsg, "ok").then(() => dcls.refetch())} style={btn}>{t("common.save")}</button>
            </div>
            <div style={{ color: "var(--fg-soft)", marginTop: 4 }}>
              {dcMsg} · unmapped: {(dcls.data?.unmapped || []).length} · overrides: {Object.keys(dcls.data?.overrides || {}).length}
            </div>

            <div style={{ color: "var(--fg-soft)", marginTop: 12 }}>{t("admin.quotaBytes")}</div>
            <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
              <input value={quotaBytes} onChange={(e) => setQuotaBytes(e.target.value)} placeholder={t("admin.quotaPlaceholder")} style={{ ...inp, flex: 1 }} />
              <button onClick={() => post("/hf/quota", { daily_bytes: quotaBytes ? Number(quotaBytes) : null }, setQuotaMsg, "ok").then(() => quota.refetch())} style={btn}>{t("common.set")}</button>
            </div>
            <div style={{ color: "var(--fg-soft)", marginTop: 4 }}>{quotaMsg}</div>
          </div>

          <div>
            <div style={{ color: "var(--fg-soft)" }}>{t("admin.rateLimit")}</div>
            <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
              <input value={rlRps} onChange={(e) => setRlRps(e.target.value)} placeholder="rps" style={{ ...inp, width: 110 }} />
              <input value={rlBurst} onChange={(e) => setRlBurst(e.target.value)} placeholder="burst" style={{ ...inp, width: 110 }} />
              <button onClick={() => post("/rate-limit", { rps: Number(rlRps || 0), burst: Number(rlBurst || 1) }, setRlMsg, "ok")} style={btn}>{t("common.apply")}</button>
            </div>
            <div style={{ color: "var(--fg-soft)", marginTop: 4 }}>{rlMsg}</div>

            <div style={{ color: "var(--fg-soft)", marginTop: 12 }}>{t("admin.syncCard")}</div>
            <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
              <button onClick={async () => { setSyncMsg("…"); try { const r = await api<any>("/sync", { method: "POST", body: "{}" }); setSyncMsg("ok " + JSON.stringify(r).slice(0, 160)); } catch (e) { setSyncMsg("ERR " + String((e as any)?.message || e)); } }} style={btn}>{t("admin.sync")}</button>
            </div>
            <div style={{ color: "var(--fg-soft)", marginTop: 4 }}>{syncMsg}</div>

            <div style={{ color: "var(--fg-soft)", marginTop: 12 }}>{t("admin.engineSign")}</div>
            <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
              <select value={signDigest} onChange={(e) => setSignDigest(e.target.value)} style={{ ...inp, flex: 1 }}>
                <option value="">—</option>
                {((imgs.data?.images as any[]) || []).map((i) => <option key={i.digest} value={i.digest}>{i.digest.slice(0, 16)} {i.signature ? "✓" : ""}</option>)}
              </select>
              <button disabled={!signDigest} onClick={() => post(`/images/${encodeURIComponent(signDigest)}/sign`, {}, setSignMsg, "ok").then(() => imgs.refetch())} style={btn}>{t("admin.sign")}</button>
            </div>
            <div style={{ color: "var(--fg-soft)", marginTop: 4 }}>{signMsg}</div>
          </div>
        </div>
      </Card>

      <Card title={t("admin.quota")}>
        {quota.isError ? <EmptyState text={t("common.error")} /> : <pre style={pre}>{JSON.stringify(quota.data || {}, null, 2)}</pre>}
      </Card>
      <Card title={t("admin.egress")}>
        {egress.isError ? <EmptyState text={t("common.error")} /> : <pre style={pre}>{JSON.stringify(egress.data || {}, null, 2)}</pre>}
      </Card>
      <Card title={t("admin.audit")}>
        {audit.isError ? <EmptyState text={t("common.error")} /> : <pre style={pre}>{JSON.stringify(audit.data || {}, null, 2)}</pre>}
      </Card>
      <Card title={t("admin.cache")}>
        {cache.isError ? <EmptyState text={t("common.error")} />
          : <div>{t("common.items")}: {(cache.data?.count ?? (cache.data?.entries || []).length) || 0} · {t("common.total")}: {((cache.data?.total_bytes || 0) / 1e9).toFixed(2)} GB · {t("common.target")} {cache.data?.target_gb ?? "—"} GB · {cache.data?.updated || ""}</div>}
      </Card>
    </div>
  );
}
const pre: React.CSSProperties = { maxHeight: 260, overflow: "auto", background: "var(--bg-soft)", padding: 12, borderRadius: 8, fontSize: 12 };
const inp: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 10px" };
const btn: React.CSSProperties = { background: "#3d7dd8", color: "#fff", border: 0, borderRadius: 6, padding: "8px 14px" };
const btn2: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 14px" };
