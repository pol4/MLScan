import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { Card, Table, Td, EmptyState, ErrorState, SeverityTag } from "../components/ui";
import { useI18n } from "../i18n";

const gb = (n?: number) => (n ? (n / 1e9).toFixed(2) + " GB" : "—");

export default function Catalog() {
  const { t } = useI18n();
  const imgs = useQuery({ queryKey: ["images"], queryFn: () => api<any>("/images/list"), retry: false });
  const packs = useQuery({ queryKey: ["testpacks"], queryFn: () => api<any>("/v4/testpacks"), retry: false });
  const dsets = useQuery({ queryKey: ["datasets"], queryFn: () => api<any>("/v4/datasets"), retry: false });
  const psets = useQuery({ queryKey: ["promptsets"], queryFn: () => api<any>("/prompt-sets"), retry: false });

  const images = (imgs.data?.images as any[]) || [];
  const packsList = (packs.data?.testpacks as any[]) || (packs.data?.packs as any[]) || [];
  const datasets = (dsets.data?.datasets as any[]) || [];
  const psRaw: any = psets.data;
  // analytics /prompt-sets отдаёт активный набор объектом ({version,name,cases,…}); тестинг — {prompt_sets:[…]}.
  const ps: any[] = psRaw?.prompt_sets || (psRaw?.version ? [psRaw] : []);

  const [packText, setPackText] = useState("{\n  \"id\": \"llm-custom\",\n  \"version\": 1,\n  \"applies_to\": {\"engines\": [\"kind:llm\"]},\n  \"steps\": [{\"type\": \"load\"}, {\"type\": \"invoke\", \"dataset\": \"rt\", \"params\": {\"max_tokens\": 64}}, {\"type\": \"assert\", \"over\": [\"responses\"]}]\n}");
  const [msg, setMsg] = useState("");
  const savePack = async () => { setMsg(t("common.saving")); try { await api("/v4/testpacks", { method: "POST", body: JSON.stringify({ pack: JSON.parse(packText) }) }); setMsg(t("cat.packSaved")); packs.refetch(); } catch (e) { setMsg("ERR " + String((e as any)?.message || e)); } };
  const activate = async (ver: string) => { try { await api("/prompt-sets/activate", { method: "POST", body: JSON.stringify({ version: ver }) }); psets.refetch(); } catch (e) { alert("ERR " + String((e as any)?.message || e)); } };
  const importXlsx = async (f: File) => {
    setMsg(t("cat.importing"));
    const b64 = await new Promise<string>((res) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(",")[1] || ""); r.readAsDataURL(f); });
    try { const r = await api<any>("/prompt-sets", { method: "POST", body: JSON.stringify({ name: f.name, content_b64: b64 }) });
      setMsg(`${t("run.promptSetLabel")} ${r.version || ""} ${r.warnings ? "· " + r.warnings.length + " " + t("cat.warningsShort") : ""}`); psets.refetch(); }
    catch (e) { setMsg("ERR " + String((e as any)?.message || e)); }
  };

  return (
    <div>
      <Card title={t("cat.engines")}>
        {imgs.isError ? <ErrorState error={imgs.error} onRetry={() => imgs.refetch()} /> : !images.length ? <EmptyState text={t("common.empty")} />
          : <Table head={[t("col.name"), "type", t("col.size"), ""]}>
            {images.map((i) => (<tr key={i.digest}><Td><code>{(i.ref || i.digest).split("@")[0].split("/").pop()}</code></Td>
              <Td>{i.type || "—"}</Td><Td>{gb(i.size)}</Td><Td>{i.signature ? <span style={{ color: "var(--ok)" }}>✓ {t("cat.signed")}</span> : <SeverityTag sev="high" />}</Td></tr>))}
          </Table>}
      </Card>

      <Card title={t("cat.testpacks")} right={(packsList.length ? packsList.length : "")}>
        {!packsList.length ? <EmptyState text={t("common.empty")} />
          : <Table head={["id", "version", "artifact_kinds", "engines"]}>
            {packsList.map((p, i) => (<tr key={(p.id || i) + "@" + (p.version || "")}><Td>{p.id}</Td><Td>{p.version ?? "—"}</Td>
              <Td>{(p.applies_to?.artifact_kinds || []).join(", ") || "—"}</Td><Td>{(p.applies_to?.engines || []).join(", ") || "—"}</Td></tr>))}
          </Table>}
        <div style={{ marginTop: 10 }}>
          <div style={{ color: "var(--fg-soft)" }}>{t("cat.newPack")}</div>
          <textarea value={packText} onChange={(e) => setPackText(e.target.value)} spellCheck={false} style={{ ...inp, width: "100%", height: 180, fontFamily: "var(--mono)" }} />
          <div style={{ marginTop: 6 }}><button onClick={savePack} style={btn}>{t("cat.save")}</button> <span style={{ color: "var(--fg-soft)" }}>{msg}</span></div>
        </div>
      </Card>

      <Card title={t("cat.datasets")}>
        {!datasets.length ? <EmptyState text={t("common.empty")} />
          : <Table head={["id/ref", "kind", "items"]}>
            {datasets.map((d, i) => (<tr key={d.id || i}><Td>{d.id || d.ref || "—"}</Td><Td>{d.kind || "—"}</Td><Td>{d.count ?? d.items ?? "—"}</Td></tr>))}
          </Table>}
      </Card>

      <Card title={t("cat.prompts")} right={<label style={btn}>{t("cat.upload")}<input type="file" accept=".xlsx" style={{ display: "none" }} onChange={(e) => { const f = e.target.files?.[0]; if (f) importXlsx(f); }} /></label>}>
        {!ps.length ? <EmptyState text={t("common.empty")} />
          : <Table head={["version", "name", "cases", ""]}>
            {ps.map((p) => (<tr key={p.version}><Td>{p.version}{p.active ? <b style={{ color: "var(--ok)" }}> · {t("cat.active")}</b> : ""}</Td>
              <Td>{p.name || "—"}</Td><Td>{p.cases ?? "—"}</Td>
              <Td>{!p.active ? <button onClick={() => activate(p.version)} style={btn}>{t("cat.activate")}</button> : null}</Td></tr>))}
          </Table>}
      </Card>
    </div>
  );
}
const inp: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 10px" };
const btn: React.CSSProperties = { background: "var(--bg-soft)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 12px", cursor: "pointer" };
