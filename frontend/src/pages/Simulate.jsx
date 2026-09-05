import { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { getJSON, post, usePoll } from "../api";
import { Badge, DomainIcon } from "../components/widgets";

const KIND_HELP = {
  identity: "Odd-hour logons, failed authentication, an unfamiliar location.",
  file: "Access to sensitive files and large writes to removable media.",
  network: "Outbound volume spikes to a destination never seen before.",
  host: "Rare process execution, persistence, quiet beaconing.",
  lateral: "Movement toward hosts the account has never touched.",
};

export default function Simulate() {
  const nav = useNavigate();
  const [sp] = useSearchParams();
  const [meta, setMeta] = useState(null);
  const [ents, setEnts] = useState([]);
  const [uid, setUid] = useState(sp.get("uid") || "");
  const [playbook, setPlaybook] = useState("exfiltration");
  const [custom, setCustom] = useState([]);
  const [intensity, setIntensity] = useState("medium");
  const [poison, setPoison] = useState("");
  const [msg, setMsg] = useState(null);
  const { data: live } = usePoll("/api/simulations", 1500);

  useEffect(() => {
    getJSON("/api/meta").then(setMeta).catch(() => {});
    getJSON("/api/entities").then((d) => {
      setEnts(d.entities);
      if (!sp.get("uid") && d.entities.length) setUid(d.entities[0].uid);
    }).catch(() => {});
  }, []);

  if (!meta) return <div className="empty">Loading…</div>;
  const pb = meta.playbooks.find((p) => p.id === playbook);
  const kinds = custom.length ? custom : (pb?.kinds || []);
  // only offer to subvert an agent that is actually involved in this activity
  const relevant = meta.agents.filter((a) =>
    kinds.includes(a.domain) || (kinds.includes("lateral") && ["host", "network"].includes(a.domain)));

  const launch = async () => {
    const body = { uid, playbook, intensity, poison_agent: poison || null };
    if (custom.length) body.kinds = custom;
    const r = await post("/api/simulate", body);
    const d = await r.json();
    setMsg(d.simulation ? `Started: ${d.simulation.label} on ${d.simulation.name}` : "Failed to start");
    setTimeout(() => setMsg(null), 4000);
  };
  const stopAll = async () => { await post("/api/simulations/stop"); };
  const stopOne = async (id) => { await post(`/api/simulation/${id}/stop`); };

  const toggleKind = (k) =>
    setCustom((c) => c.includes(k) ? c.filter((x) => x !== k) : [...c, k]);

  const chosen = ents.find((e) => e.uid === uid);

  return (
    <div>
      <div className="pagehd">
        <div>
          <h1>Simulate</h1>
          <p>Stage insider activity against any member of the department and watch the agents respond.
             Pick a playbook, or compose your own from the individual activity kinds.</p>
        </div>
        {(live?.simulations || []).length > 0 &&
          <button onClick={stopAll}>Stop all ({live.simulations.length})</button>}
      </div>

      {msg && <div className="alarm-banner" style={{ background: "var(--green-w)", borderColor: "var(--green-b)", color: "var(--green)" }}>{msg}</div>}

      <div className="grid" style={{ gridTemplateColumns: "1fr 340px" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {/* target */}
          <div className="card">
            <div className="hd"><h3>1 · Target</h3></div>
            <div className="bd">
              <select value={uid} onChange={(e) => setUid(e.target.value)}
                style={{ width: "100%", padding: "9px 11px", border: "1px solid var(--line)", borderRadius: 8, fontSize: 13.5, fontFamily: "var(--sans)" }}>
                {meta.categories.map((c) => (
                  <optgroup key={c} label={c}>
                    {ents.filter((e) => e.category === c).map((e) => (
                      <option key={e.uid} value={e.uid}>{e.name} — {e.role} ({e.host})</option>
                    ))}
                  </optgroup>
                ))}
              </select>
              {chosen && (
                <div className="kv" style={{ marginTop: 12, gridTemplateColumns: "94px 1fr" }}>
                  <span className="k">Host</span><span className="v mono">{chosen.host}</span>
                  <span className="k">IP</span><span className="v mono">{chosen.ip}</span>
                  <span className="k">Clearance</span><span className="v">{chosen.clearance}</span>
                  <span className="k">Current risk</span><span className="v"><Badge kind={chosen.tier}>{chosen.tier}</Badge></span>
                </div>
              )}
            </div>
          </div>

          {/* playbook */}
          <div className="card">
            <div className="hd"><h3>2 · Playbook</h3></div>
            <div className="bd" style={{ display: "grid", gap: 9 }}>
              {meta.playbooks.map((p) => (
                <label key={p.id} style={{
                  display: "flex", gap: 11, alignItems: "flex-start", padding: "11px 12px",
                  border: "1px solid " + (playbook === p.id ? "var(--ink)" : "var(--line)"),
                  borderRadius: 9, cursor: "pointer",
                  background: playbook === p.id ? "var(--page)" : "transparent",
                }}>
                  <input type="radio" name="pb" checked={playbook === p.id}
                    onChange={() => { setPlaybook(p.id); setCustom([]); }} style={{ marginTop: 3 }} />
                  <span>
                    <b style={{ fontSize: 13.5 }}>{p.label}</b>
                    <div style={{ color: "var(--muted)", fontSize: 12.5, marginTop: 2 }}>{p.story}</div>
                    <div style={{ display: "flex", gap: 5, marginTop: 6 }}>
                      {p.kinds.map((k) => <Badge key={k} kind="Normal">{k}</Badge>)}
                    </div>
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* custom kinds */}
          <div className="card">
            <div className="hd"><h3>3 · Or compose the activity yourself</h3>
              {custom.length > 0 && <button style={{ fontSize: 11 }} onClick={() => setCustom([])}>clear</button>}</div>
            <div className="bd" style={{ display: "grid", gap: 8 }}>
              {meta.kinds.map((k) => (
                <label key={k} style={{
                  display: "flex", gap: 10, alignItems: "center", padding: "9px 11px",
                  border: "1px solid " + (custom.includes(k) ? "var(--ink)" : "var(--line)"),
                  borderRadius: 8, cursor: "pointer",
                }}>
                  <input type="checkbox" checked={custom.includes(k)} onChange={() => toggleKind(k)} />
                  <DomainIcon domain={k === "lateral" ? "host" : k} size={16} />
                  <span><b style={{ fontSize: 13 }}>{k}</b>
                    <span style={{ color: "var(--muted)", fontSize: 12.5 }}> — {KIND_HELP[k]}</span></span>
                </label>
              ))}
              {custom.length > 0 && <div style={{ fontSize: 12, color: "var(--ink-2)" }}>
                Custom activity overrides the playbook above.</div>}
            </div>
          </div>
        </div>

        {/* right: options + launch + running */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="card">
            <div className="hd"><h3>4 · Options</h3></div>
            <div className="bd">
              <div style={{ fontSize: 11, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".5px", marginBottom: 6 }}>Intensity</div>
              <div style={{ display: "flex", gap: 6 }}>
                {meta.intensities.map((i) => (
                  <button key={i} className={intensity === i ? "primary" : ""} onClick={() => setIntensity(i)}
                    style={{ flex: 1, textTransform: "capitalize" }}>{i}</button>
                ))}
              </div>

              <div style={{ fontSize: 11, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".5px", margin: "14px 0 6px" }}>
                Subvert an agent (optional)
              </div>
              <select value={poison} onChange={(e) => setPoison(e.target.value)}
                style={{ width: "100%", padding: "8px 10px", border: "1px solid var(--line)", borderRadius: 8, fontSize: 13 }}>
                <option value="">none — all agents honest</option>
                {relevant.map((a) => <option key={a.id} value={a.id}>{a.title} ({a.id})</option>)}
              </select>
              <p style={{ fontSize: 12, color: "var(--muted)", marginTop: 8 }}>
                A subverted agent reports <b>benign</b> while its peers report malicious. The fusion
                layer should raise a conflict alarm, discount it, and contain the threat anyway.
              </p>
              {relevant.length === 0 && <p style={{ fontSize: 12, color: "var(--amber)" }}>
                No agent observes the chosen activity, so none can be meaningfully subverted.</p>}

              <button className="primary" onClick={launch} disabled={!uid}
                style={{ width: "100%", marginTop: 14, padding: "11px" }}>
                Launch simulation
              </button>
            </div>
          </div>

          <div className="card">
            <div className="hd"><h3>Running now</h3><span className="meta">{(live?.simulations || []).length}</span></div>
            <div className="bd" style={{ padding: 0 }}>
              {(live?.simulations || []).length ? live.simulations.map((s) => (
                <div key={s.id} style={{ padding: "11px 16px", borderTop: "1px solid var(--line-2)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <b style={{ fontSize: 13 }}>{s.label}</b>
                    <button style={{ fontSize: 11, padding: "3px 8px" }} onClick={() => stopOne(s.id)}>stop</button>
                  </div>
                  <div style={{ fontSize: 12.5, color: "var(--muted)" }}>{s.name} · {s.host}</div>
                  <div style={{ display: "flex", gap: 5, marginTop: 6, flexWrap: "wrap" }}>
                    {s.kinds.map((k) => <Badge key={k} kind="High">{k}</Badge>)}
                    {s.poison_agent && <Badge kind="malicious">{s.poison_agent} subverted</Badge>}
                  </div>
                </div>
              )) : <div className="empty">Nothing running.</div>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
