import { Link, useParams } from "react-router-dom";
import { usePoll, getJSON, fmtTime, scoreColor, tierColor } from "../api";
import { useEffect, useState } from "react";
import { Badge, Sparkline, DomainIcon } from "../components/widgets";

export default function IncidentDetail() {
  const { id } = useParams();
  const { data: inc } = usePoll("/api/incident/" + id, 2000, [id]);
  const [ent, setEnt] = useState(null);

  useEffect(() => {
    if (inc?.entity) getJSON("/api/entity/" + inc.entity).then(setEnt).catch(() => {});
  }, [inc?.entity]);

  if (!inc) return <div className="empty">Loading case…</div>;
  if (inc.error) return <div className="empty">Incident not found.</div>;

  return (
    <div>
      <Link to="/incidents" className="back">← All incidents</Link>
      <div className="pagehd">
        <div>
          <h1>{inc.id} <span className="mono" style={{ fontSize: 16, color: "var(--muted)", fontWeight: 500 }}>· {inc.entity}</span></h1>
          <p>{ent?.name} — {ent?.role}, {ent?.department}. Case {inc.status.toLowerCase()}{inc.alarm ? ", conflict alarm raised." : "."}</p>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <Badge kind={inc.peak_tier}>{inc.peak_tier}</Badge>
          <Badge kind={inc.status}>{inc.status}</Badge>
          {inc.alarm && <Badge kind="malicious">poisoning alarm</Badge>}
        </div>
      </div>

      {inc.alarm && (
        <div className="alarm-banner"><span className="bd2" />
          Agent poisoning detected — <b style={{ margin: "0 4px" }}>{inc.poisoned_agent}</b> contradicted the consensus (conflict K peaked at {inc.max_conflict.toFixed(2)}). It was discounted and containment proceeded on the honest agents.
        </div>
      )}

      {/* summary tiles */}
      <div className="grid" style={{ gridTemplateColumns: "repeat(4,1fr)", marginBottom: 16 }}>
        <Tile label="Peak insider risk" value={inc.peak_risk.toFixed(2)} color={tierColor(inc.peak_tier)} />
        <Tile label="Max conflict K" value={inc.max_conflict.toFixed(2)} color={inc.alarm ? "var(--red)" : "var(--ink)"} />
        <Tile label="Evidence events" value={inc.n_events} />
        <Tile label="Response actions" value={inc.n_actions} />
      </div>

      <div className="grid" style={{ gridTemplateColumns: "320px 1fr" }}>
        {/* LEFT: subject + evidence + risk chart */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {/* subject identity */}
          <div className="card">
            <div className="hd"><h3>Subject</h3></div>
            <div className="bd">
              {ent ? (
                <div className="kv">
                  <span className="k">Name</span><span className="v">{ent.name}</span>
                  <span className="k">Username</span><span className="v mono">{ent.username}</span>
                  <span className="k">Department</span><span className="v">{ent.department}</span>
                  <span className="k">Role</span><span className="v">{ent.role}</span>
                  <span className="k">Host</span><span className="v mono">{ent.host}</span>
                  <span className="k">IP address</span><span className="v mono">{ent.ip}</span>
                  <span className="k">Device ID</span><span className="v mono">{ent.device_id}</span>
                  <span className="k">Manager</span><span className="v">{ent.manager}</span>
                  <span className="k">Clearance</span><span className="v">{ent.clearance}</span>
                  <span className="k">Location</span><span className="v">{ent.location}</span>
                  <span className="k">Normal hours</span><span className="v mono">{ent.normal_hours}</span>
                  <span className="k">Status</span><span className="v">{ent.contained ? <Badge kind="malicious">{ent.contained}</Badge> : <Badge kind="Normal">active</Badge>}</span>
                </div>
              ) : <div style={{ color: "var(--faint)" }}>Loading subject…</div>}
              <Link to={"/entities/" + inc.entity} className="back" style={{ marginTop: 12, marginBottom: 0 }}>Full entity profile →</Link>
            </div>
          </div>

          {/* per-agent evidence */}
          <div className="card">
            <div className="hd"><h3>Agent Evidence</h3></div>
            <div className="bd" style={{ paddingTop: 2 }}>
              {Object.entries(inc.agent_evidence || {}).map(([aid, ev]) => (
                <div key={aid} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "9px 0", borderTop: "1px solid var(--line-2)" }}>
                  <span style={{ fontWeight: 600 }}>{aid}</span>
                  <span style={{ display: "flex", gap: 14 }} className="mono">
                    <span style={{ color: scoreColor(ev.score) }}>score {ev.score.toFixed(2)}</span>
                    <span style={{ color: ev.reliability <= 0.1 ? "var(--red)" : "var(--muted)" }}>reliab {ev.reliability.toFixed(2)}</span>
                  </span>
                </div>
              ))}
              <p style={{ fontSize: 11.5, color: "var(--muted)", marginTop: 10 }}>The fusion agent weighs each agent by reliability; an agent that contradicts its own history (a subverted sensor) is discounted toward zero.</p>
            </div>
          </div>

          {/* risk over time */}
          <div className="card">
            <div className="hd"><h3>Risk &amp; Conflict over time</h3></div>
            <div className="bd">
              <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 2 }}>Insider risk</div>
              <Sparkline data={inc.risk_series} color="var(--red)" h={38} w={280} />
              <div style={{ fontSize: 11, color: "var(--muted)", margin: "8px 0 2px" }}>Conflict mass K</div>
              <Sparkline data={inc.conflict_series} color="var(--amber)" h={38} w={280} />
            </div>
          </div>
        </div>

        {/* RIGHT: MITRE + actions + trace */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="card">
            <div className="hd"><h3>MITRE ATT&amp;CK techniques observed</h3></div>
            <div className="bd" style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {(inc.mitre || []).length ? inc.mitre.map((m) => (
                <span key={m} className="mono" style={{ fontSize: 12, background: "var(--page)", border: "1px solid var(--line)", padding: "5px 10px", borderRadius: 6, color: "var(--ink-2)" }}>{m}</span>
              )) : <span style={{ color: "var(--faint)" }}>none</span>}
            </div>
          </div>

          <div className="card">
            <div className="hd"><h3>Response Actions</h3><span className="meta">{inc.actions.length} total</span></div>
            <div className="bd scroll" style={{ maxHeight: 230, padding: 0 }}>
              <table>
                <thead><tr><th>Tick</th><th>Tier</th><th>Action</th><th>Approved</th><th>mu</th><th>Reason</th></tr></thead>
                <tbody>
                  {[...inc.actions].reverse().map((a, i) => (
                    <tr key={i}>
                      <td className="mono">{a.tick}</td>
                      <td><Badge kind={a.tier}>{a.tier}</Badge></td>
                      <td style={{ fontWeight: 600 }}>{verb(a.kind)}</td>
                      <td>{a.approved ? <span style={{ color: "var(--green)" }}>yes</span> : <span style={{ color: "var(--amber)" }}>hold</span>}</td>
                      <td className="mono">{a.mu.toFixed(2)}</td>
                      <td style={{ fontSize: 11.5, opacity: .85 }}>{a.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card">
            <div className="hd"><h3>Event Trace</h3><span className="meta">most recent {Math.min(inc.trace.length, 60)} events</span></div>
            <div className="bd scroll" style={{ maxHeight: 340, padding: 0 }}>
              <table>
                <thead><tr><th>Tick</th><th>Domain</th><th>Kind</th><th>Detail</th><th>Score</th></tr></thead>
                <tbody>
                  {[...inc.trace].reverse().map((r, i) => (
                    <tr key={i}>
                      <td className="mono">{r.tick}</td>
                      <td><span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}><DomainIcon domain={r.domain} size={14} color="var(--muted)" />{r.domain}</span></td>
                      <td className="mono" style={{ fontSize: 12 }}>{r.kind}</td>
                      <td style={{ fontSize: 12 }}>{r.detail}</td>
                      <td className="mono" style={{ color: scoreColor(r.score) }}>{r.score.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Tile({ label, value, color }) {
  return (
    <div className="card" style={{ padding: "13px 15px" }}>
      <div style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".5px" }}>{label}</div>
      <div className="mono" style={{ fontSize: 22, fontWeight: 650, marginTop: 4, color: color || "var(--ink)" }}>{value}</div>
    </div>
  );
}
const verb = (k) => ({ monitor: "Monitor", step_up: "Step-up auth", restrict: "Restrict", quarantine: "Quarantine", suspend: "Suspend" }[k] || k);
