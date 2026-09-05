import { Link, useNavigate } from "react-router-dom";
import { useState } from "react";
import { useStream, fmtTime, scoreColor, tierColor, post } from "../api";
import Pipeline from "../components/Pipeline";
import { Gauge, Meter, Badge, DomainIcon, Heartbeat, BeatDot } from "../components/widgets";

export default function Overview() {
  const { frame, connected } = useStream();
  const [expanded, setExpanded] = useState(false);
  const [speed, setSpeed] = useState(0.6);
  const nav = useNavigate();

  if (!frame) return <div className="empty">{connected ? "Waiting for the first frame…" : "Connecting to the backend…"}</div>;
  const { agents, verdict, timeline, log, budget, contained, events_seen, open_incidents, simulations, population } = frame;
  const containedList = Object.entries(contained || {});

  const pipelineCard = (
    <div className="card" style={expanded ? {
      position: "fixed", inset: 16, zIndex: 60, display: "flex", flexDirection: "column",
      boxShadow: "0 20px 60px rgba(27,42,65,.28)",
    } : {}}>
      <div className="hd">
        <h3>Agent Pipeline</h3>
        <span style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <span style={{ display: "flex", alignItems: "center", gap: 7 }}>
            <span style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".5px" }}>Flow</span>
            <input type="range" min="0.25" max="2.5" step="0.05" value={speed}
              onChange={(e) => setSpeed(+e.target.value)}
              style={{ width: 92, accentColor: "#1b2a41" }} />
            <span className="mono" style={{ fontSize: 11, color: "var(--muted)", width: 30 }}>{speed.toFixed(1)}x</span>
          </span>
          <span className="meta" style={{ color: connected ? "var(--green)" : "var(--muted)" }}>● {connected ? "Live" : "reconnecting"}</span>
          <button style={{ fontSize: 11.5, padding: "5px 10px" }} onClick={() => setExpanded((x) => !x)}>
            {expanded ? "Exit full view" : "Full view"}
          </button>
        </span>
      </div>
      <div className="bd" style={{ padding: "4px 10px 0", flex: 1, display: "flex", flexDirection: "column", justifyContent: "center" }}>
        <Pipeline agents={agents} verdict={verdict} pulses={frame.pulses} speed={speed} expanded={expanded} />
        <div className="legend">
          <span className="it"><span className="sw" style={{ background: "var(--green)" }} />Normal</span>
          <span className="it"><span className="sw" style={{ background: "var(--amber)" }} />Elevated</span>
          <span className="it"><span className="sw" style={{ background: "var(--red)" }} />Malicious</span>
          <span className="it"><span className="sw" style={{ background: "var(--ink-2)" }} />Evidence in flight</span>
        </div>
      </div>
    </div>
  );

  return (
    <div>
      {expanded && <div onClick={() => setExpanded(false)}
        style={{ position: "fixed", inset: 0, background: "rgba(27,42,65,.35)", zIndex: 50 }} />}

      <div className="grid" style={{ gridTemplateColumns: "repeat(6,1fr)", marginBottom: 16 }}>
        <Stat label="Focus" value={verdict.name || verdict.entity} mono={false} color={tierColor(verdict.tier)} />
        <Stat label="Insider risk" value={verdict.risk.toFixed(2)} color={tierColor(verdict.tier)} />
        <Stat label="Conflict K" value={verdict.conflict.toFixed(2)} color={verdict.alarm ? "var(--red)" : "var(--ink)"} />
        <Stat label="Open cases" value={open_incidents ?? 0} />
        <Stat label="Monitored" value={population ?? 0} />
        <Stat label="Events" value={events_seen} />
      </div>

      {(simulations || []).length > 0 && (
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 14, flexWrap: "wrap" }}>
          {simulations.map((s) => (
            <span key={s.id} style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12.5,
              border: "1px solid var(--amber-b)", background: "var(--amber-w)", color: "var(--amber)",
              padding: "5px 11px", borderRadius: 7, fontWeight: 600 }}>
              {s.label} → {s.name}
              {s.poison_agent && <Badge kind="malicious">{s.poison_agent} subverted</Badge>}
            </span>
          ))}
          <Link to="/simulate" style={{ fontSize: 12.5, color: "var(--ink-2)", fontWeight: 600 }}>manage →</Link>
        </div>
      )}

      {verdict.alarm && (
        <div className="alarm-banner"><span className="bd2" />
          Conflict alarm — a detection agent is contradicting the consensus about {verdict.name || verdict.entity}.
          It has been discounted; containment continues on the honest agents. (This is the case the base study cannot handle.)
        </div>
      )}

      <div className="grid" style={{ gridTemplateColumns: "300px 1fr 300px" }}>
        {/* agents */}
        <div className="card">
          <div className="hd"><h3>Detection Agents</h3><span className="meta">{agents.length}/4 online</span></div>
          <div className="bd" style={{ paddingTop: 2 }}>
            {agents.map((a) => (
              <div key={a.id} onClick={() => nav("/agents/" + a.id)}
                style={{ padding: "11px 0", borderTop: "1px solid var(--line-2)", cursor: "pointer" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <BeatDot beat={a.beat} color={a.poisoned ? "var(--red)" : scoreColor(a.score)} />
                    <DomainIcon domain={a.domain} size={15} />
                    <span style={{ fontWeight: 600 }}>{a.id}</span>
                    {a.poisoned && <Badge kind="malicious">subverted</Badge>}
                  </span>
                  <span className="mono" style={{ fontWeight: 600, color: scoreColor(a.score) }}>{a.score.toFixed(2)}</span>
                </div>
                <div style={{ marginTop: 6 }}>
                  <Heartbeat beat={a.beat} score={a.score} poisoned={a.poisoned} w={210} h={30} />
                </div>
                <div className="mono" style={{ display: "flex", justifyContent: "space-between", marginTop: 3, fontSize: 10.5, color: "var(--muted)" }}>
                  <span>conf {a.confidence.toFixed(2)}</span><span>reliab {a.reliability.toFixed(2)}</span>
                </div>
              </div>
            ))}
            <div style={{ marginTop: 10, fontSize: 11.5 }}>
              <Link to="/agents" style={{ color: "var(--ink-2)", fontWeight: 600 }}>Agent details →</Link>
            </div>
          </div>
        </div>

        {pipelineCard}

        {/* right rail */}
        <div className="card">
          <div className="hd"><h3>Risk &amp; Conflict</h3></div>
          <div className="bd">
            <Gauge value={verdict.risk} tier={verdict.tier} />
            <div style={{ fontSize: 10.5, color: "var(--muted)", textAlign: "center", textTransform: "uppercase", letterSpacing: ".6px" }}>Insider Risk</div>
            {verdict.name && <div style={{ textAlign: "center", fontSize: 12.5, marginTop: 3 }}>
              <Link to={"/entities/" + verdict.entity} style={{ color: "var(--ink-2)", fontWeight: 600 }}>{verdict.name} →</Link>
            </div>}
            <div style={{ marginTop: 12 }}>
              <Meter label="Conflict mass K" value={verdict.conflict} danger={verdict.alarm} />
              <Meter label="Budget pressure (mu)" value={budget?.mu ?? 0} max={3} color="var(--ink-2)" />
            </div>
            <div style={{ marginTop: 14, borderTop: "1px solid var(--line-2)", paddingTop: 11 }}>
              <div style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".5px", marginBottom: 7 }}>Contained</div>
              {containedList.length ? containedList.map(([e, k]) => (
                <div key={e} className="mono" style={{ fontSize: 12, marginBottom: 3 }}>
                  <Link to={"/entities/" + e}>{e.replace("user:", "")}</Link> <span style={{ color: "var(--red)" }}>· {k}</span>
                </div>
              )) : <div style={{ color: "var(--faint)", fontSize: 12 }}>none</div>}
            </div>
          </div>
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1.5fr 1fr", marginTop: 16 }}>
        <div className="card">
          <div className="hd"><h3>Response Timeline</h3><Link to="/incidents" className="meta" style={{ color: "var(--ink-2)" }}>All incidents →</Link></div>
          <div className="bd" style={{ padding: 0 }}>
            {(timeline || []).length ? timeline.map((a, i) => (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "66px 160px 1fr 150px", gap: 12, alignItems: "center", padding: "9px 16px", borderTop: i ? "1px solid var(--line-2)" : "none", fontSize: 12.5 }}>
                <span className="mono" style={{ color: "var(--muted)", fontSize: 11 }}>{fmtTime(a.ts)}</span>
                <span style={{ display: "flex", alignItems: "center", gap: 7, fontWeight: 600, whiteSpace: "nowrap" }}>
                  <Badge kind={a.tier}>{a.tier}</Badge><span>{verb(a.kind)}</span>
                  {!a.approved && <span style={{ color: "var(--amber)", fontSize: 10, fontWeight: 600 }}>hold</span>}
                </span>
                <span style={{ opacity: .85, overflow: "hidden", textOverflow: "ellipsis" }}>
                  <b>{a.name}</b> — {a.reason}
                </span>
                <span className="mono" style={{ fontSize: 10.5, color: "var(--ink-2)", textAlign: "right" }}>{a.mitre}</span>
              </div>
            )) : <div className="empty">No actions yet — start a simulation.</div>}
          </div>
        </div>
        <div className="card">
          <div className="hd"><h3>Event Log</h3></div>
          <div className="bd scroll" style={{ maxHeight: 280, padding: 0 }}>
            {(log || []).map((l, i) => (
              <div key={i} style={{ display: "flex", gap: 10, padding: "6px 16px", borderTop: i ? "1px solid var(--line-2)" : "none", fontSize: 12 }}>
                <span className="mono" style={{ color: "var(--muted)", fontSize: 11, whiteSpace: "nowrap" }}>{l.ts}</span>
                <span style={{ opacity: .9 }}>{l.text}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, color, mono = true }) {
  return (
    <div className="card" style={{ padding: "12px 14px" }}>
      <div style={{ fontSize: 10, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".5px" }}>{label}</div>
      <div className={mono ? "mono" : ""} style={{ fontSize: mono ? 20 : 14, fontWeight: 650, marginTop: 4, color: color || "var(--ink)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</div>
    </div>
  );
}
const verb = (k) => ({ monitor: "Monitor", step_up: "Step-up auth", restrict: "Restrict", quarantine: "Quarantine", suspend: "Suspend" }[k] || k);
