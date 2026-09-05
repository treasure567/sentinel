import { Link, useParams, useNavigate, useSearchParams } from "react-router-dom";
import { useState } from "react";
import { usePoll, post, fmtTime, scoreColor } from "../api";
import { Badge, Gauge, DomainIcon, Meter } from "../components/widgets";
import Terminal from "../components/Terminal";

const TABS = [["profile", "Profile"], ["pc", "Workstation"], ["shell", "Remote Shell"],
              ["events", "Event Trace"], ["cases", "Cases"]];

export default function EntityDetail() {
  const { uid } = useParams();
  const nav = useNavigate();
  const [sp, setSp] = useSearchParams();
  const tab = sp.get("tab") || "profile";
  const { data: e } = usePoll("/api/entity/" + encodeURIComponent(uid), 1500, [uid]);
  const { data: pc } = usePoll("/api/entity/" + encodeURIComponent(uid) + "/pc", 2000, [uid]);

  if (!e) return <div className="empty">Loading profile…</div>;
  if (e.error) return <div className="empty">Entity not found.</div>;

  const act = async (what, value) => { await post(`/api/entity/${encodeURIComponent(uid)}/${what}`, { value }); };

  return (
    <div>
      <Link to="/entities" className="back">← All entities</Link>
      <div className="pagehd">
        <div>
          <h1>{e.name} <span className="mono" style={{ fontSize: 15, color: "var(--muted)", fontWeight: 500 }}>· {e.username}</span></h1>
          <p>{e.role} · {e.unit} · {e.location}</p>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <Badge kind={e.tier}>{e.tier} risk</Badge>
          {e.isolated && <Badge kind="malicious">isolated</Badge>}
          {e.traffic_paused && <Badge kind="Closed">telemetry paused</Badge>}
          <button onClick={() => act("isolate", !e.isolated)}>{e.isolated ? "Restore to network" : "Isolate host"}</button>
          <button onClick={() => act("pause", !e.traffic_paused)}>{e.traffic_paused ? "Resume telemetry" : "Pause telemetry"}</button>
          <button className="primary" onClick={() => nav("/simulate?uid=" + encodeURIComponent(uid))}>Run simulation</button>
        </div>
      </div>

      {(e.active_kinds || []).length > 0 && (
        <div className="alarm-banner" style={{ background: "var(--amber-w)", borderColor: "var(--amber-b)", color: "var(--amber)" }}>
          <span className="bd2" style={{ background: "var(--amber)" }} />
          A simulation is running against this person: {e.active_kinds.join(", ")} activity.
        </div>
      )}

      <div style={{ display: "flex", gap: 7, marginBottom: 14 }}>
        {TABS.map(([k, label]) => (
          <button key={k} className={tab === k ? "primary" : ""} onClick={() => setSp({ tab: k })}>{label}</button>
        ))}
      </div>

      {tab === "profile" && (
        <div className="grid" style={{ gridTemplateColumns: "1fr 320px" }}>
          <div className="card">
            <div className="hd"><h3>Identity &amp; Asset</h3></div>
            <div className="bd">
              <div className="kv">
                <span className="k">Full name</span><span className="v">{e.name}</span>
                <span className="k">Username</span><span className="v mono">{e.username}</span>
                <span className="k">Email</span><span className="v mono">{e.email}</span>
                <span className="k">Phone</span><span className="v mono">{e.phone}</span>
                <span className="k">Category</span><span className="v">{e.category}</span>
                <span className="k">Role</span><span className="v">{e.role}</span>
                <span className="k">Unit</span><span className="v">{e.unit}</span>
                <span className="k">Manager</span><span className="v">{e.manager}</span>
                <span className="k">Clearance</span><span className="v">{e.clearance}</span>
                <span className="k">Workstation</span><span className="v mono">{e.host}</span>
                <span className="k">Operating system</span><span className="v">{e.os}</span>
                <span className="k">IP address</span><span className="v mono">{e.ip}</span>
                <span className="k">MAC</span><span className="v mono">{e.mac}</span>
                <span className="k">Device ID</span><span className="v mono">{e.device_id}</span>
                <span className="k">Office</span><span className="v">{e.location}</span>
                <span className="k">Since</span><span className="v mono">{e.joined}</span>
                <span className="k">Normal hours</span><span className="v mono">{e.normal_hours}</span>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="hd"><h3>Current Risk</h3></div>
            <div className="bd">
              <Gauge value={e.risk ?? 0} tier={e.tier} />
              <div style={{ marginTop: 10 }}>
                <Meter label="Conflict mass K" value={e.conflict ?? 0} danger={e.alarm} />
              </div>
              <div className="kv" style={{ marginTop: 12, gridTemplateColumns: "110px 1fr" }}>
                <span className="k">Cases</span><span className="v mono">{(e.incidents || []).length}</span>
                <span className="k">Containment</span><span className="v">{e.contained || "none"}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === "pc" && (pc ? <PCView pc={pc} /> : <div className="empty">Reading the workstation…</div>)}

      {tab === "shell" && (
        <div className="card">
          <div className="hd">
            <h3>Remote shell — {e.host}</h3>
            <span className="meta mono">{e.username}@{e.host} · {e.ip} · {e.os}</span>
          </div>
          <div className="bd">
            <Terminal uid={e.uid} host={e.host} user={e.username} />
          </div>
        </div>
      )}

      {tab === "events" && (
        <div className="card">
          <div className="hd"><h3>Recent Event Trace</h3><span className="meta">from the telemetry store</span></div>
          <div className="bd scroll" style={{ maxHeight: 560, padding: 0 }}>
            {(e.events || []).length ? (
              <table>
                <thead><tr><th>Tick</th><th>Domain</th><th>Kind</th><th>Features</th></tr></thead>
                <tbody>
                  {e.events.map((ev, i) => (
                    <tr key={i}>
                      <td className="mono">{ev.tick}</td>
                      <td><span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                        <DomainIcon domain={ev.domain} size={14} color="var(--muted)" />{ev.domain}</span></td>
                      <td className="mono" style={{ fontSize: 12 }}>{ev.kind}</td>
                      <td className="mono" style={{ fontSize: 11, color: "var(--muted)" }}>
                        {Object.entries(ev.features || {}).map(([k, v]) => `${k}=${(+v).toFixed(2)}`).join("  ")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <div className="empty">No events recorded yet.</div>}
          </div>
        </div>
      )}

      {tab === "cases" && (
        <div className="card">
          <div className="hd"><h3>Cases</h3></div>
          <div className="bd" style={{ padding: 0 }}>
            {(e.incidents || []).length ? (
              <table>
                <thead><tr><th>ID</th><th>Status</th><th>Peak</th><th>Events</th><th>Opened</th></tr></thead>
                <tbody>
                  {e.incidents.map((i) => (
                    <tr key={i.id} className="click" onClick={() => nav("/incidents/" + i.id)}>
                      <td className="mono" style={{ fontWeight: 600 }}>{i.id}</td>
                      <td><Badge kind={i.status}>{i.status}</Badge></td>
                      <td><Badge kind={i.peak_tier}>{i.peak_tier}</Badge></td>
                      <td className="mono">{i.n_events}</td>
                      <td className="mono" style={{ color: "var(--muted)", fontSize: 11.5 }}>{fmtTime(i.opened_ts)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <div className="empty">No cases for this person.</div>}
          </div>
        </div>
      )}
    </div>
  );
}

function PCView({ pc }) {
  const s = pc.stats || {};
  return (
    <div>
      <div className="grid" style={{ gridTemplateColumns: "repeat(4,1fr)", marginBottom: 16 }}>
        <Tile label="CPU" value={s.cpu + "%"} />
        <Tile label="Memory" value={s.mem + "%"} />
        <Tile label="Disk" value={`${s.disk_used_gb}/${s.disk_total_gb} GB`} />
        <Tile label="Uptime" value={s.uptime} small />
      </div>
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <div className="card">
          <div className="hd"><h3>Processes</h3><span className="meta">{pc.processes.length} running</span></div>
          <div className="bd scroll" style={{ maxHeight: 300, padding: 0 }}>
            <table>
              <thead><tr><th>PID</th><th>User</th><th>CPU</th><th>Command</th></tr></thead>
              <tbody>
                {pc.processes.map((p) => (
                  <tr key={p.pid} style={p.suspicious ? { background: "var(--red-w)" } : {}}>
                    <td className="mono">{p.pid}</td>
                    <td className="mono" style={{ fontSize: 12 }}>{p.user}</td>
                    <td className="mono">{p.cpu}</td>
                    <td className="mono" style={{ fontSize: 11.5 }}>
                      {p.cmd}{p.suspicious && <Badge kind="malicious">flagged</Badge>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="card">
            <div className="hd"><h3>Network connections</h3>
              {pc.isolated && <span className="meta" style={{ color: "var(--red)" }}>host isolated</span>}</div>
            <div className="bd scroll" style={{ maxHeight: 190, padding: 0 }}>
              <table>
                <thead><tr><th>Proto</th><th>Local</th><th>Remote</th><th>State</th></tr></thead>
                <tbody>
                  {pc.connections.map((c, i) => (
                    <tr key={i} style={c.suspicious ? { background: "var(--red-w)" } : {}}>
                      <td className="mono">{c.proto}</td>
                      <td className="mono" style={{ fontSize: 11.5 }}>{c.local}</td>
                      <td className="mono" style={{ fontSize: 11.5 }}>{c.remote}</td>
                      <td style={{ fontSize: 11.5 }}>{c.state}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="card">
            <div className="hd"><h3>Login sessions</h3></div>
            <div className="bd" style={{ padding: 0 }}>
              <table>
                <thead><tr><th>User</th><th>TTY</th><th>From</th><th>Login</th></tr></thead>
                <tbody>
                  {pc.sessions.map((x, i) => (
                    <tr key={i} style={x.suspicious ? { background: "var(--red-w)" } : {}}>
                      <td className="mono">{x.user}</td><td className="mono">{x.tty}</td>
                      <td className="mono" style={{ fontSize: 11.5 }}>{x.frm}</td>
                      <td className="mono">{x.login}</td>
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

function Tile({ label, value, small }) {
  return (
    <div className="card" style={{ padding: "13px 15px" }}>
      <div style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".5px" }}>{label}</div>
      <div className="mono" style={{ fontSize: small ? 15 : 22, fontWeight: 650, marginTop: 4 }}>{value}</div>
    </div>
  );
}
