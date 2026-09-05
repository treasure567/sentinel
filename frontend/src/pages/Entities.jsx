import { useNavigate } from "react-router-dom";
import { useState } from "react";
import { usePoll, post } from "../api";
import { Badge } from "../components/widgets";

export default function Entities() {
  const nav = useNavigate();
  const [cat, setCat] = useState("All");
  const [q, setQ] = useState("");
  const { data } = usePoll("/api/entities", 1500);
  const cats = ["All", ...(data?.categories || [])];
  let ents = data?.entities || [];
  if (cat !== "All") ents = ents.filter((e) => e.category === cat);
  if (q.trim()) {
    const t = q.toLowerCase();
    ents = ents.filter((e) => (e.name + e.username + e.role + e.host + e.ip + e.unit)
      .toLowerCase().includes(t));
  }
  const act = async (uid, what, value) => {
    await post(`/api/entity/${encodeURIComponent(uid)}/${what}`, { value });
  };
  const counts = {};
  (data?.entities || []).forEach((e) => { counts[e.category] = (counts[e.category] || 0) + 1; });

  return (
    <div>
      <div className="pagehd">
        <div>
          <h1>Entities</h1>
          <p>Department of Computer Science and Engineering — {(data?.entities || []).length} monitored people.
             Isolate a host, pause its telemetry, or open its workstation.</p>
        </div>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search name, host, IP…"
          style={{ padding: "8px 12px", border: "1px solid var(--line)", borderRadius: 8, fontSize: 13, width: 240, outline: "none" }} />
      </div>

      <div style={{ display: "flex", gap: 7, flexWrap: "wrap", marginBottom: 14 }}>
        {cats.map((c) => (
          <button key={c} onClick={() => setCat(c)} className={cat === c ? "primary" : ""}>
            {c}{c !== "All" && counts[c] ? ` · ${counts[c]}` : ""}
          </button>
        ))}
      </div>

      <div className="card">
        <table>
          <thead><tr>
            <th>Person</th><th>Unit / Role</th><th>Host</th><th>IP</th>
            <th>Risk</th><th>State</th><th style={{ textAlign: "right" }}>Controls</th>
          </tr></thead>
          <tbody>
            {ents.map((e) => (
              <tr key={e.uid} className="click">
                <td onClick={() => nav("/entities/" + e.uid)}>
                  <div style={{ fontWeight: 600 }}>{e.name}</div>
                  <div className="mono" style={{ fontSize: 11, color: "var(--muted)" }}>{e.username}</div>
                </td>
                <td onClick={() => nav("/entities/" + e.uid)} style={{ fontSize: 12.5 }}>
                  <div>{e.role}</div>
                  <div style={{ color: "var(--muted)", fontSize: 11.5 }}>{e.category}</div>
                </td>
                <td onClick={() => nav("/entities/" + e.uid)} className="mono" style={{ fontSize: 12 }}>{e.host}</td>
                <td onClick={() => nav("/entities/" + e.uid)} className="mono" style={{ fontSize: 12 }}>{e.ip}</td>
                <td onClick={() => nav("/entities/" + e.uid)}>
                  <Badge kind={e.tier}>{e.tier}</Badge>{" "}
                  <span className="mono" style={{ color: "var(--muted)" }}>{(e.risk ?? 0).toFixed(2)}</span>
                </td>
                <td onClick={() => nav("/entities/" + e.uid)} style={{ fontSize: 11.5 }}>
                  {e.isolated && <Badge kind="malicious">isolated</Badge>}
                  {e.traffic_paused && <Badge kind="Closed">paused</Badge>}
                  {(e.active_kinds || []).length > 0 && <Badge kind="High">sim</Badge>}
                  {!e.isolated && !e.traffic_paused && !(e.active_kinds || []).length &&
                    <span style={{ color: "var(--green)" }}>active</span>}
                </td>
                <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                  <button style={{ fontSize: 11, padding: "4px 8px" }}
                    onClick={(ev) => { ev.stopPropagation(); act(e.uid, "isolate", !e.isolated); }}>
                    {e.isolated ? "Restore" : "Isolate"}
                  </button>{" "}
                  <button style={{ fontSize: 11, padding: "4px 8px" }}
                    onClick={(ev) => { ev.stopPropagation(); act(e.uid, "pause", !e.traffic_paused); }}>
                    {e.traffic_paused ? "Resume" : "Pause"}
                  </button>{" "}
                  <button style={{ fontSize: 11, padding: "4px 8px" }}
                    onClick={(ev) => { ev.stopPropagation(); nav("/entities/" + e.uid + "?tab=pc"); }}>
                    Open PC
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {ents.length === 0 && <div className="empty">No one matches that filter.</div>}
      </div>
    </div>
  );
}
