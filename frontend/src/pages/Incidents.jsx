import { useNavigate } from "react-router-dom";
import { usePoll, fmtTime } from "../api";
import { Badge } from "../components/widgets";

export default function Incidents() {
  const nav = useNavigate();
  const { data } = usePoll("/api/incidents", 2000);
  const incidents = data?.incidents || [];

  return (
    <div>
      <div className="pagehd">
        <div>
          <h1>Incidents</h1>
          <p>Cases opened when an entity's fused risk stays high and corroborated. Click a row to open the full case file.</p>
        </div>
        {data?.db && <div style={{ fontSize: 12, color: "var(--muted)" }} className="mono">{data.db.events} events · {data.db.audit} audit rows persisted</div>}
      </div>

      <div className="card">
        {incidents.length ? (
          <table>
            <thead><tr>
              <th>ID</th><th>Entity</th><th>Status</th><th>Peak risk</th><th>Conflict</th>
              <th>Events</th><th>Actions</th><th>MITRE</th><th>Opened</th>
            </tr></thead>
            <tbody>
              {incidents.map((i) => (
                <tr key={i.id} className="click" onClick={() => nav("/incidents/" + i.id)}>
                  <td className="mono" style={{ fontWeight: 600 }}>{i.id}</td>
                  <td className="mono">{i.entity}</td>
                  <td><Badge kind={i.status}>{i.status}</Badge>{i.alarm && <Badge kind="malicious" >alarm</Badge>}</td>
                  <td><Badge kind={i.peak_tier}>{i.peak_tier}</Badge> <span className="mono" style={{ color: "var(--muted)" }}>{i.peak_risk.toFixed(2)}</span></td>
                  <td className="mono">{i.max_conflict.toFixed(2)}</td>
                  <td className="mono">{i.n_events}</td>
                  <td className="mono">{i.n_actions}</td>
                  <td style={{ fontSize: 11 }} className="mono">{(i.mitre || []).slice(0, 2).join(", ") || "—"}</td>
                  <td className="mono" style={{ color: "var(--muted)", fontSize: 11.5 }}>{fmtTime(i.opened_ts)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <div className="empty">No incidents yet. Run Scenario A or B from the top bar.</div>}
      </div>
    </div>
  );
}
