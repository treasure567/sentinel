import { usePoll, getJSON, fmtTime } from "../api";
import { useEffect, useState } from "react";
import { Badge } from "../components/widgets";

export default function Audit() {
  const { data } = usePoll("/api/audit", 2000);
  const [verify, setVerify] = useState(null);
  const rows = data?.audit || [];

  useEffect(() => {
    const t = setInterval(() => getJSON("/api/audit/verify").then(setVerify).catch(() => {}), 3000);
    getJSON("/api/audit/verify").then(setVerify).catch(() => {});
    return () => clearInterval(t);
  }, []);

  return (
    <div>
      <div className="pagehd">
        <div><h1>Audit Log</h1><p>Every score, verdict and action is written to an append-only, hash-chained log. Each entry's hash incorporates the previous entry's, so any tampering is detectable.</p></div>
        {verify && (
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {data?.db && <span className="mono" style={{ fontSize: 12, color: "var(--muted)" }}>{data.db.audit} entries</span>}
            <Badge kind={verify.intact ? "healthy" : "malicious"}>{verify.intact ? "chain intact ✓" : "chain broken ✗"}</Badge>
          </div>
        )}
      </div>

      <div className="card">
        <table>
          <thead><tr><th>Time</th><th>Tick</th><th>Type</th><th>Summary</th><th>Entry hash</th></tr></thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                <td className="mono" style={{ fontSize: 11.5, color: "var(--muted)" }}>{fmtTime(r.ts)}</td>
                <td className="mono">{r.tick}</td>
                <td><Badge kind={r.kind === "action" ? "Elevated" : r.kind === "verdict" ? "Open" : "Normal"}>{r.kind}</Badge></td>
                <td style={{ fontSize: 12 }}>{summarise(r)}</td>
                <td className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>{(r.hash || "").slice(0, 18)}…</td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <div className="empty">No audit entries yet.</div>}
      </div>
    </div>
  );
}

function summarise(r) {
  const p = r.payload || {};
  if (r.kind === "score") return `${p.agent_id} → ${p.entity}: score ${p.score}, conf ${p.confidence}`;
  if (r.kind === "verdict") return `${p.entity}: risk ${p.risk} (${p.tier}), K ${p.conflict}${p.alarm ? " — ALARM" : ""}`;
  if (r.kind === "action") return `${p.entity}: ${p.kind} [${p.tier}]${p.approved ? "" : " (hold)"}`;
  return JSON.stringify(p).slice(0, 80);
}
