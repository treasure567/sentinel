import { useNavigate } from "react-router-dom";
import { usePoll, scoreColor } from "../api";
import { Badge, Sparkline, Meter, DomainIcon, Heartbeat, BeatDot } from "../components/widgets";

export default function Agents() {
  const nav = useNavigate();
  const { data } = usePoll("/api/agents", 1000);
  const agents = data || [];
  return (
    <div>
      <div className="pagehd">
        <div><h1>Detection Agents</h1>
          <p>Each agent independently watches one telemetry domain, scores behaviour against each person's own
             baseline, and publishes evidence to the fusion agent. Click one for the full picture.</p></div>
      </div>
      <div className="grid" style={{ gridTemplateColumns: "repeat(2,1fr)" }}>
        {agents.map((a) => (
          <div className="card click" key={a.id} onClick={() => nav("/agents/" + a.id)} style={{ cursor: "pointer" }}>
            <div className="hd">
              <h3 style={{ display: "flex", alignItems: "center", gap: 9, textTransform: "none", fontSize: 14, letterSpacing: 0, color: "var(--ink)" }}>
                <BeatDot beat={a.beat} color={a.poisoned ? "var(--red)" : scoreColor(a.score)} />
                <DomainIcon domain={a.domain} size={18} /> {a.title}
              </h3>
              {a.poisoned ? <Badge kind="malicious">subverted</Badge> : <Badge kind="healthy">healthy</Badge>}
            </div>
            <div className="bd">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
                <div>
                  <div style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".5px" }}>Live threat score</div>
                  <div className="mono" style={{ fontSize: 30, fontWeight: 680, color: scoreColor(a.score) }}>{a.score.toFixed(2)}</div>
                  {a.subject_name && <div style={{ fontSize: 12, color: "var(--muted)" }}>on {a.subject_name}</div>}
                </div>
                <div style={{ width: 190 }}><Sparkline data={a.spark} color={scoreColor(a.score)} h={44} w={190} /></div>
              </div>
              <div style={{ marginTop: 10, borderTop: "1px solid var(--line-2)", paddingTop: 9 }}>
                <Heartbeat beat={a.beat} score={a.score} poisoned={a.poisoned} w={330} h={34} />
              </div>
              <div style={{ marginTop: 8 }}>
                <Meter label="Reliability (fusion trust)" value={a.reliability} danger={a.reliability <= 0.2} color="var(--green)" />
              </div>
              <div style={{ fontSize: 12.5, color: "var(--muted)", marginTop: 8 }}>{a.watches}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
