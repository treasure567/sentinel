import { Link, useParams } from "react-router-dom";
import { usePoll, scoreColor } from "../api";
import { Badge, Sparkline, Meter, DomainIcon, Heartbeat, BeatDot } from "../components/widgets";

export default function AgentDetail() {
  const { id } = useParams();
  const { data: a } = usePoll("/api/agent/" + id, 900, [id]);
  if (!a) return <div className="empty">Loading agent…</div>;
  if (a.error) return <div className="empty">Agent not found.</div>;

  return (
    <div>
      <Link to="/agents" className="back">← All agents</Link>
      <div className="pagehd">
        <div>
          <h1 style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <DomainIcon domain={a.domain} size={22} /> {a.title}
          </h1>
          <p>{a.detector}</p>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <BeatDot beat={a.beat} color={a.poisoned ? "var(--red)" : "var(--green)"} />
          {a.poisoned ? <Badge kind="malicious">subverted</Badge> : <Badge kind="healthy">healthy</Badge>}
        </div>
      </div>

      {a.poisoned && (
        <div className="alarm-banner"><span className="bd2" />
          This agent is currently reporting <b style={{ margin: "0 4px" }}>benign</b> about{" "}
          {a.poisoned_for} while its peers report malicious. The fusion layer has detected the
          contradiction and is discounting it.
        </div>
      )}

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr", marginBottom: 16 }}>
        <Tile label="Live threat score" value={a.score.toFixed(2)} color={scoreColor(a.score)} />
        <Tile label="Confidence" value={a.confidence.toFixed(2)} />
        <Tile label="Reliability (fusion trust)" value={a.reliability.toFixed(2)}
              color={a.reliability <= 0.2 ? "var(--red)" : undefined} />
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1.3fr 1fr" }}>
        <div className="card">
          <div className="hd"><h3>Live signal</h3><span className="meta">last 48 cycles</span></div>
          <div className="bd">
            <Sparkline data={a.spark} color={scoreColor(a.score)} h={70} w={520} />
            <div style={{ marginTop: 14, borderTop: "1px solid var(--line-2)", paddingTop: 12 }}>
              <div style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".5px", marginBottom: 6 }}>Heartbeat</div>
              <Heartbeat beat={a.beat} score={a.score} poisoned={a.poisoned} w={520} h={54} />
              <div className="mono" style={{ fontSize: 11, color: "var(--muted)", marginTop: 6 }}>
                {a.beat?.n ?? 0} cycles reported · {a.beat?.events ?? 0} events processed · {a.beat?.latency_ms ?? 0} ms avg
              </div>
            </div>
            <div style={{ marginTop: 14 }}>
              <Meter label="Confidence" value={a.confidence} color="var(--ink-2)" />
              <Meter label="Reliability" value={a.reliability} danger={a.reliability <= 0.2} color="var(--green)" />
            </div>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="card">
            <div className="hd"><h3>Specification</h3></div>
            <div className="bd">
              <div className="kv" style={{ gridTemplateColumns: "104px 1fr" }}>
                <span className="k">Agent id</span><span className="v mono">{a.id}</span>
                <span className="k">Domain</span><span className="v">{a.domain}</span>
                <span className="k">Deployed at</span><span className="v" style={{ fontSize: 12.5 }}>{a.placement}</span>
                <span className="k">Watches</span><span className="v" style={{ fontSize: 12.5 }}>{a.watches}</span>
                <span className="k">Features</span><span className="v mono" style={{ fontSize: 12 }}>{(a.features || []).join(", ")}</span>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="hd"><h3>Current subject</h3></div>
            <div className="bd">
              {a.subject ? (
                <div>
                  <div style={{ fontWeight: 600 }}>{a.subject_name}</div>
                  <Link to={"/entities/" + a.subject} className="mono" style={{ fontSize: 12, color: "var(--ink-2)" }}>{a.subject} →</Link>
                </div>
              ) : <span style={{ color: "var(--faint)" }}>nothing being reported</span>}
              {a.top_features?.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".5px", marginBottom: 6 }}>Top contributing features</div>
                  {a.top_features.map(([n, v], i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
                      <span className="mono" style={{ fontSize: 11.5, width: 118 }}>{n}</span>
                      <div style={{ flex: 1, height: 6, background: "var(--line-2)", borderRadius: 3 }}>
                        <div style={{ height: "100%", width: v * 100 + "%", background: scoreColor(a.score), borderRadius: 3 }} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
          <div className="card">
            <div className="hd"><h3>Techniques it can surface</h3></div>
            <div className="bd" style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
              {(a.mitre || []).map((m) => (
                <span key={m} className="mono" style={{ fontSize: 11.5, background: "var(--page)", border: "1px solid var(--line)", padding: "4px 9px", borderRadius: 6, color: "var(--ink-2)" }}>{m}</span>
              ))}
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
      <div className="mono" style={{ fontSize: 24, fontWeight: 650, marginTop: 4, color: color || "var(--ink)" }}>{value}</div>
    </div>
  );
}
