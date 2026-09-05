import { useEffect, useRef, useState } from "react";
import { getJSON, tierColor, scoreColor } from "../api";
import Pipeline from "../components/Pipeline";
import { Gauge, Meter, Badge, Sparkline } from "../components/widgets";

export default function Replay() {
  const [pb, setPb] = useState("exfiltration");
  const [poison, setPoison] = useState("");
  const [meta, setMeta] = useState(null);
  const [data, setData] = useState(null);
  const [i, setI] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [loading, setLoading] = useState(false);
  const timer = useRef(null);

  const load = async (playbook, po) => {
    setLoading(true); setPlaying(false); setI(0); setPb(playbook); setPoison(po ?? "");
    try {
      const q = `?playbook=${playbook}` + (po ? `&poison=${po}` : "");
      const d = await getJSON("/api/replay" + q);
      setData(d);
    } finally { setLoading(false); }
  };
  useEffect(() => {
    getJSON("/api/meta").then(setMeta).catch(() => {});
    load("exfiltration", "");
  }, []);

  useEffect(() => {
    if (playing && data) {
      timer.current = setInterval(() => {
        setI((x) => { if (x >= data.frames.length - 1) { setPlaying(false); return x; } return x + 1; });
      }, 600);
    }
    return () => clearInterval(timer.current);
  }, [playing, data]);

  if (loading || !data) return <div className="empty">Recording replay…</div>;
  const frame = data.frames[i];
  const v = frame.verdict;
  const injected = i >= data.inject_at;

  return (
    <div>
      <div className="pagehd">
        <div><h1>Replay</h1><p>A deterministic, recorded run of a scenario. Scrub through it tick-by-tick to see exactly how the agents, fusion and response evolved.</p></div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <select value={pb} onChange={(e) => load(e.target.value, poison)}
            style={{ padding: "8px 10px", border: "1px solid var(--line)", borderRadius: 8, fontSize: 13 }}>
            {(meta?.playbooks || []).map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
          </select>
          <select value={poison} onChange={(e) => load(pb, e.target.value)}
            style={{ padding: "8px 10px", border: "1px solid var(--line)", borderRadius: 8, fontSize: 13 }}>
            <option value="">all agents honest</option>
            {(meta?.agents || []).map((a) => <option key={a.id} value={a.id}>{a.id} subverted</option>)}
          </select>
        </div>
      </div>

      {/* transport */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="bd" style={{ paddingTop: 14, display: "flex", alignItems: "center", gap: 16 }}>
          <button className="primary" onClick={() => { if (i >= data.frames.length - 1) setI(0); setPlaying((p) => !p); }} style={{ minWidth: 84 }}>
            {playing ? "❚❚ Pause" : "▶ Play"}
          </button>
          <button onClick={() => { setPlaying(false); setI(0); }}>⟲ Restart</button>
          <input type="range" min={0} max={data.frames.length - 1} value={i} onChange={(e) => { setPlaying(false); setI(+e.target.value); }} style={{ flex: 1, accentColor: "#1b2a41" }} />
          <span className="mono" style={{ fontSize: 13, color: "var(--muted)", whiteSpace: "nowrap" }}>tick {i + 1} / {data.frames.length}</span>
          <Badge kind={injected ? v.tier : "Normal"}>{injected ? (data.label || pb) : "baseline"}</Badge>
        </div>
      </div>

      {v.alarm && (
        <div className="alarm-banner"><span className="bd2" />Conflict alarm at this tick — the poisoned agent is contradicting the others (K={v.conflict.toFixed(2)}); it is discounted and containment holds.</div>
      )}

      <div className="grid" style={{ gridTemplateColumns: "1fr 300px" }}>
        <div className="card">
          <div className="hd"><h3>Agent Pipeline — recorded</h3><span className="meta">frame {i + 1}</span></div>
          <div className="bd" style={{ padding: "4px 10px 0" }}>
            <Pipeline agents={frame.agents} verdict={v} pulses={frame.pulses} speed={0.8} />
            <div className="legend">
              <span className="it"><span className="sw" style={{ background: "var(--green)" }} />Normal</span>
              <span className="it"><span className="sw" style={{ background: "var(--amber)" }} />Elevated</span>
              <span className="it"><span className="sw" style={{ background: "var(--red)" }} />Malicious</span>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="hd"><h3>State at this tick</h3></div>
          <div className="bd">
            <Gauge value={v.risk} tier={v.tier} />
            <div style={{ marginTop: 10 }}>
              <Meter label="Conflict Mass K" value={v.conflict} danger={v.alarm} />
              <Meter label="Budget pressure (mu)" value={frame.budget?.mu ?? 0} max={3} color="var(--ink-2)" />
            </div>
            <div className="kv" style={{ marginTop: 12, gridTemplateColumns: "90px 1fr" }}>
              <span className="k">Focus</span><span className="v mono">{v.entity}</span>
              <span className="k">Risk tier</span><span className="v">{v.tier}</span>
              <span className="k">Events</span><span className="v mono">{frame.events_seen}</span>
            </div>
          </div>
        </div>
      </div>

      {/* per-agent scores at this frame */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="hd"><h3>Agent scores at this tick</h3></div>
        <div className="bd" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14 }}>
          {frame.agents.map((a) => (
            <div key={a.id} style={{ border: "1px solid var(--line)", borderRadius: 8, padding: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontWeight: 600, fontSize: 13 }}>{a.id}</span>
                {a.poisoned && <Badge kind="malicious">poison</Badge>}
              </div>
              <div className="mono" style={{ fontSize: 20, fontWeight: 650, color: scoreColor(a.score), marginTop: 2 }}>{a.score.toFixed(2)}</div>
              <Sparkline data={a.spark} color={scoreColor(a.score)} h={24} />
              <div className="mono" style={{ fontSize: 10.5, color: "var(--muted)", marginTop: 2 }}>reliab {a.reliability.toFixed(2)}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
