import { useEffect, useRef, useState } from "react";
import { tierColor, scoreColor } from "../api";

export function Badge({ kind, children }) {
  return <span className={"badge " + (kind || "")}>{children}</span>;
}

export function StatCard({ label, value, sub, color }) {
  return (
    <div className="card" style={{ padding: "13px 15px" }}>
      <div style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".5px" }}>{label}</div>
      <div className="mono" style={{ fontSize: 22, fontWeight: 650, marginTop: 4, color: color || "var(--ink)" }}>{value}</div>
      {sub && <div style={{ fontSize: 11.5, color: "var(--muted)", marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

export function Sparkline({ data = [], color = "var(--ink-2)", h = 30, w = 160 }) {
  const n = Math.max(data.length, 2);
  const pts = data.map((v, i) => `${(i / (n - 1) * w).toFixed(1)},${(h - 2 - v * (h - 4)).toFixed(1)}`);
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ display: "block" }}>
      <polyline points={pts.join(" ")} fill="none" stroke={color} strokeWidth="1.6" />
    </svg>
  );
}

export function Meter({ label, value, max = 1, color, danger }) {
  const pct = Math.min(100, (value / max) * 100);
  const c = danger ? "var(--red)" : color || (value > 0.2 * max ? "var(--amber)" : "var(--green)");
  return (
    <div style={{ margin: "6px 0" }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--muted)", textTransform: "uppercase", letterSpacing: ".5px", marginBottom: 5 }}>
        <span>{label}</span><span className="mono" style={{ fontWeight: 600 }}>{value.toFixed(2)}</span>
      </div>
      <div style={{ height: 9, borderRadius: 5, background: "var(--line-2)", overflow: "hidden" }}>
        <div style={{ height: "100%", width: pct + "%", borderRadius: 5, background: c, transition: "width .3s, background .3s" }} />
      </div>
    </div>
  );
}

export function Gauge({ value = 0, tier = "Normal", size = 168 }) {
  const R = 62, cx = 84, cy = 84;
  const a0 = Math.PI * 0.75, a1 = Math.PI * 2.25;
  const z = (f) => a0 + f * (a1 - a0);
  const seg = (from, to, color, wdt) => {
    const large = (to - from) > Math.PI ? 1 : 0;
    const x0 = cx + R * Math.cos(from), y0 = cy + R * Math.sin(from);
    const x1 = cx + R * Math.cos(to), y1 = cy + R * Math.sin(to);
    return <path d={`M ${x0} ${y0} A ${R} ${R} 0 ${large} 1 ${x1} ${y1}`} fill="none" stroke={color} strokeWidth={wdt} strokeLinecap="round" />;
  };
  const frac = Math.max(0, Math.min(1, value));
  const aVal = z(frac);
  const nx = cx + (R - 4) * Math.cos(aVal), ny = cy + (R - 4) * Math.sin(aVal);
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
      <svg width={size} height={size * 0.8} viewBox="0 0 168 134">
        {seg(z(0), z(1), "#eef1f6", 13)}
        {seg(z(0), z(0.35), "#2a9d8f", 13)}
        {seg(z(0.35), z(0.75), "#e0982f", 13)}
        {seg(z(0.75), z(1), "#c0392b", 13)}
        <line x1={cx} y1={cy} x2={nx} y2={ny} stroke="#1b2a41" strokeWidth="3" strokeLinecap="round" />
        <circle cx={cx} cy={cy} r="5" fill="#1b2a41" />
        <text x={cx} y={cy - 16} textAnchor="middle" fontSize="26" fontWeight="700" fill="#1b2a41" fontFamily="var(--mono)">{value.toFixed(2)}</text>
      </svg>
      <div style={{ fontWeight: 700, fontSize: 14, marginTop: -4, color: tierColor(tier) }}>{tier}</div>
    </div>
  );
}

// small domain glyphs for pipeline nodes and lists
export function DomainIcon({ domain, size = 18, color = "#1b2a41" }) {
  const s = { width: size, height: size, fill: "none", stroke: color, strokeWidth: 1.9, strokeLinecap: "round", strokeLinejoin: "round" };
  switch (domain) {
    case "network": return <svg viewBox="0 0 24 24" {...s}><path d="M5 12.5a11 11 0 0 1 14 0M8 15.5a6.5 6.5 0 0 1 8 0" /><circle cx="12" cy="18.5" r="1.2" fill={color} stroke="none" /></svg>;
    case "host": return <svg viewBox="0 0 24 24" {...s}><rect x="3" y="4" width="18" height="12" rx="1.5" /><path d="M8 20h8M12 16v4" /></svg>;
    case "identity": return <svg viewBox="0 0 24 24" {...s}><circle cx="12" cy="8" r="3.4" /><path d="M5.5 19a6.5 6.5 0 0 1 13 0" /></svg>;
    case "file": return <svg viewBox="0 0 24 24" {...s}><path d="M6 3h8l4 4v14H6z" /><path d="M14 3v4h4" /></svg>;
    case "fusion": return <svg viewBox="0 0 24 24" {...s}><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z" /><path d="M12 3v18M4 7.5l8 4.5 8-4.5" /></svg>;
    case "response": return <svg viewBox="0 0 24 24" {...s}><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z" /></svg>;
    case "explain": return <svg viewBox="0 0 24 24" {...s}><rect x="5" y="3" width="14" height="18" rx="1.5" /><path d="M8 8h8M8 12h8M8 16h5" /></svg>;
    default: return <svg viewBox="0 0 24 24" {...s}><circle cx="12" cy="12" r="8" /></svg>;
  }
}


/* ---------------------------------------------------------------- heartbeat
   A live beat for one agent. The trace scrolls continuously and a spike is
   drawn each time the agent actually reports, so a healthy agent shows a steady
   rhythm, a busy one beats faster, and an agent that stops reporting flatlines. */
export function Heartbeat({ beat, score = 0, poisoned = false, w = 150, h = 34, live = true }) {
  const [trace, setTrace] = useState(() => new Array(60).fill(0));
  const lastN = useRef(beat?.n ?? 0);
  const phase = useRef(0);

  useEffect(() => {
    if (!live) return;
    const id = setInterval(() => {
      setTrace((prev) => {
        const next = prev.slice(1);
        // a beat arrived since the last frame -> draw the spike
        const beated = (beat?.n ?? 0) !== lastN.current;
        if (beated) { lastN.current = beat?.n ?? 0; phase.current = 1; }
        let v = 0;
        if (phase.current > 0) {
          const p = phase.current;
          v = p > 0.72 ? (1 - p) * 3.4 : p > 0.45 ? 1 : p > 0.3 ? -0.35 : p * 0.9;
          phase.current = Math.max(0, p - 0.14);
        }
        next.push(v);
        return next;
      });
    }, 55);
    return () => clearInterval(id);
  }, [beat, live]);

  const color = poisoned ? "var(--red)" : score >= 0.6 ? "var(--red)"
              : score >= 0.35 ? "var(--amber)" : "var(--green)";
  const mid = h / 2;
  const pts = trace.map((v, i) => `${(i / (trace.length - 1)) * w},${(mid - v * (h * 0.38)).toFixed(1)}`);
  const bpm = beat?.interval_ms ? Math.round(60000 / Math.max(120, beat.interval_ms)) : 0;

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} style={{ display: "block", overflow: "visible" }}>
        <line x1="0" y1={mid} x2={w} y2={mid} stroke="var(--line-2)" strokeWidth="1" />
        <polyline points={pts.join(" ")} fill="none" stroke={color} strokeWidth="1.7"
                  strokeLinejoin="round" strokeLinecap="round" />
      </svg>
      <span className="mono" style={{ fontSize: 10.5, color: "var(--muted)", whiteSpace: "nowrap" }}>
        {bpm ? bpm + "/min" : "--"}
      </span>
    </div>
  );
}

/* a small pulsing dot that beats in time with the agent */
export function BeatDot({ beat, color = "var(--green)" }) {
  const [on, setOn] = useState(false);
  const lastN = useRef(beat?.n ?? 0);
  useEffect(() => {
    if ((beat?.n ?? 0) !== lastN.current) {
      lastN.current = beat?.n ?? 0;
      setOn(true);
      const t = setTimeout(() => setOn(false), 260);
      return () => clearTimeout(t);
    }
  }, [beat?.n]);
  return <span style={{
    width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block",
    transform: on ? "scale(1.7)" : "scale(1)", opacity: on ? 1 : 0.45,
    transition: "transform .18s ease, opacity .25s ease",
  }} />;
}
