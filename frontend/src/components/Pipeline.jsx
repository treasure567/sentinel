import { useEffect, useRef } from "react";
import { DomainIcon } from "./widgets";
import { scoreColor } from "../api";

// node layout on a 900x300 canvas
const NODES = [
  { id: "network", x: 92, y: 60, label: "Network", sub: "flow agent" },
  { id: "host", x: 92, y: 150, label: "Host / Identity", sub: "endpoint agents" },
  { id: "file", x: 92, y: 240, label: "File / Device", sub: "data agent" },
  { id: "fusion", x: 372, y: 150, label: "Fusion", sub: "D–S · conflict K" },
  { id: "response", x: 606, y: 150, label: "Response", sub: "CMDP · budget β" },
  { id: "explain", x: 818, y: 150, label: "Explanation", sub: "SHAP · MITRE" },
];
const EDGES = [
  ["network", "fusion"], ["host", "fusion"], ["file", "fusion"],
  ["fusion", "response"], ["response", "explain"],
];
const NW = 138, NH = 56;
const byId = (id) => NODES.find((n) => n.id === id);

export default function Pipeline({ agents = [], verdict = {}, pulses = [], speed = 1, expanded = false }) {
  const svgRef = useRef(null);
  const scoreByDomain = {};
  agents.forEach((a) => { scoreByDomain[a.domain] = a; });

  // fire pulses when the prop changes
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    (pulses || []).forEach((p) => {
      const [from, to] = p.edge.split("->");
      const path = svg.querySelector(`#edge-${from}-${to}`);
      if (!path) return;
      const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      dot.setAttribute("r", "4.5");
      dot.setAttribute("fill", p.hot ? "#c0392b" : "#2c4a73");
      svg.appendChild(dot);
      const len = path.getTotalLength();
      // travel time is analyst-controllable: the default is slow enough to
      // actually follow a packet of evidence from an agent to the fusion layer
      const dur = 1500 / Math.max(0.25, speed);
      const t0 = performance.now();
      const step = (t) => {
        const k = Math.min(1, (t - t0) / dur);
        const pt = path.getPointAtLength(k * len);
        dot.setAttribute("cx", pt.x); dot.setAttribute("cy", pt.y);
        if (k < 1) requestAnimationFrame(step); else dot.remove();
      };
      requestAnimationFrame(step);
    });
  }, [pulses, speed]);

  const nodeStroke = (id) => {
    if (id === "fusion") return verdict.alarm ? "#c0392b" : "#dbe1ea";
    if (id === "response" || id === "explain")
      return verdict.tier === "Critical" ? "#c0392b" : verdict.tier === "High" ? "#e0982f" : "#dbe1ea";
    const a = scoreByDomain[id];
    if (!a) return "#dbe1ea";
    return a.score >= 0.6 ? "#c0392b" : a.score >= 0.35 ? "#e0982f" : "#dbe1ea";
  };
  const nodeVal = (id) => {
    if (id === "fusion") return "K=" + (verdict.conflict ?? 0).toFixed(2);
    if (id === "response") return verdict.tier || "Normal";
    if (id === "explain") return verdict.mitre ? "MITRE" : "—";
    const a = scoreByDomain[id];
    return a ? a.score.toFixed(2) : "—";
  };
  const valColor = (id) => {
    if (id === "fusion") return verdict.alarm ? "#c0392b" : "#6b7688";
    if (id === "response") return verdict.tier === "Critical" ? "#c0392b" : verdict.tier === "High" ? "#e0982f" : "#6b7688";
    const a = scoreByDomain[id];
    return a ? scoreColor(a.score) : "#6b7688";
  };

  return (
    <svg ref={svgRef} viewBox="0 0 910 300"
         style={{ width: "100%", height: expanded ? "min(72vh, 760px)" : "auto", display: "block" }}>
      {/* edges */}
      {EDGES.map(([f, t]) => {
        const a = byId(f), b = byId(t);
        const x1 = a.x + NW / 2, y1 = a.y, x2 = b.x - NW / 2, y2 = b.y, mx = (x1 + x2) / 2;
        return <path key={`${f}-${t}`} id={`edge-${f}-${t}`} d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`} fill="none" stroke="#dbe1ea" strokeWidth="2" />;
      })}
      {/* nodes */}
      {NODES.map((n) => {
        const stroke = nodeStroke(n.id);
        const strong = stroke !== "#dbe1ea";
        const val = nodeVal(n.id);
        const x0 = n.x - NW / 2, y0 = n.y - NH / 2;
        return (
          <g key={n.id}>
            <rect x={x0} y={y0} width={NW} height={NH} rx="11" fill="#fff" stroke={stroke} strokeWidth={strong ? 2.2 : 1.5} />
            {/* icon top-left */}
            <g transform={`translate(${x0 + 13}, ${y0 + 11})`}><DomainIconSVG domain={n.id} /></g>
            {/* label + sub, left-aligned under the icon row */}
            <text x={x0 + 13} y={y0 + 40} fontSize="12.5" fontWeight="650" fill="#1b2a41" fontFamily="var(--sans)">{n.label}</text>
            <text x={x0 + 13} y={y0 + 51} fontSize="9" fill="#8a94a6" fontFamily="var(--sans)">{n.sub}</text>
            {/* score value as a pill in the top-right, clear of the label */}
            <text x={x0 + NW - 12} y={y0 + 20} textAnchor="end" fontSize="12" fontWeight="700" fill={valColor(n.id)} fontFamily="var(--mono)">{val}</text>
          </g>
        );
      })}
    </svg>
  );
}

// inline icon rendered inside SVG <g> (18px)
function DomainIconSVG({ domain }) {
  const p = { fill: "none", stroke: "#1b2a41", strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round" };
  const map = {
    network: <g {...p}><path d="M2 8a9 9 0 0 1 14 0M5 11a5 5 0 0 1 8 0" /><circle cx="9" cy="14" r="1" fill="#1b2a41" stroke="none" /></g>,
    host: <g {...p}><rect x="1" y="2" width="16" height="10" rx="1.3" /><path d="M6 16h6M9 12v4" /></g>,
    identity: <g {...p}><circle cx="9" cy="6" r="2.8" /><path d="M3.5 15a5.5 5.5 0 0 1 11 0" /></g>,
    file: <g {...p}><path d="M4 1h7l3.5 3.5V17H4z" /><path d="M11 1v3.5h3.5" /></g>,
    fusion: <g {...p}><path d="M9 1l7 4v8l-7 4-7-4V5z" /><path d="M9 1v16M2 5l7 4 7-4" /></g>,
    response: <g {...p}><path d="M9 1l6 2.5V8c0 4-2.5 6.5-6 8-3.5-1.5-6-4-6-8V3.5z" /></g>,
    explain: <g {...p}><rect x="3" y="1" width="12" height="16" rx="1.3" /><path d="M6 6h6M6 9h6M6 12h4" /></g>,
  };
  return <svg viewBox="0 0 18 18" width="18" height="18">{map[domain] || map.fusion}</svg>;
}
