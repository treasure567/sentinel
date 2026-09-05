import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { post, usePoll } from "./api";

const NAV = [
  ["/", "Overview", icoGrid],
  ["/incidents", "Incidents", icoAlert],
  ["/entities", "Entities", icoUsers],
  ["/simulate", "Simulate", icoBolt],
  ["/agents", "Agents", icoChip],
  ["/audit", "Audit Log", icoLock],
  ["/replay", "Replay", icoPlay],
];

export default function App() {
  const [now, setNow] = useState(new Date());
  const [busy, setBusy] = useState(false);
  const loc = useLocation();
  const nav = useNavigate();
  const { data: inc } = usePoll("/api/incidents", 3000, [loc.pathname]);
  const openCount = inc ? inc.incidents.filter((i) => i.status === "Open").length : 0;

  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t); }, []);

  const stopAll = async () => { setBusy(true); await post("/api/simulations/stop"); setTimeout(() => setBusy(false), 500); };
  const reset = async () => { setBusy(true); await post("/api/reset"); setTimeout(() => setBusy(false), 700); };

  return (
    <div className="app">
      <aside className="rail">
        <div className="logo">
          <div className="mk"><svg viewBox="0 0 24 24" fill="none" stroke="#1b2a41" strokeWidth="2.2"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" /></svg></div>
          <div><b>Sentinel</b><span>OAU · CSE Department</span></div>
        </div>
        <nav>
          {NAV.map(([to, label, Ico]) => (
            <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => isActive ? "active" : ""}>
              <Ico />{label}
              {to === "/incidents" && openCount > 0 && <span className="count">{openCount}</span>}
            </NavLink>
          ))}
        </nav>
        <div className="foot">
          CPE 310 · Group 4<br />Multi-agent prototype<br />
          <span style={{ color: "#4f628a" }}>Base study: Audit-LLM (2024)</span>
        </div>
      </aside>

      <div>
        <div className="topbar">
          <div className="title">Multi-Agent Insider-Threat Detection &amp; Automated Response
            <small>Detection agents → Dempster–Shafer fusion → constrained response</small>
          </div>
          <div className="right">
            <span className="clock">{now.toLocaleTimeString()}</span>
            <div className="btns">
              <button className="primary" disabled={busy} onClick={() => nav("/simulate")}>Run a simulation</button>
              <button disabled={busy} onClick={stopAll}>Stop simulations</button>
              <button className="ghost" disabled={busy} onClick={reset}>Reset</button>
            </div>
          </div>
        </div>
        <div className="content"><Outlet /></div>
      </div>
    </div>
  );
}

function base(children) { return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">{children}</svg>; }
function icoGrid() { return base(<><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>); }
function icoAlert() { return base(<><path d="M12 3l9 16H3z" /><path d="M12 10v4M12 17v.5" /></>); }
function icoUsers() { return base(<><circle cx="9" cy="8" r="3" /><path d="M3.5 19a5.5 5.5 0 0 1 11 0M16 6a3 3 0 0 1 0 6M20.5 19a5 5 0 0 0-4-5" /></>); }
function icoChip() { return base(<><rect x="6" y="6" width="12" height="12" rx="1.5" /><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" /></>); }
function icoLock() { return base(<><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></>); }
function icoBolt() { return base(<><path d="M13 2L4 14h6l-1 8 9-12h-6z" /></>); }
function icoPlay() { return base(<><circle cx="12" cy="12" r="9" /><path d="M10 9l5 3-5 3z" fill="currentColor" stroke="none" /></>); }
