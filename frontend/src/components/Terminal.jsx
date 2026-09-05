import { useEffect, useRef, useState } from "react";
import { API } from "../api";

/* A remote shell onto a monitored workstation. Everything it talks to is the
   simulated machine on the backend — the point is that what an analyst finds
   here lines up with what the detection agents are reporting. */
const HINTS = ["whoami", "id", "ls -la", "cat /etc/passwd", "ps", "netstat", "w", "last",
  "uname -a", "df -h", "find ~ -name '*.enc'", "cat ~/.bash_history", "tree ~", "help"];

export default function Terminal({ uid, host, user, height = 380 }) {
  const [lines, setLines] = useState([]);
  const [cmd, setCmd] = useState("");
  const [prompt, setPrompt] = useState(`${user}@${host}:~$`);
  const [busy, setBusy] = useState(false);
  const [hist, setHist] = useState([]);
  const [hi, setHi] = useState(-1);
  const boxRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    setLines([
      { t: "sys", v: `Connecting to ${host} (${user}) …` },
      { t: "sys", v: `Connected. Read-only analyst session. Type 'help' for commands.` },
    ]);
  }, [uid, host, user]);

  useEffect(() => {
    if (boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
  }, [lines]);

  const send = async (c) => {
    const line = c.trim();
    if (!line) return;
    setLines((L) => [...L, { t: "cmd", v: `${prompt} ${line}` }]);
    setHist((h) => [...h, line]); setHi(-1);
    if (line === "clear") { setLines([]); setCmd(""); return; }
    setBusy(true);
    try {
      const r = await fetch(`${API}/api/shell/${encodeURIComponent(uid)}`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cmd: line }),
      });
      const d = await r.json();
      if (d.output === "\x1b[CLEAR]") setLines([]);
      else if (d.output === "\x1b[EXIT]") setLines((L) => [...L, { t: "sys", v: "Session closed." }]);
      else if (d.output) setLines((L) => [...L, { t: "out", v: d.output }]);
      if (d.prompt) setPrompt(d.prompt);
    } catch {
      setLines((L) => [...L, { t: "err", v: "connection to the machine failed" }]);
    } finally { setBusy(false); setCmd(""); }
  };

  const onKey = (e) => {
    if (e.key === "Enter") { send(cmd); }
    else if (e.key === "ArrowUp") {
      e.preventDefault();
      const n = hi < 0 ? hist.length - 1 : Math.max(0, hi - 1);
      if (hist[n] !== undefined) { setHi(n); setCmd(hist[n]); }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const n = hi < 0 ? -1 : hi + 1;
      if (n >= hist.length) { setHi(-1); setCmd(""); } else { setHi(n); setCmd(hist[n]); }
    }
  };

  return (
    <div>
      <div ref={boxRef} onClick={() => inputRef.current?.focus()}
        style={{
          background: "#0e1726", color: "#d6e0f0", fontFamily: "var(--mono)", fontSize: 12.5,
          lineHeight: 1.55, padding: "12px 14px", borderRadius: "9px 9px 0 0", height,
          overflow: "auto", cursor: "text", border: "1px solid #0e1726", borderBottom: "none",
        }}>
        {lines.map((l, i) => (
          <pre key={i} style={{
            margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word",
            color: l.t === "cmd" ? "#7fd1c1" : l.t === "sys" ? "#7f8ea8" : l.t === "err" ? "#e8897c" : "#d6e0f0",
          }}>{l.v}</pre>
        ))}
        {busy && <pre style={{ margin: 0, color: "#7f8ea8" }}>…</pre>}
      </div>
      <div style={{
        display: "flex", alignItems: "center", gap: 8, background: "#0b1220",
        padding: "9px 14px", borderRadius: "0 0 9px 9px", border: "1px solid #0e1726", borderTop: "1px solid #1b2942",
      }}>
        <span className="mono" style={{ color: "#7fd1c1", fontSize: 12.5, whiteSpace: "nowrap" }}>{prompt}</span>
        <input ref={inputRef} value={cmd} onChange={(e) => setCmd(e.target.value)} onKeyDown={onKey}
          spellCheck={false} autoComplete="off" placeholder="type a command…"
          style={{
            flex: 1, background: "transparent", border: "none", outline: "none",
            color: "#d6e0f0", fontFamily: "var(--mono)", fontSize: 12.5,
          }} />
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10 }}>
        {HINTS.map((h) => (
          <button key={h} onClick={() => send(h)} style={{ fontSize: 11, padding: "4px 9px", fontFamily: "var(--mono)" }}>{h}</button>
        ))}
      </div>
    </div>
  );
}
