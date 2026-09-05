import { useEffect, useRef, useState } from "react";

// Backend base URL. Override with VITE_API in an .env file if needed.
export const API = import.meta.env.VITE_API || "http://127.0.0.1:8000";

export async function getJSON(path) {
  const r = await fetch(API + path);
  if (!r.ok) throw new Error(path + " -> " + r.status);
  return r.json();
}
export function post(path) {
  return fetch(API + path, { method: "POST" });
}

// Live snapshot via SSE. Returns the latest frame (or null before first frame).
export function useStream() {
  const [frame, setFrame] = useState(null);
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    let es;
    const connect = () => {
      es = new EventSource(API + "/stream");
      es.onopen = () => setConnected(true);
      es.onmessage = (e) => { try { setFrame(JSON.parse(e.data)); } catch {} };
      es.onerror = () => { setConnected(false); es.close(); setTimeout(connect, 1500); };
    };
    connect();
    return () => es && es.close();
  }, []);
  return { frame, connected };
}

// Poll a JSON endpoint on an interval (for pages that don't need SSE).
export function usePoll(path, ms = 1500, deps = []) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const saved = useRef(path);
  saved.current = path;
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try { const d = await getJSON(saved.current); if (alive) { setData(d); setErr(null); } }
      catch (e) { if (alive) setErr(e.message); }
    };
    tick();
    const id = setInterval(tick, ms);
    return () => { alive = false; clearInterval(id); };
    // eslint-disable-next-line
  }, deps);
  return { data, err };
}

export const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString() : "—";
export const fmtScore = (v) => (v ?? 0).toFixed(2);
export const scoreColor = (v) => v >= 0.6 ? "var(--red)" : v >= 0.35 ? "var(--amber)" : "var(--green)";
export const tierColor = (t) => t === "Critical" ? "var(--red)" : (t === "High" || t === "Elevated") ? "var(--amber)" : "var(--green)";
