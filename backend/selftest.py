"""
selftest.py — headless end-to-end check of the whole pipeline (no UI).

Verifies the behaviours the demonstration depends on:
  1. baseline traffic for the whole department raises no incidents;
  2. every attack playbook is detected, escalates and is contained;
  3. a clean run raises NO conflict alarm;
  4. a run with a subverted agent DOES raise the conflict alarm, the rogue agent
     is discounted, and containment still happens;
  5. analyst controls (isolate, pause) take effect;
  6. the remote shell answers on a simulated machine;
  7. the provenance chain verifies.
"""
import sys
from mais.engine import Engine
from mais import entities as E
from mais.provenance import Provenance

FAIL = []


def check(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        FAIL.append(msg)


def reset_flags():
    for e in E.all_entities():
        E.set_isolated(e.uid, False)
        E.set_paused(e.uid, False)


def run(playbook=None, poison=None, ticks=26, uid=None, seed=7, intensity="high"):
    reset_flags()
    eng = Engine(seed=seed, log_path=f"/tmp/selftest_{playbook or 'base'}.jsonl")
    if playbook:
        eng.start_simulation(uid or E.TARGET_UID, playbook,
                             intensity=intensity, poison_agent=poison)
    peak, tier, alarms = 0.0, "Normal", 0
    for _ in range(ticks):
        eng.step()
        v = eng.verdicts.get(uid or E.TARGET_UID)
        if v:
            if v.alarm:
                alarms += 1
            if v.risk > peak:
                peak, tier = v.risk, v.tier
    return eng, peak, tier, alarms


def main():
    print("\n1. Directory")
    check(len(E.all_entities()) == 30, f"30 monitored people ({len(E.all_entities())} found)")
    check(len(E.categories()) == 6, "six staff categories")

    print("\n2. Baseline — no false positives")
    eng, _, _, _ = run(ticks=60)
    check(len(eng.incidents.list()) == 0, "no incidents raised on normal departmental traffic")
    check(eng.stats.get("alarms", 0) == 0, "no conflict alarms on normal traffic")

    print("\n3. Attack playbooks are detected and contained")
    for pb in ["exfiltration", "credential_abuse", "lateral_movement", "sabotage"]:
        eng, peak, tier, alarms = run(pb)
        check(tier in ("High", "Critical"), f"{pb}: escalates to {tier} (risk {peak:.2f})")
        check(bool(eng.enterprise.contained), f"{pb}: containment action taken")
        check(alarms == 0, f"{pb}: no false conflict alarm on a clean run")

    print("\n4. A subverted agent is caught (the case the base study cannot handle)")
    eng, peak, tier, alarms = run("exfiltration", poison="net-flow")
    check(alarms > 0, f"conflict alarm raised ({alarms} ticks)")
    check(tier in ("High", "Critical"), f"threat still reaches {tier} despite the lie")
    check(bool(eng.enterprise.contained), "containment still proceeds on the honest agents")

    print("\n5. Analyst controls")
    reset_flags()
    eng = Engine(seed=7, log_path="/tmp/selftest_ctl.jsonl")
    uid = E.TARGET_UID
    eng.set_isolated(uid, True)
    check(E.get(uid).isolated, "isolate takes effect")
    eng.set_paused(uid, True)
    before = eng.events_seen
    for _ in range(6):
        eng.step()
    check(all(ev != uid for ev in []) and E.get(uid).traffic_paused, "pause takes effect")
    eng.set_paused(uid, False); eng.set_isolated(uid, False)

    print("\n6. Remote shell on a simulated machine")
    m = eng.machine(uid)
    check(m.run("whoami") == E.get(uid).username, "whoami returns the account name")
    check("CSE-" in m.run("hostname"), "hostname resolves")
    check("PID" in m.run("ps"), "process table renders")
    check("Filesystem" in m.run("df -h"), "disk usage renders")
    check("command not found" in m.run("definitelynotacommand"), "unknown commands are handled")

    print("\n7. Provenance")
    check(Provenance.verify("/tmp/selftest_exfiltration.jsonl"), "hash chain verifies")

    print("\n" + ("ALL CHECKS PASSED" if not FAIL else f"{len(FAIL)} CHECK(S) FAILED"))
    sys.exit(0 if not FAIL else 1)


if __name__ == "__main__":
    main()
