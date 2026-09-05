"""
explain.py — plain-language attribution and MITRE ATT&CK mapping.

Every action carries a short human-readable reason built from the features that
most drove the verdict, plus a MITRE technique label from a small lookup. This
is the prototype's stand-in for full SHAP attribution: because the detectors
already return their top contributing features, a faithful explanation is a
matter of naming them, no heavy library required.
"""
from __future__ import annotations
from typing import List

# feature -> (readable phrase, MITRE technique)
FEATURE_MAP = {
    "fail_count":       ("repeated failed logons", "T1110 Brute Force"),
    "geo_novelty":      ("logon from an unfamiliar location", "T1078 Valid Accounts"),
    "logon_hour":       ("logon at an unusual hour", "T1078 Valid Accounts"),
    "proc_rare":        ("a rarely-seen process", "T1059 Command & Scripting"),
    "file_sensitivity": ("access to a highly sensitive file", "T1213 Data from Repositories"),
    "usb_bytes":        ("a large write to removable media", "T1052 Exfil over Physical Medium"),
    "bytes_out":        ("a spike in outbound data", "T1041 Exfiltration over C2"),
    "dst_novelty":      ("traffic to a never-seen destination", "T1041 Exfiltration over C2"),
}


def explain(contributors, verdict) -> tuple[str, str]:
    """
    contributors: the Verdict.contributors [(agent_id, weight, score), ...]
    Returns (reason_text, mitre_label).
    We pick the strongest-scoring contributing agents and translate the domain
    signal into words. The MITRE label comes from the single strongest feature.
    """
    hot = sorted(contributors, key=lambda c: c[2], reverse=True)
    phrases: List[str] = []
    mitre = ""
    domain_phrase = {
        "net-flow": ("bytes_out",),
        "host-proc": ("proc_rare",),
        "id-logon": ("fail_count",),
        "file-dev": ("usb_bytes",),
    }
    for agent_id, weight, score in hot:
        if score < 0.5 or weight < 0.2:
            continue
        keys = domain_phrase.get(agent_id, ())
        for k in keys:
            phrase, m = FEATURE_MAP[k]
            phrases.append(phrase)
            if not mitre:
                mitre = m
    if not phrases:
        return ("routine activity within normal bounds", "")
    if len(phrases) == 1:
        reason = "Observed " + phrases[0] + "."
    else:
        reason = "Correlated signals: " + ", ".join(phrases[:-1]) + " and " + phrases[-1] + "."
    return reason, mitre
