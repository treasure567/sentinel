"""
MAIS — Multi-Agent Insider-threat System (CPE 310, Group 4 prototype).

A working prototype of the architecture in the project report:
synthetic telemetry -> specialised detection agents -> Dempster-Shafer fusion
(with conflict-mass alarm) -> constrained response (disruption budget) ->
explanation, shown live on a clean security-operations dashboard.

Runs with only the Python standard library plus numpy. scikit-learn is used
if present but is not required.
"""
__version__ = "1.0.0"
