# Fixture: NEG — V1 limitation. Multi-hop alias chain a→b→sink is NOT detected.
# This fixture documents the limitation; Phase 3 (full dataflow) will close it.
import urllib.request
a = urllib.request.urlopen("http://127.0.0.1:0/synthetic").read()
b = a                # ← V1 doesn't propagate taint through this hop
exec(b)              # ← PYAST-003 fires, PYAST-005 does NOT (limitation, by design)
