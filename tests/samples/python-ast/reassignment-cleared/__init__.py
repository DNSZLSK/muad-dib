# Fixture: NEG — reassignment clears taint. Verifies the V1 invariant
# documented in handle-assignment.js.
import urllib.request
payload = urllib.request.urlopen("http://127.0.0.1:0/synthetic").read()
payload = "print('overwritten safe value')"   # ← clears the taint
exec(payload)                                   # ← PYAST-003 fires, PYAST-005 must NOT
