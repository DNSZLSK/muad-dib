# Fixture: PYSRC-009 — fork-exec node -e with inert literal payload.
import subprocess
subprocess.run(["node", "-e", "console.log('synthetic fixture, no side effect')"])
