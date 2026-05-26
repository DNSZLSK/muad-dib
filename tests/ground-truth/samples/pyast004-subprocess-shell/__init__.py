# Fixture: PYAST-004 — subprocess.run with shell=True at module level.
import subprocess
subprocess.run("echo synthetic-fixture", shell=True)
