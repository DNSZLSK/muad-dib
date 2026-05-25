# Fixture: PYSRC-009 — bash -c variant. Inert echo.
import subprocess
subprocess.Popen(["bash", "-c", "echo synthetic"])
