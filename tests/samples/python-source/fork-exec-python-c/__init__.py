# Fixture: PYSRC-009 — python -c variant. Inert no-op.
import subprocess
subprocess.check_output(["python3", "-c", "import sys; print(sys.version_info)"])
