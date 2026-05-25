# Fixture: NEG — runs a real script file, NOT inline code. Should not fire PYSRC-009.
# PYSRC-002 (subprocess) still fires because subprocess.run is itself the trigger,
# but that's a different rule with broader scope.
import subprocess
subprocess.run(["node", "real_script.js"])
