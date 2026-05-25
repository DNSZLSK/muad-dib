# Fixture: PYSRC-002. Inert subprocess invocation at module level.
import subprocess
subprocess.Popen(["echo", "synthetic-fixture"])
