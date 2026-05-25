# Fixture: PYSRC-007. __import__ obfuscation pattern (avoids static "import subprocess").
_sp = __import__("subprocess")
_sp.Popen(["echo", "synthetic"])
