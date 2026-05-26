# Fixture: PYAST-008 — __import__ with hardcoded dangerous module name.
# This is an obfuscation pattern — static "import subprocess" would be flagged
# at the manifest level, but __import__("subprocess") evades that.
_sp = __import__("subprocess")
