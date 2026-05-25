# Fixture: NEG — string cmd via shell, not the list form. PYSRC-009 must NOT fire
# (it targets the list `["node", "-e", code]` shape). PYAST-004 catches the
# shell=True risk separately, which is the right division of labour.
import subprocess
subprocess.run("node -e 'console.log(1)'", shell=True)
