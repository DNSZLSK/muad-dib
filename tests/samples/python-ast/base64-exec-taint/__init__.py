# Fixture: PYAST-006 — base64 decode then exec. Decoded value is "print('inert')".
import base64
code = base64.b64decode(b"cHJpbnQoJ2luZXJ0Jyk=")
exec(code)
