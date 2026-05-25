# Fixture: PYSRC-001 + PYSRC-005. Inert base64-decode-then-exec.
import base64
# Decoded value is "print('inert')" — synthetic payload, no side effect.
ENCODED = b"cHJpbnQoJ2luZXJ0Jyk="
exec(base64.b64decode(ENCODED))
