# Fixture: PYSRC-001. Direct exec() call at module level.
# NOT REAL MALWARE — the payload string is inert.
PAYLOAD = "print('synthetic fixture, no side effect')"
exec(PAYLOAD)
