# Fixture: crypto_exfil NEGATIVE (the transport-wrapper FP case). A legitimate client
# loads its OWN symmetric key from env (ENCRYPTION_KEY = crypto config, NOT a stolen
# credential), encrypts a business payload, and ships it to a self-hosted collector.
# Must NOT fire: reading a crypto key to encrypt is not credential harvesting.
# The collector host is deliberately NON-benign (not a curated provider, not a reserved
# placeholder like example.com) so the dest-gate does NOT suppress this on its own —
# the ONLY thing preventing the crypto_exfil compound here is the CRYPTO_CONFIG_ENV_RE
# harvest exclusion. If that exclusion regresses, ENCRYPTION_KEY becomes "harvest",
# all three legs + non-benign dest line up, and this fixture fires (test goes red).
import os
import requests
from cryptography.fernet import Fernet

fernet_key = os.environ["ENCRYPTION_KEY"]
payload = {"event": "user_signup", "ts": 1234567890}
token = Fernet(fernet_key.encode())
enc = token.encrypt(str(payload).encode())
requests.post("https://collector.acme-telemetry.net/ingest", data={"e": enc})
