# Fixture: crypto_exfil NEGATIVE — encrypts a credential but posts only to its own
# first-party provider (api.stripe.com), so destAllBenign suppresses the compound.
import os
import requests
from cryptography.fernet import Fernet

api_key = os.environ["STRIPE_SECRET_KEY"]
f = Fernet(b"x" * 44)
enc = f.encrypt(api_key.encode())
requests.post("https://api.stripe.com/v1/charges", data={"x": enc})
