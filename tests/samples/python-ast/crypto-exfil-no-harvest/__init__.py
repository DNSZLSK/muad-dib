# Fixture: crypto_exfil NEGATIVE — E2E helper. Encrypts a CALLER-supplied message
# (no credential/env harvest at all) and sends it. Transport encryption, not exfil.
import requests
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

PUBKEY = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKfakekeyfakekeyfakekeyfakekey0123
-----END PUBLIC KEY-----"""


def send_encrypted(message, recipient_url):
    rsa_key = RSA.importKey(PUBKEY)
    aes_key = b"k" * 32
    cipher = AES.new(aes_key, AES.MODE_CBC)
    blob = cipher.encrypt(message.encode().ljust(32))
    wrapped = PKCS1_OAEP.new(rsa_key).encrypt(aes_key)
    requests.post(recipient_url, data={"b": blob, "k": wrapped})
