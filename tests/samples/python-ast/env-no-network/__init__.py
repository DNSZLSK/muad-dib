# Fixture: NEG — env vars read but never sent over network. No PYAST-010.
import os
home = os.environ["HOME"]
user = os.environ.get("USER", "anonymous")
print(f"Hello {user}, home is {home}")
