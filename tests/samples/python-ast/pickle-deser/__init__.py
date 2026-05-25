# Fixture: PYAST-007 — pickle.loads() at module level (RCE if input is untrusted).
import pickle
BLOB = b"\x80\x04N."  # synthetic: pickles to None
DATA = pickle.loads(BLOB)
