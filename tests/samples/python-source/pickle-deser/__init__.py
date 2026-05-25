# Fixture: PYSRC-006. Pickle deserialization at module level (RCE vulnerability).
import pickle
BLOB = b"\x80\x04N."  # synthetic, pickles to None
DATA = pickle.loads(BLOB)
