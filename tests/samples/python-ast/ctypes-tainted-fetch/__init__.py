# Fixture: PYAST-009 — ctypes.CDLL with arg coming from a network fetch.
import urllib.request
import ctypes
blob = urllib.request.urlopen("http://127.0.0.1:0/synthetic").read()
ctypes.CDLL(blob)
