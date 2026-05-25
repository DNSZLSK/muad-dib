# Fixture: PYAST-009 — ctypes.CDLL loading from /tmp (world-writable).
import ctypes
ctypes.CDLL("/tmp/payload.so")
