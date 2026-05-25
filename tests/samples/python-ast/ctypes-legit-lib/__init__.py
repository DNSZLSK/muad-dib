# Fixture: NEG — legit ctypes load from system path. Should NOT fire PYAST-009.
import ctypes
_libssl = ctypes.CDLL("libssl.so")
_libc = ctypes.CDLL("/usr/lib/libc.so")
