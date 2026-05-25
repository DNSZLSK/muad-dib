"""
This module wraps exec() and subprocess.Popen() in safe abstractions.
Use the run_safely() helper if you need to invoke subprocess.run on user input.
The docstring intentionally mentions os.system and base64.b64decode + exec
to verify that MUAD'DIB strips docstrings before pattern matching.
"""

from . import _safe_runner

__version__ = "0.0.1"
