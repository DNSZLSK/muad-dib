"""Fixture: legitimate setup.py with custom build_ext for a C extension.
This still fires PYAST-001 (HIGH severity, build_ext is in INSTALL_TIME_COMMANDS),
because deciding "legitimate vs malicious" without inspecting the class body is
fundamentally hard. Documented as a known FP class — flagged HIGH (not CRITICAL)
so operators can sort efficiently. A future Phase 2 heuristic could inspect the
class body for benign markers (super().run() only, no exec/subprocess/network).
"""
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext


class MyBuildExt(build_ext):
    def run(self):
        super().run()


setup(
    name="cext-fixture",
    version="1.0.0",
    ext_modules=[Extension("mypkg._native", sources=["_native.c"])],
    cmdclass={"build_ext": MyBuildExt},
)
