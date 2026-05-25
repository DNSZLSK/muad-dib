"""Legitimate setup.py with a C extension. No top-level subprocess / exec."""
from setuptools import setup, Extension

ext = Extension(
    "my_pkg._native",
    sources=["src/my_pkg/_native.c"],
    include_dirs=["src/my_pkg"],
)

setup(
    name="my_pkg",
    version="1.0.0",
    ext_modules=[ext],
)
