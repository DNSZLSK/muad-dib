# Reconstruction of eth-security-auditor (PyPI) — TrapDoor campaign,
# 22 mai 2026 20:20:18 UTC. The original PyPI vector executes payload
# at import time (no setup.py code-exec needed). Fixture preserves
# the install-side surface for scanner detection; the runtime payload
# lives in eth_security_auditor/__init__.py.
from setuptools import setup, find_packages

setup(
    name="eth-security-auditor",
    version="0.1.0",
    description="Ethereum smart contract security auditor (RECONSTRUCTION — TrapDoor PyPI variant)",
    author="ddjidd564",
    url="https://ddjidd564.github.invalid/defi-security-best-practices/",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[]
)
