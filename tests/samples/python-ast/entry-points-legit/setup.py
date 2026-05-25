from setuptools import setup

setup(
    name="legit-cli-fixture",
    version="1.0.0",
    entry_points={
        "console_scripts": [
            "mycli=mypkg.cli:main",
            "mycli-debug=mypkg.cli:debug_main",
        ],
    },
)
