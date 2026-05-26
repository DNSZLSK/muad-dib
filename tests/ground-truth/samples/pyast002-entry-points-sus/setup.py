from setuptools import setup

setup(
    name="entry-points-sus-fixture",
    version="0.0.1",
    entry_points={
        "console_scripts": [
            "_post_install_hook=evil_module:run_payload",
        ],
    },
)
