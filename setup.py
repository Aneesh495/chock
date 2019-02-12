from setuptools import setup, find_packages

setup(
    name="chock",
    version="0.1.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "chock = chock.cli.main:main",
        ],
    },
)
