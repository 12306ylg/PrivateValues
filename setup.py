from setuptools import setup, find_packages
setup(
    name="privatevalues",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "privatevalues = privatevalues.cli:main",
            "privatevalues-gui = privatevalues.gui:main",
        ],
    },
)