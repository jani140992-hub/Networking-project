from setuptools import setup, find_packages

setup(
    name="netsphere",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "netsphere": ["web/*"],
    },
    entry_points={
        "console_scripts": [
            "netsphere=netsphere.cli:main",
        ],
    },
)
