from setuptools import setup, find_packages

setup(
    name="cyberscan",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "paramiko",
        "scapy",
        "smbprotocol"
    ],
    entry_points={
        "console_scripts": [
            "cyberscan=core.port_scanner:main"
        ]
    },
    author="Senin Adın",
    description="Advanced Cyber Security Scanner",
    url="https://github.com/seninhesabin/cyberscan",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
