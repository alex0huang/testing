"""
More intentional vulnerability samples for AdaL review testing (round 2).
"""

import hashlib
import subprocess
import yaml

AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/yT2FyQ8x8vK9x0x0x0x0x0x0x0x0x0x0x0
-----END RSA PRIVATE KEY-----"""


def run_shell(user_input: str) -> str:
    # Command injection via subprocess + shell=True
    return subprocess.check_output(f"echo {user_input}", shell=True, text=True)


def weak_password_hash(password: str) -> str:
    # Weak crypto for password storage
    return hashlib.md5(password.encode()).hexdigest()


def parse_yaml_config(raw: str) -> dict:
    # Unsafe YAML load (arbitrary object instantiation)
    return yaml.load(raw, Loader=yaml.Loader)


def fetch_url(url: str):
    import urllib.request

    # SSRF: no URL allowlist, fetches arbitrary user-supplied URL
    return urllib.request.urlopen(url).read()
