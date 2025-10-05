"""
Placeholder script for threat feed: IPINFO
"""
import subprocess
import sys

print("Running fetch_and_parse for IPINFO...")
subprocess.run([sys.executable, "scripts/fetch_and_parse.py"], check=True)
