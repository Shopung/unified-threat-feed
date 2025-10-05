"""
Placeholder script for threat feed: OTX
"""
import subprocess
import sys

print("Running fetch_and_parse for OTX...")
subprocess.run([sys.executable, "scripts/fetch_and_parse.py"], check=True)
