"""
Placeholder script for threat feed: ABUSEIPDB
"""
import subprocess
import sys

print("Running fetch_and_parse for ABUSEIPDB...")
subprocess.run([sys.executable, "scripts/fetch_and_parse.py"], check=True)
