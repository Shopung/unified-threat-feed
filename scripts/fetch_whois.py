"""
Placeholder script for threat feed: WHOIS
"""
import subprocess
import sys

print("Running fetch_and_parse for WHOIS...")
subprocess.run([sys.executable, "scripts/fetch_and_parse.py"], check=True)
