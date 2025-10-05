"""
Placeholder script for threat feed: HF
"""
import subprocess
import sys

print("Running fetch_and_parse for HF...")
subprocess.run([sys.executable, "scripts/fetch_and_parse.py"], check=True)
