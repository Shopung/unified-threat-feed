#!/usr/bin/env python3
# =========================================
# Unified Threat Feed Full Setup (Phase 1 + Phase 2 + Phase 3 + Env Check + Auto Install)
# Fully cross-platform (Windows/Linux/macOS)
# Dynamic parallel execution based on CPU cores
# =========================================

import os
import subprocess
import sys
import json
import time
import zipfile
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing

# -------------------------
# Variables
# -------------------------
LOGDIR = "./logs"
os.makedirs(LOGDIR, exist_ok=True)
LOGFILE = os.path.join(LOGDIR, f"setup_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.log")
DIST_DIR = "./dist"
os.makedirs(DIST_DIR, exist_ok=True)

RETRY_MAX = 3
RETRY_DELAY = 5  # seconds

WORKFLOW_DIR = ".github/workflows"
os.makedirs(WORKFLOW_DIR, exist_ok=True)
WORKFLOW_FILE = os.path.join(WORKFLOW_DIR, "phase3_update_feeds.yml")

REQUIREMENTS_FILE = "requirements.txt"
REQUIREMENTS = ["requests", "python-whois", "jq"]

ENV_FILE = ".env"
ENV_EXAMPLE_FILE = ".env.example"

THREAT_SCRIPTS = []

# -------------------------
# Logging
# -------------------------
def log(level: str, message: str):
    entry = {"timestamp": datetime.utcnow().isoformat(), "level": level, "message": message}
    print(json.dumps(entry))
    with open(LOGFILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

# -------------------------
# Environment Checks
# -------------------------
def check_python_env():
    try:
        python_version = subprocess.run([sys.executable, "--version"], capture_output=True, text=True, check=True)
        pip_version = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True, text=True, check=True)
        log("INFO", f"Python found: {python_version.stdout.strip()}")
        log("INFO", f"pip found: {pip_version.stdout.strip()}")
    except subprocess.CalledProcessError:
        log("ERROR", "Python and/or pip not found. Please install before running this script.")
        sys.exit(1)

def create_requirements():
    log("INFO", f"Creating {REQUIREMENTS_FILE}...")
    with open(REQUIREMENTS_FILE, "w") as f:
        f.write("\n".join(REQUIREMENTS))
    log("INFO", f"{REQUIREMENTS_FILE} created with packages: {', '.join(REQUIREMENTS)}")

def install_requirements():
    log("INFO", f"Installing Python packages from {REQUIREMENTS_FILE}...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", REQUIREMENTS_FILE], check=True)
        log("INFO", "Python packages installed successfully")
    except subprocess.CalledProcessError as e:
        log("ERROR", f"Failed to install Python packages: {e}")
        sys.exit(1)

# -------------------------
# Load .env into os.environ
# -------------------------
def load_env():
    if not os.path.isfile(ENV_FILE):
        create_env_example()
        with open(ENV_FILE, "w") as f:
            with open(ENV_EXAMPLE_FILE, "r") as ef:
                f.write(ef.read())
        log("WARNING", f".env file was missing. Created from {ENV_EXAMPLE_FILE}. Please update it with real API keys.")
    with open(ENV_FILE) as f:
        for line in f:
            if line.strip() and not line.startswith("#") and "=" in line:
                k, v = line.strip().split("=", 1)
                os.environ.setdefault(k, v)

def create_env_example():
    example_content = "# Example .env\nIPINFO_API_KEY=\nFEED1_API_KEY=\nFEED1_URL=\nFEED1_TYPE=IP\n"
    with open(ENV_EXAMPLE_FILE, "w") as f:
        f.write(example_content)
    log("INFO", f"Created {ENV_EXAMPLE_FILE} with placeholders")

# -------------------------
# Retry wrapper
# -------------------------
def retry_task(task_callable, *args, **kwargs):
    for attempt in range(1, RETRY_MAX + 1):
        log("INFO", f"Attempt {attempt}: Running {task_callable.__name__}...")
        try:
            result = task_callable(*args, **kwargs)
            log("INFO", f"{task_callable.__name__} succeeded")
            return result
        except Exception as e:
            log("ERROR", f"{task_callable.__name__} failed: {e}")
            if attempt < RETRY_MAX:
                sleep_time = RETRY_DELAY ** attempt
                log("INFO", f"Retrying in {sleep_time}s...")
                time.sleep(sleep_time)
            else:
                log("ERROR", f"All retries for {task_callable.__name__} failed")
                raise

# -------------------------
# Shell command helper
# -------------------------
def run_shell(command, check=True):
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0 and check:
        raise RuntimeError(f"Command failed: {command}\n{result.stderr}")
    return result.stdout.strip()

# -------------------------
# Phase 1: GitHub Repo Setup
# -------------------------
def phase1_setup():
    log("INFO", "Starting Phase 1: GitHub Repo setup...")
    try:
        run_shell("git checkout -b main")
    except RuntimeError:
        run_shell("git checkout main")
    try:
        run_shell("git init 2>/dev/null")
    except RuntimeError:
        log("INFO", "Git repo already initialized")
    with open("README.md", "w") as f:
        f.write("# Unified Threat Feed\n")
    run_shell("git add README.md")
    try:
        run_shell('git commit -m "Phase 1 setup: initialize repo"')
    except RuntimeError:
        log("INFO", "No changes to commit")

# -------------------------
# Phase 2: Directory Setup
# -------------------------
def phase2_directories():
    log("INFO", "Creating Phase 2 directories...")
    os.makedirs("feeds/raw", exist_ok=True)
    os.makedirs("feeds/parsed", exist_ok=True)
    os.makedirs("scripts", exist_ok=True)
    os.makedirs(".github/workflows", exist_ok=True)

# -------------------------
# Phase 2: fetch_and_parse.py (parallel)
# -------------------------
def create_fetch_and_parse():
    log("INFO", "Creating scripts/fetch_and_parse.py with parallel feed fetching and parsing...")
    content = '''import os
import json
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing

RAW_DIR = "../feeds/raw"
PARSED_DIR = "../feeds/parsed"
os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(PARSED_DIR, exist_ok=True)

def load_feeds_from_env():
    feeds = []
    for k, v in os.environ.items():
        if k.endswith("_API_KEY") and v.strip():
            name = k.replace("_API_KEY", "")
            url = os.environ.get(f"{name}_URL", None)
            if url:
                feeds.append({
                    "name": name,
                    "url": url,
                    "headers": {"Authorization": v},
                    "type": os.environ.get(f"{name}_TYPE", "IP")
                })
    return feeds

FEEDS = load_feeds_from_env()

def fetch_feed(feed):
    api_header = next(iter(feed.get("headers", {}).values()), None)
    if not api_header:
        print(f"[WARNING] Skipping {feed['name']} because API key is missing.")
        return []
    print(f"Fetching {feed['name']}...")
    try:
        response = requests.get(feed['url'], headers=feed.get('headers', {}))
        response.raise_for_status()
        filename = f"{RAW_DIR}/{feed['name']}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
        with open(filename, "w") as f:
            f.write(response.text)
        return response.json() if "application/json" in response.headers.get("Content-Type", "") else response.text
    except Exception as e:
        print(f"[ERROR] Fetching {feed['name']} failed: {e}")
        return []

def enrich_ip(ip):
    ipinfo_token = os.getenv("IPINFO_API_KEY")
    if not ipinfo_token:
        return {}
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json?token={ipinfo_token}")
        data = r.json()
        return {
            "geolocation": {"country": data.get("country"), "region": data.get("region"), "city": data.get("city")},
            "asn": data.get("org", "").split()[0] if data.get("org") else None,
            "isp": " ".join(data.get("org", "").split()[1:]) if data.get("org") else None
        }
    except Exception as e:
        print(f"[ERROR] Enriching IP {ip} failed: {e}")
        return {}

def normalize_indicator(feed_name, indicator, i_type="IP"):
    enriched = enrich_ip(indicator) if i_type == "IP" else {}
    return {
        "indicator": indicator,
        "type": i_type,
        "threat_type": "malware",
        "source": feed_name,
        "first_seen": datetime.utcnow().isoformat(),
        "last_seen": datetime.utcnow().isoformat(),
        "confidence": 80,
        "enrichment": enriched
    }

def deduplicate(data):
    seen = set()
    unique = []
    for item in data:
        key = item["indicator"] + item["type"]
        if key not in seen:
            unique.append(item)
            seen.add(key)
    return unique

def process_feed(feed):
    all_indicators = []
    raw_data = fetch_feed(feed)
    if isinstance(raw_data, list):
        for i in raw_data:
            all_indicators.append(normalize_indicator(feed["name"], i, feed["type"]))
    elif isinstance(raw_data, dict) and "data" in raw_data:
        for i in raw_data["data"]:
            all_indicators.append(normalize_indicator(feed["name"], i.get("ipAddress", ""), feed["type"]))
    return all_indicators

def main():
    if not FEEDS:
        print("[INFO] No feeds found in .env. Please add API keys and optional URLs (NAME_URL) and TYPE (NAME_TYPE).")
        return

    all_indicators = []
    max_workers = min(len(FEEDS), multiprocessing.cpu_count())
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_feed, feed): feed for feed in FEEDS}
        for future in as_completed(futures):
            feed = futures[future]
            try:
                result = future.result()
                all_indicators.extend(result)
                print(f"[INFO] {feed['name']} processed with {len(result)} indicators")
            except Exception as e:
                print(f"[ERROR] Processing feed {feed['name']} failed: {e}")

    all_indicators = deduplicate(all_indicators)
    parsed_file = f"{PARSED_DIR}/parsed_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
    with open(parsed_file, "w") as f:
        json.dump(all_indicators, f, indent=2)
    print(f"Saved parsed feed to {parsed_file}")

if __name__ == "__main__":
    main()
'''
    os.makedirs("scripts", exist_ok=True)
    with open("scripts/fetch_and_parse.py", "w") as f:
        f.write(content)

# -------------------------
# Phase 3: Placeholder feed scripts
# -------------------------
def create_placeholder_scripts():
    log("INFO", "Creating dynamic placeholder threat feed scripts...")
    feed_names = [k.replace("_API_KEY", "") for k in os.environ if k.endswith("_API_KEY") and os.environ[k].strip()]
    THREAT_SCRIPTS.clear()
    for feed_name in feed_names:
        script_path = f"scripts/fetch_{feed_name.lower()}.py"
        THREAT_SCRIPTS.append(script_path)
        content = f'''"""
Placeholder script for threat feed: {feed_name}
"""
import subprocess
import sys

print("Running fetch_and_parse for {feed_name}...")
subprocess.run([sys.executable, "scripts/fetch_and_parse.py"], check=True)
'''
        with open(script_path, "w") as f:
            f.write(content)

# -------------------------
# Validate .env keys
# -------------------------
def validate_env():
    missing = [k for k in os.environ if k.endswith("_API_KEY") and not os.environ[k].strip()]
    if missing:
        log("WARNING", f"Missing API keys for: {', '.join(missing)}")

# -------------------------
# Run threat feed scripts in parallel
# -------------------------
def run_threat_scripts():
    log("INFO", "Running all threat feed scripts in parallel...")
    if not THREAT_SCRIPTS:
        log("INFO", "No threat feed scripts found, skipping execution.")
        return
    max_workers = min(len(THREAT_SCRIPTS), multiprocessing.cpu_count())
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(subprocess.run, [sys.executable, script], {"check": True}): script for script in THREAT_SCRIPTS}
        for future in as_completed(futures):
            script = futures[future]
            try:
                future.result()
                log("INFO", f"{script} executed successfully")
            except Exception as e:
                log("ERROR", f"{script} failed: {e}")

# -------------------------
# Create ZIP archive of parsed feeds
# -------------------------
def create_zip():
    zip_name = f"{DIST_DIR}/feeds_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.zip"
    log("INFO", f"Creating ZIP archive {zip_name}")
    with zipfile.ZipFile(zip_name, "w") as zipf:
        for root, _, files in os.walk("feeds/parsed"):
            for file in files:
                zipf.write(os.path.join(root, file), arcname=file)
    log("INFO", f"ZIP archive created: {zip_name}")

# -------------------------
# Git commit and push
# -------------------------
def git_commit_push(message="Automated update"):
    run_shell("git add .")
    try:
        run_shell(f'git commit -m "{message}"')
    except RuntimeError:
        log("INFO", "No changes to commit")
    run_shell("git push origin main")

# -------------------------
# GitHub release (placeholder)
# -------------------------
def github_release(tag="v1.0.0"):
    log("INFO", f"Creating GitHub release {tag} (placeholder)")
    pass

# -------------------------
# Generate GitHub Actions workflow with matrix
# -------------------------
def generate_workflow():
    log("INFO", "Generating Phase 3 GitHub Actions workflow...")
    workflow_content = f'''name: Phase3 Update Feeds

on:
  schedule:
    - cron: "0 * * * *"
  workflow_dispatch:

jobs:
  update_feeds:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        script: [{', '.join(f'"{script}"' for script in THREAT_SCRIPTS)}]
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.x'
      - name: Install dependencies
        run: pip install -r {REQUIREMENTS_FILE}
      - name: Run threat feed script
        run: python ${{{{ matrix.script }}}}
'''
    with open(WORKFLOW_FILE, "w") as f:
        f.write(workflow_content)
    log("INFO", f"Workflow written to {WORKFLOW_FILE}")

# -------------------------
# Main execution
# -------------------------
if __name__ == "__main__":
    check_python_env()
    create_requirements()
    install_requirements()
    load_env()
    phase1_setup()
    phase2_directories()
    create_fetch_and_parse()
    create_placeholder_scripts()
    validate_env()
    run_threat_scripts()
    create_zip()
    git_commit_push()
    github_release()
    generate_workflow()
    log("INFO", "Unified Threat Feed setup complete!")
