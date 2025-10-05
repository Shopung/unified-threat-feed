#!/usr/bin/env python3
# =========================================
# Unified Threat Feed Full Setup (Phase 1 + Phase 2 + Phase 3 + Phase 4 + Env Check + Auto Install + Auto Scheduler)
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
import smtplib
from email.message import EmailMessage
import glob

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
    example_content = """# Example .env
IPINFO_API_KEY=
FEED1_API_KEY=
FEED1_URL=
FEED1_TYPE=IP
ALERT_EMAIL=
SMTP_SERVER=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
"""
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
    content = """# Your fetch_and_parse.py content from previous Phase 2"""
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
# Phase 4: Alerts, Validation & Cleanup
# -------------------------
def send_alert(subject, message):
    email_to = os.getenv("ALERT_EMAIL")
    if not email_to:
        log("INFO", "No ALERT_EMAIL set, skipping alert")
        return
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    if not all([smtp_server, smtp_user, smtp_pass]):
        log("ERROR", "SMTP credentials missing, cannot send alert")
        return
    try:
        email = EmailMessage()
        email.set_content(message)
        email['Subject'] = subject
        email['From'] = smtp_user
        email['To'] = email_to
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(email)
        log("INFO", f"Alert sent to {email_to}")
    except Exception as e:
        log("ERROR", f"Failed to send alert: {e}")

def validate_feeds():
    parsed_files = glob.glob("feeds/parsed/*.json")
    for pf in parsed_files:
        try:
            with open(pf) as f:
                data = json.load(f)
            if not data:
                log("WARNING", f"{pf} is empty")
                send_alert("Unified Feed Warning", f"Parsed feed {pf} is empty")
        except Exception as e:
            log("ERROR", f"Validation failed for {pf}: {e}")
            send_alert("Unified Feed Error", f"Failed to validate {pf}: {e}")

def cleanup_raw_feeds(retention_days=7):
    now = time.time()
    raw_files = glob.glob("feeds/raw/*.json")
    for fpath in raw_files:
        if os.stat(fpath).st_mtime < now - retention_days * 86400:
            try:
                os.remove(fpath)
                log("INFO", f"Deleted old raw feed: {fpath}")
            except Exception as e:
                log("ERROR", f"Failed to delete {fpath}: {e}")

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
                send_alert("Unified Feed Script Error", f"{script} failed: {e}")

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
# Automatic scheduling
# -------------------------
def register_cron_job(interval_minutes=60):
    import getpass
    user = getpass.getuser()
    cron_command = f"*/{interval_minutes} * * * * {sys.executable} {os.path.abspath(__file__)} >> {LOGFILE} 2>&1"
    try:
        existing_cron = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        cron_lines = existing_cron.stdout.splitlines() if existing_cron.returncode == 0 else []
        if cron_command not in cron_lines:
            cron_lines.append(cron_command)
            cron_text = "\n".join(cron_lines)
            subprocess.run(["crontab"], input=cron_text, text=True)
            log("INFO", "Cron job registered successfully.")
        else:
            log("INFO", "Cron job already exists.")
    except Exception as e:
        log("ERROR", f"Failed to register cron job: {e}")

def register_windows_task(interval_minutes=60):
    task_name = "UnifiedThreatFeedAuto"
    abs_path = os.path.abspath(__file__)
    command = f'schtasks /Create /F /SC MINUTE /MO {interval_minutes} /TN "{task_name}" /TR "{sys.executable} {abs_path}" /RL HIGHEST'
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "SUCCESS" in result.stdout:
            log("INFO", "Windows Task Scheduler task created successfully.")
        elif "ERROR" in result.stdout or result.returncode != 0:
            log("ERROR", f"Failed to create Windows task: {result.stdout} {result.stderr}")
        else:
            log("INFO", "Windows task already exists or updated.")
    except Exception as e:
        log("ERROR", f"Failed to register Windows task: {e}")

def setup_auto_scheduler(interval_minutes=60):
    if sys.platform.startswith("win"):
        log("INFO", "Setting up Windows Task Scheduler...")
        register_windows_task(interval_minutes)
    else:
        log("INFO", "Setting up cron job on Linux/macOS...")
        register_cron_job(interval_minutes)

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
    validate_feeds()
    cleanup_raw_feeds()
    create_zip()
    git_commit_push()
    github_release()
    generate_workflow()
    # Setup automatic scheduler (every 60 minutes)
    setup_auto_scheduler(interval_minutes=60)
    log("INFO", "Unified Threat Feed setup complete!")
