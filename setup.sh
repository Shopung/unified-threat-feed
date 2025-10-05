#!/bin/bash

# =========================
# Unified Threat Feed Full Setup (Phase 1 + Phase 2)
# =========================

echo "Starting Unified Threat Feed setup..."

# -------------------------
# Phase 1: GitHub Repo Setup
# -------------------------
git checkout -b main || git checkout main
git init 2>/dev/null || echo "Git repo already initialized"

echo "# Unified Threat Feed" > README.md
git add README.md
git commit -m "Phase 1 setup: initialize repo" || echo "No changes to commit"

# -------------------------
# Phase 2: Directory Setup
# -------------------------
echo "Creating Phase 2 directories..."
mkdir -p feeds/raw feeds/parsed scripts .github/workflows

# -------------------------
# Phase 2: Python Script
# -------------------------
cat << 'EOF' > scripts/fetch_and_parse.py
import os
import json
import requests
from datetime import datetime

RAW_DIR = "../feeds/raw"
PARSED_DIR = "../feeds/parsed"
os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(PARSED_DIR, exist_ok=True)

FEEDS = [
    {"name": "OTX", "url": "https://otx.alienvault.com/api/v1/indicators/export?type=IPv4",
     "headers": {"X-OTX-API-KEY": os.getenv("OTX_API_KEY")}, "type": "IP"},
    {"name": "AbuseIPDB", "url": "https://api.abuseipdb.com/api/v2/blacklist",
     "headers": {"Key": os.getenv("ABUSEIPDB_API_KEY")}, "type": "IP"}
]

def fetch_feed(feed):
    print(f"Fetching {feed['name']}...")
    try:
        response = requests.get(feed["url"], headers=feed.get("headers", {}))
        response.raise_for_status()
        filename = f"{RAW_DIR}/{feed['name']}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
        with open(filename, "w") as f:
            f.write(response.text)
        return response.json() if "application/json" in response.headers.get("Content-Type","") else response.text
    except Exception as e:
        print(f"Error fetching {feed['name']}: {e}")
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
        print(f"Error enriching IP {ip}: {e}")
        return {}

def enrich_domain(domain):
    whois_api_key = os.getenv("WHOIS_API_KEY")
    if not whois_api_key:
        return {}
    try:
        r = requests.get(f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={whois_api_key}&domainName={domain}&outputFormat=JSON")
        data = r.json()
        registrant = data.get("WhoisRecord", {}).get("registryData", {}).get("registrant", {})
        creation_date = data.get("WhoisRecord", {}).get("registryData", {}).get("registryCreationDate")
        return {"whois": {"registrant": registrant.get("name"), "creation_date": creation_date}}
    except Exception as e:
        print(f"Error enriching domain {domain}: {e}")
        return {}

def normalize_indicator(feed_name, indicator, i_type="IP"):
    enriched = enrich_ip(indicator) if i_type=="IP" else enrich_domain(indicator) if i_type=="domain" else {}
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

def main():
    all_indicators = []
    for feed in FEEDS:
        raw_data = fetch_feed(feed)
        if isinstance(raw_data, list):
            for i in raw_data:
                all_indicators.append(normalize_indicator(feed["name"], i, feed["type"]))
        elif isinstance(raw_data, dict) and "data" in raw_data:
            for i in raw_data["data"]:
                all_indicators.append(normalize_indicator(feed["name"], i.get("ipAddress",""), feed["type"]))
    all_indicators = deduplicate(all_indicators)
    parsed_file = f"{PARSED_DIR}/parsed_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
    with open(parsed_file, "w") as f:
        json.dump(all_indicators, f, indent=2)
    print(f"Saved parsed feed to {parsed_file}")

if __name__ == "__main__":
    main()
EOF

# -------------------------
# Phase 2: GitHub Actions Workflow
# -------------------------
cat << 'EOF' > .github/workflows/update_feeds.yml
name: Update Threat Feeds
on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:
jobs:
  update_feeds:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: "3.11"
      - run: pip install requests python-whois jq
      - run: python scripts/fetch_and_parse.py
        env:
          OTX_API_KEY: ${{ secrets.OTX_API_KEY }}
          ABUSEIPDB_API_KEY: ${{ secrets.ABUSEIPDB_API_KEY }}
          IPINFO_API_KEY: ${{ secrets.IPINFO_API_KEY }}
          WHOIS_API_KEY: ${{ secrets.WHOIS_API_KEY }}
      - run: |
          git config --global user.name "github-actions[bot]"
          git config --global user.email "github-actions[bot]@users.noreply.github.com"
          git add feeds/parsed/
          git commit -m "Update enriched threat feeds [skip ci]" || echo "No changes to commit"
          git push
EOF

# -------------------------
# Phase 2: Requirements File
# -------------------------
echo -e "requests\npython-whois\njq" > requirements.txt

# -------------------------
# Phase 2: Create ZIP
# -------------------------
echo "Creating Phase 2 ZIP..."
python3 - <<'EOF'
import zipfile, os
zip_name = "unified_threat_feed_phase2.zip"
source_dirs = ["feeds", "scripts", ".github", "requirements.txt", "README.md"]
with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for path in source_dirs:
        if os.path.isfile(path):
            zipf.write(path)
        else:
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, ".")
                    zipf.write(file_path, arcname)
print(f"Phase 2 zip created: {zip_name}")
EOF

# -------------------------
# Phase 2: Validate GitHub Secrets
# -------------------------
echo "Validating GitHub Secrets..."
SECRETS=("OTX_API_KEY" "ABUSEIPDB_API_KEY" "IPINFO_API_KEY" "WHOIS_API_KEY")
MISSING=0
for secret in "${SECRETS[@]}"; do
    if [ -z "${!secret}" ]; then
        echo "WARNING: $secret not set. Please add it as a GitHub Secret or local env variable."
        MISSING=1
    else
        echo "Found $secret"
    fi
done
echo "Add missing secrets in GitHub: Settings → Secrets → Actions."

# -------------------------
# Phase 2: Local Validation
# -------------------------
if [ $MISSING -eq 0 ]; then
    echo "Running local Phase 2 validation..."
    python3 scripts/fetch_and_parse.py
    LAST_PARSED=$(ls -1 feeds/parsed/ | sort | tail -n 1)
    if [ -n "$LAST_PARSED" ]; then
        COUNT=$(jq '. | length' "feeds/parsed/$LAST_PARSED")
        echo "Local validation complete: $COUNT indicators fetched and enriched in $LAST_PARSED"
    else
        echo "No parsed feed files found after local validation."
    fi
else
    echo "Skipping local validation due to missing environment variables."
fi

# -------------------------
# Phase 2: Create .env.example
# -------------------------
echo "Creating .env.example with placeholder API keys..."
cat << 'EOF' > .env.example
# ==========================
# Unified Threat Feed API Keys
# ==========================

OTX_API_KEY=your_otx_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
IPINFO_API_KEY=your_ipinfo_api_key_here
WHOIS_API_KEY=your_whois_api_key_here
EOF

echo "Created .env.example. Copy to .env and fill in real API keys:"
echo "  cp .env.example .env"
echo "Then either export locally or add them as GitHub Secrets."

# -------------------------
# Phase 2: Commit All Files
# -------------------------
echo "Committing Phase 2 files to GitHub..."
git add .
git commit -m "Phase 2 setup: add scripts, workflow, requirements, ZIP, and .env.example" || echo "No changes to commit"
git push -u origin main || echo "Ensure your GitHub remote is set"

echo "Setup complete! All Phase 2 files committed and ready."
