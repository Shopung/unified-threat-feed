import os
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
