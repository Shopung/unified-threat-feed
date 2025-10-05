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
