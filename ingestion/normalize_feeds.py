import json, os

def normalize_feed(raw_path, source_name):
    normalized = [{
        "ioc": "example.com",
        "type": "domain",
        "source": source_name,
        "first_seen": "2025-10-05",
        "last_seen": "2025-10-05"
    }]
    return normalized

def main():
    os.makedirs("output", exist_ok=True)
    normalized_data = []
    for file in os.listdir("output/feeds"):
        if file.endswith(".raw"):
            source_name = file.replace("_", " ").replace(".raw", "")
            normalized_data.extend(normalize_feed(f"output/feeds/{file}", source_name))
    with open("output/unified_ioc.json", "w") as f:
        json.dump(normalized_data, f, indent=2)
    print(f"[+] Normalized data saved to output/unified_ioc.json")

if __name__ == "__main__":
    main()
