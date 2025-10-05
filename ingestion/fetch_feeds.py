import os, yaml, requests

def fetch_feed(source):
    try:
        print(f"[+] Fetching {source['name']} ...")
        r = requests.get(source['url'], timeout=30)
        r.raise_for_status()
        filename = f"output/feeds/{source['name'].replace(' ', '_')}.raw"
        with open(filename, 'wb') as f:
            f.write(r.content)
        print(f"    -> Saved to {filename}")
    except Exception as e:
        print(f"[!] Failed to fetch {source['name']}: {e}")

def main():
    os.makedirs("output/feeds", exist_ok=True)
    with open("data_sources/source_list.yml", "r") as f:
        config = yaml.safe_load(f)

    for src in config.get("sources", []):
        if src.get("enabled", False):
            fetch_feed(src)

if __name__ == "__main__":
    main()
