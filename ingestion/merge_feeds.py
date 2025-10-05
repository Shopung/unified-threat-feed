import json, os

MAX_FILE_SIZE_MB = 100

def split_large_file(data, base_filename="unified_ioc"):
    os.makedirs("output", exist_ok=True)
    part = 1
    chunk = []
    for record in data:
        chunk.append(record)
        if (len(json.dumps(chunk)) / (1024 * 1024)) >= MAX_FILE_SIZE_MB:
            fname = f"output/{base_filename}_part{part}.json"
            with open(fname, "w") as f:
                json.dump(chunk, f, indent=2)
            print(f"[+] Created {fname}")
            part += 1
            chunk = []
    if chunk:
        fname = f"output/{base_filename}_part{part}.json"
        with open(fname, "w") as f:
            json.dump(chunk, f, indent=2)
        print(f"[+] Created {fname}")

def main():
    with open("output/unified_ioc.json", "r") as f:
        data = json.load(f)
    split_large_file(data)
    print("[+] Merge complete")

if __name__ == "__main__":
    main()
