import requests

VIRUSTOTAL_API_KEY = "fd6e68a615a7dbe0576af4ddc4f653b7501d8ab1be2939830ca7485351b16fa9"

# These are REAL known malware hashes from public databases
# Safe to use — we are just looking them up, not downloading anything
known_hashes = {
    "WannaCry Ransomware":  "84c82835a5d21bbcf75a61706d8ab549",
    "Mirai Botnet":         "60a1f49cd3680748cf0b3f2b2a0cf5b3",
    "NotPetya":             "027cc450ef5f8c5f653329641ec1fed9",
    "Emotet Trojan":        "a2a8ce4e9a7e73cfbf4c7e0139f6b2d8",
}

print("=" * 55)
print("  CloudMalScan — VirusTotal Live Lookup Test")
print("=" * 55)

for name, hash_val in known_hashes.items():
    print(f"\n🔍 Looking up: {name}")
    print(f"   Hash: {hash_val}")

    url     = f"https://www.virustotal.com/api/v3/files/{hash_val}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=10)

        if r.status_code == 200:
            data      = r.json()["data"]["attributes"]
            stats     = data["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            total     = sum(stats.values())
            names     = list(data.get("names", ["Unknown"])[:2])
            print(f"   ✅ FOUND IN VIRUSTOTAL!")
            print(f"   🚨 {malicious} / {total} engines flagged as MALICIOUS")
            print(f"   📛 Known as: {', '.join(names)}")

        elif r.status_code == 404:
            print(f"   ⚪ Not found in VirusTotal database")

        elif r.status_code == 401:
            print(f"   ❌ Invalid API key")

        else:
            print(f"   ⚠ Status code: {r.status_code}")

    except Exception as e:
        print(f"   ❌ Error: {e}")

print("\n" + "=" * 55)
print("  Test complete!")
print("=" * 55)
