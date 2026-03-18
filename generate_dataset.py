import pandas as pd
import numpy as np
import os

print("Generating CloudMalScan training dataset...")

np.random.seed(42)
NUM_SAMPLES = 5000

# Malware families to simulate
families = [
    "clean",
    "ransomware",
    "trojan",
    "spyware",
    "rootkit",
    "botnet",
    "worm",
    "adware",
]

rows = []

for i in range(NUM_SAMPLES):
    family = np.random.choice(families, p=[
        0.40,   # 40% clean
        0.10,   # 10% ransomware
        0.12,   # 12% trojan
        0.08,   # 8%  spyware
        0.07,   # 7%  rootkit
        0.08,   # 8%  botnet
        0.08,   # 8%  worm
        0.07,   # 7%  adware
    ])

    is_malware = family != "clean"

    row = {
        # Static features
        "file_size_kb":         np.random.normal(500, 200) if is_malware else np.random.normal(200, 100),
        "num_sections":         np.random.randint(5, 15)   if is_malware else np.random.randint(2, 8),
        "num_imports":          np.random.randint(50, 200) if is_malware else np.random.randint(10, 80),
        "num_exports":          np.random.randint(0, 20)   if is_malware else np.random.randint(0, 5),
        "has_tls":              np.random.randint(0, 2),
        "has_debug":            1 if not is_malware else 0,
        "is_packed":            1 if is_malware else 0,
        "entropy":              np.random.uniform(6.5, 8.0) if is_malware else np.random.uniform(4.0, 6.5),

        # Dynamic features
        "num_api_calls":        np.random.randint(100, 500) if is_malware else np.random.randint(10, 150),
        "num_registry_writes":  np.random.randint(10, 100) if is_malware else np.random.randint(0, 20),
        "num_file_writes":      np.random.randint(5, 80)   if is_malware else np.random.randint(0, 15),
        "num_network_calls":    np.random.randint(10, 100) if is_malware else np.random.randint(0, 10),
        "num_process_creates":  np.random.randint(2, 20)   if is_malware else np.random.randint(0, 5),
        "has_persistence":      1 if family in ["ransomware","trojan","rootkit","botnet"] else 0,
        "has_encryption":       1 if family in ["ransomware","trojan"] else 0,
        "has_keylogger":        1 if family in ["spyware","trojan"] else 0,
        "has_network_spread":   1 if family in ["worm","botnet"] else 0,
        "has_rootkit_behavior": 1 if family == "rootkit" else 0,
        "has_adware_behavior":  1 if family == "adware" else 0,
        "num_dns_queries":      np.random.randint(5, 50)   if is_malware else np.random.randint(0, 10),
        "num_http_requests":    np.random.randint(10, 200) if is_malware else np.random.randint(0, 20),
        "cpu_usage_avg":        np.random.uniform(30, 90)  if is_malware else np.random.uniform(5, 40),
        "memory_usage_mb":      np.random.uniform(50, 500) if is_malware else np.random.uniform(10, 100),
        "num_suspicious_strings": np.random.randint(3, 15) if is_malware else np.random.randint(0, 2),

        # Label
        "family": family,
    }
    rows.append(row)

# Create DataFrame
df = pd.DataFrame(rows)

# Make sure no negative values
numeric_cols = df.select_dtypes(include=[np.number]).columns
df[numeric_cols] = df[numeric_cols].clip(lower=0)

# Save dataset
os.makedirs("datasets", exist_ok=True)
df.to_csv("datasets/cmd_2024.csv", index=False)

print(f"✅ Dataset generated: {len(df)} samples")
print(f"✅ Saved to: datasets/cmd_2024.csv")
print(f"\nClass distribution:")
print(df["family"].value_counts())
