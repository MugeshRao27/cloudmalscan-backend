import hashlib
import os
import requests

VIRUSTOTAL_API_KEY = "fd6e68a615a7dbe0576af4ddc4f653b7501d8ab1be2939830ca7485351b16fa9"

def get_file_hashes(file_path):
    """Compute MD5 and SHA256 hash of file"""
    md5    = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {
        "md5":    md5.hexdigest(),
        "sha256": sha256.hexdigest(),
    }

def get_file_info(file_path):
    """Get basic file metadata"""
    size = os.path.getsize(file_path)
    ext  = os.path.splitext(file_path)[1].lower()
    type_map = {
        ".json": "JSON Log File",
        ".csv":  "CSV Log File",
        ".log":  "Log File",
        ".exe":  "Windows Executable",
        ".dll":  "Windows DLL",
        ".txt":  "Text File",
    }
    return {
        "size_bytes": size,
        "size_kb":    round(size / 1024, 2),
        "extension":  ext,
        "file_type":  type_map.get(ext, "Unknown File Type"),
    }

def check_suspicious_strings(file_path):
    """Look for suspicious strings inside the file"""
    suspicious = [
        "cmd.exe", "powershell", "base64", "eval(",
        "exec(", "wget", "curl", "/bin/sh", "nc -e",
        "mimikatz", "metasploit", "payload",
    ]
    found = []
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()
            for s in suspicious:
                if s in content:
                    found.append(s)
    except Exception:
        pass
    return found

def virustotal_lookup(file_hash: str):
    """Look up a file hash on VirusTotal"""
    try:
        url     = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r       = requests.get(url, headers=headers, timeout=10)

        if r.status_code == 200:
            stats     = r.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            total     = sum(stats.values())
            return {
                "result":    f"{malicious} / {total} engines flagged",
                "malicious": malicious,
                "total":     total,
            }
        elif r.status_code == 404:
            return {"result": "Not found in VirusTotal", "malicious": 0, "total": 0}
        else:
            return {"result": "Lookup failed", "malicious": 0, "total": 0}

    except Exception as e:
        return {"result": f"Error: {str(e)}", "malicious": 0, "total": 0}
