import os
import re
import shutil
import joblib
import numpy as np
from fastapi import APIRouter, UploadFile, File
from app.modules.static_analysis import get_file_hashes, get_file_info, check_suspicious_strings, virustotal_lookup

router = APIRouter()

UPLOAD_DIR = "/tmp/cloudmalscan"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── LOAD ML MODEL ─────────────────────────────────
MODEL_PATH    = "app/models/malware_classifier.pkl"
ENCODER_PATH  = "app/models/label_encoder.pkl"
FEATURES_PATH = "app/models/feature_names.pkl"

ml_model      = None
ml_encoder    = None
feature_names = None

try:
    ml_model      = joblib.load(MODEL_PATH)
    ml_encoder    = joblib.load(ENCODER_PATH)
    feature_names = joblib.load(FEATURES_PATH)
    print(f"✅ ML model loaded — {len(feature_names)} features")
except Exception as e:
    print(f"⚠ ML model not loaded: {e}")

# ── FAMILY DETECTION FROM STRINGS ─────────────────
def detect_family_from_strings(suspicious, file_ext):
    s = [x.lower() for x in suspicious]

    ransomware_keys = ["base64", "encrypt", "payload", "ransom", "bitcoin"]
    trojan_keys     = ["mimikatz", "metasploit", "meterpreter", "backdoor"]
    botnet_keys     = ["nc -e", "wget", "curl", "botnet"]
    spyware_keys    = ["keylog", "screenshot", "password", "credential"]
    rootkit_keys    = ["rootkit", "stealth", "hide", "hook"]
    worm_keys       = ["/bin/sh", "spread", "replicate", "worm"]

    scores = {
        "Ransomware": sum(1 for k in ransomware_keys if any(k in x for x in s)),
        "Trojan":     sum(1 for k in trojan_keys     if any(k in x for x in s)),
        "Botnet":     sum(1 for k in botnet_keys     if any(k in x for x in s)),
        "Spyware":    sum(1 for k in spyware_keys    if any(k in x for x in s)),
        "Rootkit":    sum(1 for k in rootkit_keys    if any(k in x for x in s)),
        "Worm":       sum(1 for k in worm_keys       if any(k in x for x in s)),
    }

    if file_ext in [".exe", ".dll"]:
        scores["Trojan"] += 2

    best  = max(scores, key=scores.get)
    score = scores[best]
    return best if score > 0 else "Trojan"

# ── BUILD FEATURE VECTOR ──────────────────────────
def build_features(file_path, file_info, suspicious):
    ext    = file_info["extension"].lower()
    size   = file_info["size_kb"]
    n_susp = len(suspicious)
    s      = [x.lower() for x in suspicious]

    feature_map = {
        "file_size_kb":           size,
        "num_sections":           5 if ext == ".exe" else 2,
        "num_imports":            n_susp * 10,
        "num_exports":            0,
        "has_tls":                1 if ext == ".exe" else 0,
        "has_debug":              0,
        "is_packed":              1 if n_susp > 3 else 0,
        "entropy":                7.5 if n_susp > 3 else 4.5,
        "num_api_calls":          n_susp * 20,
        "num_registry_writes":    n_susp * 5,
        "num_file_writes":        n_susp * 3,
        "num_network_calls":      n_susp * 4,
        "num_process_creates":    n_susp * 2,
        "has_persistence":        1 if any(k in s for k in ["schtasks","startup"])    else 0,
        "has_encryption":         1 if any(k in s for k in ["base64","encrypt"])      else 0,
        "has_keylogger":          1 if any(k in s for k in ["keylog","hook"])         else 0,
        "has_network_spread":     1 if any(k in s for k in ["wget","curl","nc"])      else 0,
        "has_rootkit_behavior":   1 if any(k in s for k in ["rootkit","hide"])        else 0,
        "has_adware_behavior":    0,
        "num_dns_queries":        n_susp * 2,
        "num_http_requests":      n_susp * 5,
        "cpu_usage_avg":          60.0 if n_susp > 3 else 10.0,
        "memory_usage_mb":        200.0 if n_susp > 3 else 50.0,
        "num_suspicious_strings": n_susp,
    }

    if feature_names:
        vector = [feature_map.get(f, 0) for f in feature_names]
    else:
        vector = list(feature_map.values())

    return np.array(vector).reshape(1, -1)

# ── SCAN ENDPOINT ─────────────────────────────────
@router.post("/upload")
async def scan_file(file: UploadFile = File(...)):
    """Upload and scan a file for malware indicators"""

    # Save uploaded file
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # Run static analysis
    hashes     = get_file_hashes(file_path)
    file_info  = get_file_info(file_path)
    suspicious = check_suspicious_strings(file_path)

    # ── Demo hash detection for VT lookup ─────────
    demo_hash = None
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
            match = re.search(r'hash_test:\s*([a-f0-9]{32})', content)
            if match:
                demo_hash = match.group(1)
                print(f"Demo hash found: {demo_hash}")
    except:
        pass

    # Use demo hash for VT if found, otherwise use real file hash
    lookup_hash = demo_hash if demo_hash else hashes["md5"]
    vt          = virustotal_lookup(lookup_hash)
    vt_summary  = vt["result"]

    # Rule based risk score
    risk_score = min(len(suspicious) * 15, 100)

    # ── ML Classification ─────────────────────────
    ml_family     = None
    ml_confidence = 0
    ml_used       = False

    if ml_model is not None:
        try:
            features      = build_features(file_path, file_info, suspicious)
            prediction    = ml_model.predict(features)[0]
            probability   = ml_model.predict_proba(features).max()
            ml_family     = ml_encoder.inverse_transform([prediction])[0]
            ml_confidence = round(float(probability) * 100, 2)
            ml_used       = True
            print(f"ML result: {ml_family} ({ml_confidence}%)")
        except Exception as e:
            print(f"ML error: {e}")

    # ── Final Verdict ─────────────────────────────
    if ml_used and ml_family:
        if ml_family == "clean":
            verdict = "CLEAN"
            family  = "None"
        else:
            verdict = "MALICIOUS"
            family  = detect_family_from_strings(suspicious, file_info["extension"])
    else:
        verdict = "MALICIOUS" if risk_score >= 70 else "SUSPICIOUS" if risk_score >= 40 else "CLEAN"
        family  = detect_family_from_strings(suspicious, file_info["extension"]) if verdict != "CLEAN" else "None"
        ml_confidence = risk_score

    # ── Risk Level ────────────────────────────────
    if verdict == "MALICIOUS" or risk_score >= 70:
        risk = "CRITICAL"
    elif risk_score >= 40:
        risk = "HIGH"
    elif risk_score >= 10:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # ── MITRE Mapping ─────────────────────────────
    mitre_map = {
        "Ransomware": "T1486, T1490, T1041",
        "Trojan":     "T1078, T1548, T1041",
        "Spyware":    "T1056, T1005, T1041",
        "Rootkit":    "T1014, T1562, T1548",
        "Botnet":     "T1071, T1078, T1041",
        "Worm":       "T1021, T1091, T1078",
    }
    mitre = mitre_map.get(family, "T1078, T1548, T1041") if verdict == "MALICIOUS" else "None"

    import datetime
    import firebase_admin
    from firebase_admin import credentials, firestore

    result = {
        "filename":           file.filename,
        "file_type":          file_info["file_type"],
        "size_kb":            file_info["size_kb"],
        "md5":                hashes["md5"],
        "sha256":             hashes["sha256"],
        "suspicious_strings": suspicious,
        "virustotal":         vt_summary,
        "risk_score":         risk_score,
        "verdict":            verdict,
        "family":             family,
        "confidence":         ml_confidence,
        "risk":               risk,
        "ml_used":            ml_used,
        "mitre":              mitre,
        "timestamp":          datetime.datetime.utcnow().isoformat(),
    }

    try:
        if not firebase_admin._apps:
            import json
            gc = os.getenv("GOOGLE_CREDENTIALS")
            if gc:
                cred = credentials.Certificate(json.loads(gc))
            else:
                cred = credentials.Certificate("serviceAccountKey.json")
            firebase_admin.initialize_app(cred)
        db = firestore.client()
        db.collection("scan_logs").add(result)
        print(f"✅ Saved to Firestore: {file.filename}")
    except Exception as e:
        print(f"⚠ Firestore save failed: {e}")

    return result