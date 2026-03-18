from fastapi import APIRouter

router = APIRouter()

# Sample log data — later replace with real database
SAMPLE_LOGS = [
    {"id":1,"time":"04:12:33","source":"AWS CloudTrail","event":"CreateInstance",  "ip":"185.220.101.42","risk":"HIGH",    "malware":"Mirai Botnet"       },
    {"id":2,"time":"04:13:01","source":"GCP Audit",     "event":"BucketRead",      "ip":"192.168.1.10",  "risk":"LOW",     "malware":"Clean"              },
    {"id":3,"time":"04:14:55","source":"Azure Monitor", "event":"UnusualLogin",    "ip":"45.33.32.156",  "risk":"CRITICAL","malware":"Ransomware.LockBit" },
    {"id":4,"time":"04:15:10","source":"AWS CloudTrail","event":"IAMRoleChange",   "ip":"103.21.244.0",  "risk":"MEDIUM",  "malware":"Trojan.GenericKD"   },
    {"id":5,"time":"04:16:22","source":"GCP Audit",     "event":"APIKeyExposed",   "ip":"198.54.117.198","risk":"HIGH",    "malware":"Spyware.Agent"      },
    {"id":6,"time":"04:17:44","source":"Azure Monitor", "event":"DataExfiltration","ip":"91.108.4.0",    "risk":"CRITICAL","malware":"APT.Lazarus"        },
]

@router.get("/all")
def get_all_logs():
    return {"logs": SAMPLE_LOGS, "total": len(SAMPLE_LOGS)}

@router.get("/{log_id}")
def get_log(log_id: int):
    log = next((l for l in SAMPLE_LOGS if l["id"] == log_id), None)
    if not log:
        return {"error": "Log not found"}
    return log