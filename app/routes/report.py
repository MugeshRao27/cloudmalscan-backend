from fastapi import APIRouter

router = APIRouter()

@router.get("/summary")
def get_report_summary():
    return {
        "case_id":      "CMLS-2025-0309-001",
        "generated":    "2025-03-09 04:20:00 UTC",
        "risk_score":   87,
        "verdict":      "MALICIOUS",
        "total_events": 8,
        "platforms":    ["AWS CloudTrail", "Azure Monitor", "GCP Audit"],
        "iocs": [
            {"type": "IP",   "value": "185.220.101.42", "threat": "Mirai Botnet"        },
            {"type": "IP",   "value": "45.33.32.156",   "threat": "Ransomware.LockBit"  },
            {"type": "Hash", "value": "a3f2d91b4c87...", "threat": "Ransomware.LockBit" },
        ],
    }
