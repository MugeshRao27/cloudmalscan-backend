# MITRE ATT&CK behavior mapping rules
BEHAVIOR_MAP = {
    "CreateInstance":    {"id": "T1078", "name": "Valid Accounts",           "tactic": "Initial Access"      },
    "IAMRoleChange":     {"id": "T1548", "name": "Abuse Elevation Control",  "tactic": "Privilege Escalation"},
    "UnusualLogin":      {"id": "T1078", "name": "Valid Accounts",           "tactic": "Initial Access"      },
    "DataExfiltration":  {"id": "T1041", "name": "Exfil Over C2 Channel",   "tactic": "Exfiltration"        },
    "APIKeyExposed":     {"id": "T1552", "name": "Unsecured Credentials",    "tactic": "Credential Access"   },
    "BucketRead":        {"id": "T1530", "name": "Cloud Storage Object",     "tactic": "Collection"          },
    "SecurityGroupMod":  {"id": "T1562", "name": "Disable Cloud Logs",       "tactic": "Defense Evasion"     },
    "MassDownload":      {"id": "T1005", "name": "Data from Local System",   "tactic": "Collection"          },
    "RootLogin":         {"id": "T1078", "name": "Valid Accounts",           "tactic": "Initial Access"      },
    "S3BucketPublic":    {"id": "T1537", "name": "Transfer to Cloud Account","tactic": "Exfiltration"        },
}

def map_to_mitre(event_name: str):
    """Map a cloud event name to MITRE ATT&CK technique"""
    return BEHAVIOR_MAP.get(event_name, {
        "id": "T0000", "name": "Unknown Technique", "tactic": "Unclassified"
    })

def map_multiple(event_names: list):
    """Map a list of events to MITRE techniques"""
    results = []
    seen = set()
    for event in event_names:
        technique = map_to_mitre(event)
        if technique["id"] not in seen:
            seen.add(technique["id"])
            results.append(technique)
    return results