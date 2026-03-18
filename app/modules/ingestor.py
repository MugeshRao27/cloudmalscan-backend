import json
import pandas as pd

def parse_cloudtrail(file_path):
    """Parse AWS CloudTrail JSON log file"""
    try:
        with open(file_path) as f:
            data = json.load(f)
        records = data.get("Records", [])
        df = pd.DataFrame(records)
        # Keep only useful columns if they exist
        cols = [c for c in ["eventTime","eventName","sourceIPAddress","userAgent","eventSource"] if c in df.columns]
        return df[cols].to_dict(orient="records")
    except Exception as e:
        return {"error": str(e)}

def parse_csv_log(file_path):
    """Parse generic CSV log file"""
    try:
        df = pd.read_csv(file_path)
        return df.head(50).to_dict(orient="records")
    except Exception as e:
        return {"error": str(e)}