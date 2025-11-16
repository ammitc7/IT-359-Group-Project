import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict

ALERT_FILE = Path("output/alerts.json")

def notify_unexpected_ports(target: str, host_ip: str, unexpected: List[int], details: Dict):
    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        arr = json.loads(ALERT_FILE.read_text(encoding="utf-8")) if ALERT_FILE.exists() else []
    except Exception:
        arr = []
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "target": target,
        "host": host_ip,
        "unexpected_ports": unexpected,
        "details": details
    }
    arr.append(entry)
    ALERT_FILE.write_text(json.dumps(arr, indent=2))
    print(f"[ALERT] unexpected ports on {host_ip}: {unexpected} (logged to {ALERT_FILE})")
