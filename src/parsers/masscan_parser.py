import json
from typing import Dict

def parse_masscan_json(path: str) -> Dict:
    hosts_map = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            obj=json.loads(line)
            ip = obj.get("ip") or obj.get("address")
            if not ip:
                continue
            hosts_map.setdefault(ip, {"ip": ip, "hostname": None, "status": "up", "ports": []})
            for porto in obj.get("ports", []):
                hosts_map[ip]["ports"].append({
                    "port": porto.get("port"),
                    "protocol": porto.get("proto") or porto.get("protocol") or "tcp",
                    "state": porto.get("status") or "open",
                    "service": porto.get("service"),
                    "banner": None
                })
    return {
        "scan_id": "",
        "target": "",
        "hosts": list(hosts_map.values()),
        "metadata": {"scanner": "masscan"}
    }
