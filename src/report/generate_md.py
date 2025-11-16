from typing import Dict
from tabulate import tabulate
from datetime import datetime

def _table_hosts(parsed: Dict) -> str:
    rows=[]
    for h in parsed.get("hosts", []):
        open_ports = sorted([p["port"] for p in h.get("ports", []) if p.get("state")=="open" and p.get("port") is not None])
        rows.append([h.get("ip"), h.get("hostname") or "", h.get("status") or "", ",".join(map(str, open_ports))])
    return tabulate(rows, headers=["IP","Hostname","Status","Open Ports"], tablefmt="github")

def _table_changes(diff: Dict) -> str:
    rows=[]
    for c in diff.get("changes", []):
        rows.append([c["ip"], ",".join(map(str,c["added_ports"])), ",".join(map(str,c["removed_ports"]))])
    if not rows:
        rows=[["—","—","—"]]
    return tabulate(rows, headers=["Host","Newly Opened","Now Closed"], tablefmt="github")

def generate_report_md(parsed: Dict, diff: Dict|None = None) -> str:
    ts = datetime.utcnow().isoformat()+"Z"
    out=[]
    out.append(f"# Automated Recon Report\n\n_Generated: {ts}_\n")
    out.append("## Scan Summary")
    out.append(_table_hosts(parsed))
    if diff is not None:
        out.append("\n## Changes vs Baseline")
        out.append(_table_changes(diff))
    return "\n\n".join(out)
