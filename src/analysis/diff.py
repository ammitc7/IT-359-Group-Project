from typing import Dict, Set

def _host_map(parsed: Dict) -> Dict[str, Set[int]]:
    m={}
    for h in parsed.get("hosts", []):
        open_ports = {p["port"] for p in h.get("ports", []) if p.get("state")=="open" and p.get("port") is not None}
        m[h.get("ip")] = open_ports
    return m

def diff_scans(old: Dict, new: Dict) -> Dict:
    a=_host_map(old); b=_host_map(new)
    all_hosts = set(a.keys()) | set(b.keys())
    changes=[]
    for ip in sorted(all_hosts):
        oldp=a.get(ip,set()); newp=b.get(ip,set())
        added = sorted(list(newp - oldp))
        removed = sorted(list(oldp - newp))
        if added or removed:
            changes.append({"ip": ip, "added_ports": added, "removed_ports": removed})
    return {"changes": changes}
