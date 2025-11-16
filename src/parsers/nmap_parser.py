from lxml import etree
from typing import Dict

def parse_nmap_xml(path: str) -> Dict:
    tree = etree.parse(path)
    root = tree.getroot()
    result = {"scan_id": "", "target": "", "hosts": [], "metadata": {}}

    scaninfo = root.find("scaninfo")
    if scaninfo is not None:
        result["metadata"]["scaninfo"] = {k: scaninfo.get(k) for k in scaninfo.keys()}

    for host in root.findall("host"):
        ip = None
        hostname = None
        status = None
        ports_list = []

        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")

        hnames = host.find("hostnames")
        if hnames is not None:
            hn = hnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        st = host.find("status")
        if st is not None:
            status = st.get("state")

        ports = host.find("ports")
        if ports is not None:
            for p in ports.findall("port"):
                try:
                    portnum = int(p.get("portid"))
                except Exception:
                    portnum = None
                proto = p.get("protocol")
                state_el = p.find("state")
                state = state_el.get("state") if state_el is not None else None
                service_el = p.find("service")
                service = service_el.get("name") if service_el is not None else None

                banner = None
                if service_el is not None:
                    prod = service_el.get("product")
                    ver = service_el.get("version")
                    extrainfo = service_el.get("extrainfo")
                    parts = [x for x in (prod, ver, extrainfo) if x]
                    if parts:
                        banner = " ".join(parts)

                ports_list.append({
                    "port": portnum,
                    "protocol": proto,
                    "state": state,
                    "service": service,
                    "banner": banner
                })

        hostobj = {"ip": ip, "hostname": hostname, "status": status, "ports": ports_list}
        result["hosts"].append(hostobj)

    return result
