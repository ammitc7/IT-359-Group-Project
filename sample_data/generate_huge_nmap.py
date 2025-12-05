import random
from pathlib import Path
from datetime import datetime
def generate_host(ip: str, hostname: str | None, open_ports: list[tuple[int, str, str]]) -> str:
    """
    Build an <host> block for nmap XML.
    open_ports: list of (port, service_name, product)
    """
    host_xml = []
    host_xml.append('  <host>')
    host_xml.append('    <status state="up"/>')
    host_xml.append(f'    <address addr="{ip}" addrtype="ipv4"/>')
    host_xml.append('    <hostnames>')
    if hostname:
        host_xml.append(f'      <hostname name="{hostname}" type="user"/>')
    host_xml.append('    </hostnames>')
    host_xml.append('    <ports>')
    for port, service, product in open_ports:
        host_xml.append(f'      <port protocol="tcp" portid="{port}">')
        host_xml.append('        <state state="open"/>')
        host_xml.append(f'        <service name="{service}" product="{product}" />')
        host_xml.append('      </port>')
    host_xml.append('    </ports>')
    host_xml.append('  </host>')
    return "\n".join(host_xml)


def main():
    out_path = Path("sample_data/huge_nmap_sample.xml")
    num_hosts = 150  # adjust if you want even bigger
    random.seed(42)

    # Common fake services to sprinkle around
    common_ports = [
        (22, "ssh", "OpenSSH"),
        (80, "http", "Apache httpd"),
        (443, "https", "nginx"),
        (3306, "mysql", "MySQL"),
        (3389, "ms-wbt-server", "Microsoft RDP"),
        (8080, "http-alt", "Jetty"),
        (53, "domain", "BIND"),
        (25, "smtp", "Postfix"),
    ]

    lines = []
    now = datetime.utcnow().strftime("%a %b %d %H:%M:%S %Y")
    lines.append('<?xml version="1.0"?>')
    lines.append('<!DOCTYPE nmaprun>')
    lines.append(f'<nmaprun scanner="nmap" args="nmap -sV 10.0.0.0/24 -oX huge_nmap_sample.xml" startstr="{now}">')

    base_ip_parts = [10, 0, 0, 1]

    for i in range(num_hosts):
        ip = f"10.0.0.{i+1}"
        hostname = f"host-{i+1}.lab.local"
        # choose between 2 and 6 random ports for each host
        ports_for_host = random.sample(common_ports, k=random.randint(2, 6))
        lines.append(generate_host(ip, hostname, ports_for_host))

    lines.append('</nmaprun>')

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OK] Generated {num_hosts} fake hosts into {out_path}")


if __name__ == "__main__":
    main()
