import argparse
import sqlite3
import pathlib
import textwrap
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Set

import yaml

from src.vuln_correlation import (

    load_vuln_signatures,
    findings_from_dicts,
    correlate_vulnerabilities,
)


# ---------------------------
# Parsing Nmap XML
# ---------------------------

def parse_nmap_xml(xml_path: pathlib.Path) -> List[Dict[str, Any]]:
    """
    Parse an Nmap XML file and return a list of normalized findings.

    Each finding dict has:
      host, hostname, port, protocol, service, product, version
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    ns = ""  # Nmap XML normally has no namespace by default

    findings: List[Dict[str, Any]] = []

    for host_el in root.findall(f"{ns}host"):
        # Host IP
        addr_el = host_el.find(f"{ns}address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        host_ip = addr_el.get("addr")

        # Optional hostname
        hostname_el = host_el.find(f"{ns}hostnames/{ns}hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None

        # Ports
        ports_el = host_el.find(f"{ns}ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall(f"{ns}port"):
            state_el = port_el.find(f"{ns}state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid = int(port_el.get("portid"))
            protocol = port_el.get("protocol") or "tcp"

            service_el = port_el.find(f"{ns}service")
            service_name = service_el.get("name") if service_el is not None else None
            product = service_el.get("product") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None

            findings.append(
                {
                    "host": host_ip,
                    "hostname": hostname,
                    "port": portid,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version,
                }
            )

    return findings


# ---------------------------
# SQLite helpers
# ---------------------------

def init_sqlite(db_path: pathlib.Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            hostname TEXT,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT
        );
        """
    )
    conn.commit()
    return conn


def store_findings(conn: sqlite3.Connection, findings: List[Dict[str, Any]]) -> None:
    cur = conn.cursor()
    cur.executemany(
        """
        INSERT INTO findings (host, hostname, port, protocol, service, product, version)
        VALUES (:host, :hostname, :port, :protocol, :service, :product, :version);
        """,
        findings,
    )
    conn.commit()


def fetch_all_findings(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT host, hostname, port, protocol, service, product, version
        FROM findings
        ORDER BY host, port;
        """
    )
    rows = cur.fetchall()
    result = []
    for host, hostname, port, protocol, service, product, version in rows:
        result.append(
            {
                "host": host,
                "hostname": hostname,
                "port": port,
                "protocol": protocol,
                "service": service,
                "product": product,
                "version": version,
            }
        )
    return result


# ---------------------------
# Expected ports / alerts
# ---------------------------

def load_expected_ports(path: pathlib.Path) -> Set[int]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    ports = data.get("expected_ports") or data.get("ports") or []
    return {int(p) for p in ports}


def generate_unexpected_port_alerts(
    findings: List[Dict[str, Any]], expected_ports: Set[int]
) -> List[str]:
    alerts: List[str] = []

    for f in findings:
        port = f["port"]
        host = f["host"]
        service = f.get("service") or "unknown"
        if port not in expected_ports:
            alerts.append(
                f"Unexpected port {port}/tcp ({service}) detected on host {host}"
            )
    return alerts


# ---------------------------
# Markdown reports
# ---------------------------

def write_markdown_report(
    findings: List[Dict[str, Any]], output_path: pathlib.Path
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []
    lines.append(f"# Recon Report\n")
    lines.append("")
    if not findings:
        lines.append("_No open ports found in this scan._")
    else:
        # Group by host
        lines.append("## Hosts and Open Ports\n")
        current_host = None
        for f in findings:
            host_label = f["host"]
            if host_label != current_host:
                lines.append(f"### Host: {host_label}")
                if f.get("hostname"):
                    lines.append(f"- Hostname: `{f['hostname']}`")
                current_host = host_label
            service = f.get("service") or "unknown"
            product = f.get("product") or ""
            version = f.get("version") or ""
            banner = " ".join(part for part in [product, version] if part)
            lines.append(
                f"- Port **{f['port']}/{f['protocol']}**: `{service}`"
                + (f" — _{banner}_" if banner else "")
            )

    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_alert_report(alerts: List[str], output_path: pathlib.Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines: List[str] = []
    lines.append("# Alerts — Unexpected Ports\n")
    lines.append("")
    if not alerts:
        lines.append("_No unexpected ports detected based on expected_ports.yaml._")
    else:
        for alert in alerts:
            lines.append(f"- {alert}")
    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_vuln_markdown_report(
    correlated, output_path: pathlib.Path
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []
    lines.append("# Vulnerability Risk Report\n")
    lines.append("")
    if not correlated:
        lines.append("_No vulnerabilities correlated for this scan._")
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return

    correlated = sorted(
        correlated, key=lambda c: (c.host, c.port, c.severity), reverse=False
    )

    current_host = None
    for c in correlated:
        host_label = c.hostname or c.host
        if host_label != current_host:
            lines.append(f"## Host: {host_label}")
            current_host = host_label

        banner_parts = [c.product or "", c.version or ""]
        banner = " ".join(p for p in banner_parts if p)

        lines.append(
            f"### Port {c.port}/{c.protocol} ({c.service or 'unknown'}) — "
            f"{c.vuln_id} ({c.severity.upper()})"
        )
        if banner:
            lines.append(f"- Detected service: `{banner}`")
        lines.append(f"- **Vulnerability:** {c.vuln_name}")
        lines.append(f"- **Description:** {c.description}")
        lines.append(f"- **Match reason:** {c.match_reason}")
        if c.references:
            lines.append(f"- **References:**")
            for ref in c.references:
                lines.append(f"  - {ref}")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------
# Orchestration
# ---------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automated Recon Output Parsing & Alerting with Risk Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Example:

              python3 -m src.orchestrator \\
                --input sample_data/huge_nmap_sample.xml \\
                --output-dir output \\
                --expected-ports expected_ports.yaml \\
                --sqlite output/recon.db \\
                --report-md output/report_huge_nmap.md \\
                --vuln-signatures vuln_signatures.yaml \\
                --vuln-report-md output/vuln_report_huge_nmap.md \\
                --dry-run
            """
        ),
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to Nmap XML file (previously saved scan output).",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where reports and database will be stored.",
    )
    parser.add_argument(
        "--expected-ports",
        required=True,
        help="YAML file listing expected/normal ports.",
    )
    parser.add_argument(
        "--sqlite",
        required=True,
        help="Path to SQLite database file to write findings into.",
    )
    parser.add_argument(
        "--report-md",
        required=True,
        help="Path to main Markdown recon report (within output dir).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parsing-only mode (no live scanning; still writes local outputs).",
    )

    # New risk-analysis options
    parser.add_argument(
        "--vuln-signatures",
        help="Path to vuln_signatures.yaml for risk analysis.",
    )
    parser.add_argument(
        "--vuln-report-md",
        help="Path to Markdown vulnerability risk report.",
    )

    args = parser.parse_args()

    input_path = pathlib.Path(args.input)
    output_dir = pathlib.Path(args.output_dir)
    sqlite_path = pathlib.Path(args.sqlite)
    report_md_path = pathlib.Path(args.report_md)
    expected_ports_path = pathlib.Path(args.expected_ports)

    if args.dry_run:
        print("[INFO] Running in dry-run mode (no live scanning, file parsing only).")

    # 1) Parse Nmap XML into normalized findings
    print(f"[INFO] Parsing Nmap XML from {input_path} ...")
    findings = parse_nmap_xml(input_path)
    print(f"[INFO] Parsed {len(findings)} open ports from scan file.")

    # 2) Initialize SQLite and store findings
    print(f"[INFO] Initializing SQLite DB at {sqlite_path} ...")
    conn = init_sqlite(sqlite_path)
    print(f"[INFO] Storing findings into database ...")
    store_findings(conn, findings)

    # 3) Load all findings back (for reporting, grouping, etc.)
    db_findings = fetch_all_findings(conn)

    # 4) Expected ports / alerts
    print(f"[INFO] Loading expected ports from {expected_ports_path} ...")
    expected_ports = load_expected_ports(expected_ports_path)
    alerts = generate_unexpected_port_alerts(db_findings, expected_ports)

    alert_md_path = output_dir / "alerts_unexpected_ports.md"

    # 5) Write main recon report and alerts
    print(f"[INFO] Writing main Markdown report to {report_md_path} ...")
    write_markdown_report(db_findings, report_md_path)

    print(f"[INFO] Writing alerts report to {alert_md_path} ...")
    write_alert_report(alerts, alert_md_path)

    # 6) Optional: Vulnerability risk analysis
    if args.vuln_signatures and args.vuln_report_md:
        vuln_signatures_path = pathlib.Path(args.vuln_signatures)
        vuln_report_path = pathlib.Path(args.vuln_report_md)

        print(f"[INFO] Loading vulnerability signatures from {vuln_signatures_path} ...")
        signatures = load_vuln_signatures(vuln_signatures_path)

        print("[INFO] Running vulnerability correlation (risk analysis) ...")
        port_findings = findings_from_dicts(db_findings)
        correlated = correlate_vulnerabilities(port_findings, signatures)

        print(
            f"[INFO] Writing vulnerability risk Markdown report to {vuln_report_path} ..."
        )
        write_vuln_markdown_report(correlated, vuln_report_path)

        print(
            f"[INFO] Risk analysis complete. {len(correlated)} correlated vulnerabilities written."
        )
    else:
        print(
            "[INFO] No vuln_signatures or vuln_report_md provided; "
            "skipping vulnerability risk analysis."
        )

    conn.close()
    print("[INFO] Done.")


if __name__ == "__main__":
    main()
