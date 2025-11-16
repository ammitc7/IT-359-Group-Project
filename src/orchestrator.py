import argparse
import yaml
from pathlib import Path
from src.parsers.nmap_parser import parse_nmap_xml
from src.parsers.masscan_parser import parse_masscan_json
from src.storage.store_json import store_json
from src.storage.store_sqlite import store_scan_to_sqlite
from src.alerts.notifier import notify_unexpected_ports
from src.analysis.diff import diff_scans
from src.report.generate_md import generate_report_md
import json

def load_expected(path: str):
    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8"))

def load_parsed_json(path: str):
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))

def detect_format(input_path: str) -> str:
    if input_path.lower().endswith(".xml"):
        return "nmap-xml"
    if input_path.lower().endswith(".json"):
        return "masscan-json"
    return "nmap-xml"

def main():
    ap = argparse.ArgumentParser(description="Parse saved scan outputs, store results, alert, and report (dry-run safe).")
    ap.add_argument("--input", required=True, help="Path to nmap XML or masscan JSON")
    ap.add_argument("--output-dir", required=True, help="Directory for normalized JSON and reports")
    ap.add_argument("--expected-ports", default="expected_ports.yaml", help="Expected ports YAML")
    ap.add_argument("--sqlite", default="", help="Optional SQLite DB path to store results")
    ap.add_argument("--baseline-json", default="", help="Optional previous normalized JSON to diff against")
    ap.add_argument("--report-md", default="", help="Optional path for a Markdown report")
    ap.add_argument("--dry-run", action="store_true", help="Dry-run mode (default safe)")
    args = ap.parse_args()

    if not args.dry_run:
        print("Warning: default is dry-run. Please pass --dry-run to stay safe. Exiting.")
        return

    fmt = detect_format(args.input)
    if fmt == "nmap-xml":
        parsed = parse_nmap_xml(args.input)
        parsed["metadata"]["scanner"] = "nmap"
    else:
        parsed = parse_masscan_json(args.input)

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    norm_json_path = outdir / (Path(args.input).stem + ".json")
    store_json(parsed, str(norm_json_path))
    print(f"[OK] Normalized JSON saved to {norm_json_path}")

    expected = load_expected(args.expected_ports) or {}
    defaults = set(expected.get("defaults", {}).get("expected_ports", []))
    hosts_expected = expected.get("hosts", {})

    for host in parsed.get("hosts", []):
        ip = host.get("ip")
        discovered = {p["port"] for p in host.get("ports", []) if p.get("state")=="open" and p.get("port")}
        exp = set(hosts_expected.get(ip, {}).get("expected_ports", defaults))
        unexpected = sorted(list(discovered - exp))
        if unexpected:
            notify_unexpected_ports(
                target=parsed.get("target","unknown"),
                host_ip=ip,
                unexpected=unexpected,
                details={"discovered": list(discovered), "expected": list(exp)}
            )

    if args.sqlite:
        store_scan_to_sqlite(args.sqlite, parsed)
        print(f"[OK] Stored to SQLite DB: {args.sqlite}")

    diff = None
    if args.baseline_json:
        old = load_parsed_json(args.baseline_json)
        if old:
            diff = diff_scans(old, parsed)

    if args.report_md:
        md = generate_report_md(parsed, diff)
        Path(args.report_md).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report_md).write_text(md, encoding="utf-8")
        print(f"[OK] Report saved to {args.report_md}")

if __name__ == "__main__":
    main()
