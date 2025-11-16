import argparse
import yaml
from pathlib import Path
from src.parsers.nmap_parser import parse_nmap_xml
from src.storage.store_json import store_json
from src.alerts.notifier import notify_unexpected_ports


def load_expected(path: str):
    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Process saved nmap XML outputs (dry-run).")
    parser.add_argument("--input", required=True, help="Path to nmap XML file")
    parser.add_argument("--output-dir", required=True, help="Write normalized outputs here")
    parser.add_argument("--expected-ports", default="expected_ports.yaml", help="YAML config")
    parser.add_argument("--dry-run", action="store_true", help="Dry-run mode (default safe)")
    args = parser.parse_args()

    if not args.dry_run:
        print("Warning: default is dry-run. Please pass --dry-run to stay safe. Exiting.")
        return

    parsed = parse_nmap_xml(args.input)
    outp = Path(args.output_dir) / (Path(args.input).stem + ".json")
    store_json(parsed, str(outp))
    print(f"Parsed output saved to {outp}")

    expected = load_expected(args.expected_ports) or {}
    defaults = set(expected.get("defaults", {}).get("expected_ports", []))
    hosts_expected = expected.get("hosts", {})

    for host in parsed.get("hosts", []):
        ip = host.get("ip")
        discovered = {
            p["port"]
            for p in host.get("ports", [])
            if p.get("state") == "open" and p.get("port")
        }
        exp = set(hosts_expected.get(ip, {}).get("expected_ports", defaults))
        unexpected = sorted(list(discovered - exp))
        if unexpected:
            notify_unexpected_ports(
                target=parsed.get("target", "unknown"),
                host_ip=ip,
                unexpected=unexpected,
                details={"discovered": list(discovered), "expected": list(exp)},
            )


if __name__ == "__main__":
    main()
