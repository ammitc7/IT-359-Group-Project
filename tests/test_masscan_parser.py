from pathlib import Path
from src.parsers.masscan_parser import parse_masscan_json

def test_masscan_parser():
    sample = Path("sample_data/masscan_sample.json")
    assert sample.exists()
    parsed = parse_masscan_json(str(sample))
    hosts = {h["ip"]: h for h in parsed["hosts"]}
    assert "10.0.0.10" in hosts
    assert 443 in {p["port"] for p in hosts["10.0.0.10"]["ports"]}
