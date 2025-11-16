from src.parsers.nmap_parser import parse_nmap_xml
from pathlib import Path

def test_parse_sample():
    sample = Path("sample_data/nmap_sample.xml")
    assert sample.exists(), "sample_data/nmap_sample.xml missing"
    parsed = parse_nmap_xml(str(sample))
    hosts = parsed.get("hosts", [])
    assert len(hosts) == 1
    h = hosts[0]
    assert h["ip"] == "10.0.0.5"
    port_nums = {p["port"] for p in h["ports"]}
    assert 22 in port_nums and 8080 in port_nums
