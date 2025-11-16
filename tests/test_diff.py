from src.analysis.diff import diff_scans

def test_diff_basic():
    old={"hosts":[{"ip":"1.1.1.1","ports":[{"port":22,"state":"open"}]}]}
    new={"hosts":[{"ip":"1.1.1.1","ports":[{"port":22,"state":"open"},{"port":80,"state":"open"}]}]}
    d = diff_scans(old,new)
    assert d["changes"][0]["added_ports"] == [80]
