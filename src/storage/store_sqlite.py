import sqlite3
from pathlib import Path
from typing import Dict

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT,
  target TEXT,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  ip TEXT,
  hostname TEXT,
  status TEXT,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS ports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER,
  port INTEGER,
  protocol TEXT,
  state TEXT,
  service TEXT,
  banner TEXT,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_ports_host_port ON ports(host_id, port);
"""

def init_db(db_path: str):
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn

def store_scan_to_sqlite(db_path: str, parsed: Dict):
    conn = init_db(db_path)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (scan_id, target, created_at) VALUES (?, ?, datetime('now'))",
        (parsed.get("scan_id",""), parsed.get("target",""))
    )
    scan_row_id = cur.lastrowid

    for h in parsed.get("hosts", []):
        cur.execute(
            "INSERT INTO hosts (scan_id, ip, hostname, status) VALUES (?,?,?,?)",
            (scan_row_id, h.get("ip"), h.get("hostname"), h.get("status"))
        )
        host_id = cur.lastrowid
        for p in h.get("ports", []):
            cur.execute(
                "INSERT INTO ports (host_id, port, protocol, state, service, banner) VALUES (?,?,?,?,?,?)",
                (host_id, p.get("port"), p.get("protocol"), p.get("state"), p.get("service"), p.get("banner"))
            )
    conn.commit()
    conn.close()
