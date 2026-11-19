"""Persistent desired configurations and actual connectivity observations."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sqlite3
import threading
from contextlib import contextmanager
from .schema import DEFAULT_VLANS, validate_vlan

_LOCK = threading.RLock()

@contextmanager
def connect():
    path = Path(os.getenv("NETSCOPE_NETWORK_DB", str(Path(__file__).resolve().parents[1] / "data" / "network.sqlite3")))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
      CREATE TABLE IF NOT EXISTS vlan_config (id INTEGER PRIMARY KEY, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS firewall_rules (id TEXT PRIMARY KEY, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS connectivity_tests (id TEXT PRIMARY KEY, data TEXT NOT NULL, created REAL NOT NULL DEFAULT (unixepoch()));
    """)
    for v in DEFAULT_VLANS:
        conn.execute("INSERT OR IGNORE INTO vlan_config(id,data) VALUES(?,?)", (v["id"], json.dumps(validate_vlan(v))))
    conn.commit()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def get_vlans() -> list[dict]:
    with _LOCK, connect() as conn:
        return [json.loads(row[0]) for row in conn.execute("SELECT data FROM vlan_config ORDER BY id")]


def get_rules() -> list[dict]:
    with _LOCK, connect() as conn:
        return [json.loads(row[0]) for row in conn.execute("SELECT data FROM firewall_rules ORDER BY rowid")]


def save_vlan(vlan: dict) -> None:
    with _LOCK, connect() as conn:
        conn.execute("INSERT INTO vlan_config(id,data) VALUES(?,?)", (vlan["id"], json.dumps(vlan)))


def save_rules(rules: list[dict]) -> None:
    with _LOCK, connect() as conn:
        conn.execute("DELETE FROM firewall_rules")
        conn.executemany("INSERT INTO firewall_rules(id,data) VALUES(?,?)", [(r["id"], json.dumps(r)) for r in rules])


def save_test(result: dict) -> None:
    with _LOCK, connect() as conn:
        conn.execute("INSERT INTO connectivity_tests(id,data) VALUES(?,?)", (result["id"], json.dumps(result)))
        conn.execute("DELETE FROM connectivity_tests WHERE id NOT IN (SELECT id FROM connectivity_tests ORDER BY created DESC,rowid DESC LIMIT 1000)")


def get_tests() -> list[dict]:
    with _LOCK, connect() as conn:
        return [json.loads(row[0]) for row in conn.execute("SELECT data FROM connectivity_tests ORDER BY created DESC,rowid DESC LIMIT 100")]
