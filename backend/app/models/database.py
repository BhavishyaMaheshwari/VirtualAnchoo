"""SQLite metadata and historical capture sessions, serialized through one lock.

PCAP files remain on disk; packet payloads are never duplicated into SQLite.
"""
from __future__ import annotations
import json
from pathlib import Path
import sqlite3
import threading
import time
import uuid

class Database:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.pcap_dir = self.data_dir / "captures"
        self.pcap_dir.mkdir(exist_ok=True)
        self.lock = threading.RLock()
        db_path = self.data_dir / "virtualanchoo.sqlite3"
        legacy_path = self.data_dir / "netscope.sqlite3"
        if legacy_path.exists() and not db_path.exists():
            db_path = legacy_path
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript('''
        CREATE TABLE IF NOT EXISTS sessions (
          id TEXT PRIMARY KEY, source TEXT NOT NULL, name TEXT NOT NULL,
          interface TEXT NOT NULL, bpf_filter TEXT NOT NULL DEFAULT '',
          started_at REAL NOT NULL, ended_at REAL, status TEXT NOT NULL,
          packet_count INTEGER NOT NULL DEFAULT 0, byte_count INTEGER NOT NULL DEFAULT 0,
          error TEXT, pcap_path TEXT NOT NULL, stats TEXT
        );
        CREATE TABLE IF NOT EXISTS packets (
          id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
          timestamp REAL NOT NULL, protocol TEXT, src_ip TEXT, dst_ip TEXT,
          src_port INTEGER, dst_port INTEGER, vlan_id INTEGER, length INTEGER,
          metadata TEXT NOT NULL, FOREIGN KEY(session_id) REFERENCES sessions(id)
        );
        CREATE INDEX IF NOT EXISTS packet_session ON packets(session_id, id);
        CREATE INDEX IF NOT EXISTS packet_time ON packets(session_id, timestamp);
        CREATE INDEX IF NOT EXISTS packet_protocol ON packets(session_id, protocol);
        ''')
        self.conn.execute("UPDATE sessions SET status='interrupted', ended_at=?, error='Service restarted before this session completed' WHERE status IN ('running','importing')", (time.time(),))
        self.conn.commit()

    def create_session(self, source, name, interface, bpf_filter=""):
        sid = str(uuid.uuid4())
        path = self.pcap_dir / f"{sid}.pcap"
        with self.lock:
            self.conn.execute("INSERT INTO sessions (id,source,name,interface,bpf_filter,started_at,status,pcap_path) VALUES(?,?,?,?,?,?,?,?)", (sid,source,name,interface,bpf_filter,time.time(),"running" if source == "live" else "importing",str(path)))
            self.conn.commit()
        return self.session(sid)

    def session(self, sid=None):
        with self.lock:
            row = self.conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone() if sid else self.conn.execute("SELECT * FROM sessions ORDER BY started_at DESC LIMIT 1").fetchone()
            if not row:
                return None
            result = dict(row)
            result.pop("stats", None)
            return result

    def sessions(self):
        with self.lock:
            return [dict(row) for row in self.conn.execute("SELECT id,source,name,interface,bpf_filter,started_at,ended_at,status,packet_count,byte_count,error FROM sessions ORDER BY started_at DESC LIMIT 100")]

    def insert_packet(self, sid, packet):
        meta = dict(packet)
        with self.lock:
            cursor = self.conn.execute("INSERT INTO packets(session_id,timestamp,protocol,src_ip,dst_ip,src_port,dst_port,vlan_id,length,metadata) VALUES(?,?,?,?,?,?,?,?,?,?)", (sid, meta["timestamp"],meta.get("protocol"),meta.get("src_ip"),meta.get("dst_ip"),meta.get("src_port"),meta.get("dst_port"),meta.get("vlan_id"),meta["length"],json.dumps(meta)))
            self.conn.execute("UPDATE sessions SET packet_count=packet_count+1,byte_count=byte_count+? WHERE id=?",(meta["length"],sid))
            self.conn.commit()
            meta["id"] = cursor.lastrowid
            meta["session_id"] = sid
        return meta

    def finish_session(self, sid, status="completed", error=None, stats=None):
        with self.lock:
            self.conn.execute("UPDATE sessions SET status=?,ended_at=?,error=?,stats=? WHERE id=?", (status,time.time(),error,json.dumps(stats) if stats else None,sid))
            self.conn.commit()

    def _where(self, sid, filters):
        where, values = ["session_id=?"], [sid]
        for key in ("protocol","src_ip","dst_ip","src_port","dst_port","vlan_id"):
            if filters.get(key) is not None and filters[key] != "":
                where.append(f"{key}=?")
                values.append(filters[key])
        for key, column, op in (("min_size","length",">="),("max_size","length","<="),("start_time","timestamp",">="),("end_time","timestamp","<=")):
            if filters.get(key) is not None:
                where.append(f"{column}{op}?")
                values.append(filters[key])
        if filters.get("search"):
            where.append("(src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ? OR metadata LIKE ?)")
            values.extend(["%"+filters["search"]+"%"]*4)
        return " AND ".join(where), values

    @staticmethod
    def _packet(row):
        result = json.loads(row["metadata"])
        result.update(id=row["id"],session_id=row["session_id"])
        return result

    def packets(self, sid, page=1, page_size=100, **filters):
        if not sid:
            return {"items":[],"total":0,"page":page,"page_size":page_size}
        where, values = self._where(sid,filters)
        with self.lock:
            total = self.conn.execute(f"SELECT COUNT(*) FROM packets WHERE {where}", values).fetchone()[0]
            rows = self.conn.execute(f"SELECT id,session_id,metadata FROM packets WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?", values+[page_size,(page-1)*page_size]).fetchall()
        return {"items":[self._packet(r) for r in rows],"total":total,"page":page,"page_size":page_size}

    def packet(self, pid):
        with self.lock:
            row = self.conn.execute("SELECT id,session_id,metadata FROM packets WHERE id=?",(pid,)).fetchone()
        return self._packet(row) if row else None

    def all_packets(self, sid):
        if not sid:
            return []
        with self.lock:
            rows = self.conn.execute("SELECT id,session_id,metadata FROM packets WHERE session_id=? ORDER BY id",(sid,)).fetchall()
        return [self._packet(row) for row in rows]

    def save_stats(self, sid, stats):
        with self.lock:
            self.conn.execute("UPDATE sessions SET stats=? WHERE id=?", (json.dumps(stats),sid))
            self.conn.commit()

    def delete_session(self, sid):
        session = self.session(sid)
        if not session:
            return False
        with self.lock:
            self.conn.execute("DELETE FROM packets WHERE session_id=?",(sid,))
            self.conn.execute("DELETE FROM sessions WHERE id=?",(sid,))
            self.conn.commit()
        Path(session["pcap_path"]).unlink(missing_ok=True)
        return True

    def close(self):
        with self.lock:
            self.conn.close()
