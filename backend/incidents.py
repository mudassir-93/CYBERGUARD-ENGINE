"""Local-first incident management and SQLite persistence for CyberGuard."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

INCIDENT_TYPES = {
    "port_scan": ("Port scan activity", "medium", 55),
    "brute_force": ("Repeated connection failures", "high", 75),
    "dos": ("High-volume traffic pattern", "critical", 90),
    "lateral_movement": ("Suspicious internal host fan-out", "high", 70),
}
STATUSES = {"new", "acknowledged", "investigating", "resolved", "false_positive"}
ACTIVE_STATUSES = {"new", "acknowledged", "investigating"}
TRANSITIONS = {
    "new": {"acknowledged", "investigating", "resolved", "false_positive"},
    "acknowledged": {"investigating", "resolved", "false_positive"},
    "investigating": {"acknowledged", "resolved", "false_positive"},
    "resolved": {"new"},
    "false_positive": {"new"},
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _timestamp(value: Any) -> str:
    if value is None:
        return utc_now()
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("observed_at must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("observed_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")


def _ip(value: Any, field: str, optional: bool = False) -> str | None:
    if value in (None, "") and optional:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a valid IP address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid IP address") from exc


def normalize_detection(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Detection payload must be a JSON object")
    kind = payload.get("type")
    if kind not in INCIDENT_TYPES:
        raise ValueError("type must be one of: " + ", ".join(INCIDENT_TYPES))
    source = _ip(payload.get("source_ip"), "source_ip")
    destination = _ip(payload.get("destination_ip"), "destination_ip", optional=True)
    title, severity, score = INCIDENT_TYPES[kind]
    port = payload.get("destination_port")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535):
        raise ValueError("destination_port must be an integer from 1 to 65535")
    protocol = payload.get("protocol", "TCP")
    if not isinstance(protocol, str) or protocol.upper() not in {"TCP", "UDP", "ICMP", "OTHER"}:
        raise ValueError("protocol must be TCP, UDP, ICMP, or OTHER")
    evidence = payload.get("evidence", {})
    if not isinstance(evidence, dict) or len(json.dumps(evidence, ensure_ascii=False)) > 16000:
        raise ValueError("evidence must be a JSON object no larger than 16 KB")
    summary = payload.get("summary", title)
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 500:
        raise ValueError("summary must contain 1-500 characters")
    return {
        "type": kind, "title": title, "summary": summary.strip(),
        "severity": severity, "risk_score": score,
        "source_ip": source, "destination_ip": destination,
        "destination_port": port, "protocol": protocol.upper(),
        "observed_at": _timestamp(payload.get("observed_at")),
        "evidence": evidence,
    }


class IncidentStore:
    """SQLite-backed incident repository; each operation owns its connection."""

    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _session(self):
        db = self._connect()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _initialize(self) -> None:
        with self._session() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, type TEXT NOT NULL,
                    title TEXT NOT NULL, summary TEXT NOT NULL, severity TEXT NOT NULL,
                    risk_score INTEGER NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
                    status TEXT NOT NULL, source_ip TEXT NOT NULL, destination_ip TEXT,
                    destination_port INTEGER, protocol TEXT NOT NULL, first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    occurrence_count INTEGER NOT NULL DEFAULT 1, evidence_json TEXT NOT NULL,
                    resolution_note TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_status_updated ON incidents(status, updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint ON incidents(fingerprint, status);
                CREATE TABLE IF NOT EXISTS incident_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id, id);
            """)

    @staticmethod
    def _fingerprint(item: dict[str, Any]) -> str:
        identity = "|".join(str(item.get(key) or "") for key in (
            "type", "source_ip", "destination_ip", "destination_port", "protocol"
        ))
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["evidence"] = json.loads(result.pop("evidence_json"))
        return result

    def ingest(self, payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        item = normalize_detection(payload)
        fingerprint, now = self._fingerprint(item), utc_now()
        observation = {"observed_at": item["observed_at"], **item["evidence"]}
        with self._session() as db:
            existing = db.execute(
                "SELECT * FROM incidents WHERE fingerprint=? AND status IN ('new','acknowledged','investigating') ORDER BY created_at DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if existing:
                evidence = json.loads(existing["evidence_json"])
                observations = evidence.setdefault("observations", [])
                observations.append(observation)
                evidence["observations"] = observations[-100:]
                db.execute("""
                    UPDATE incidents SET last_seen=MAX(last_seen, ?), updated_at=?,
                    occurrence_count=occurrence_count+1, risk_score=MAX(risk_score, ?),
                    evidence_json=? WHERE id=?
                """, (item["observed_at"], now, item["risk_score"],
                      json.dumps(evidence, ensure_ascii=False), existing["id"]))
                db.execute(
                    "INSERT INTO incident_events(incident_id,event_type,message,created_at,metadata_json) VALUES(?,?,?,?,?)",
                    (existing["id"], "correlated_detection", "A matching detection was correlated with this incident", now,
                     json.dumps({"type": item["type"], "observed_at": item["observed_at"]})),
                )
                row = db.execute("SELECT * FROM incidents WHERE id=?", (existing["id"],)).fetchone()
                return self._row(row), True

            incident_id = "CG-" + uuid.uuid4().hex[:12].upper()
            evidence = {"observations": [observation]}
            db.execute("""
                INSERT INTO incidents(id,fingerprint,type,title,summary,severity,risk_score,status,
                    source_ip,destination_ip,destination_port,protocol,first_seen,last_seen,
                    created_at,updated_at,occurrence_count,evidence_json)
                VALUES(?,?,?,?,?,?,?,'new',?,?,?,?,?,?,?,?,1,?)
            """, (incident_id, fingerprint, item["type"], item["title"], item["summary"],
                  item["severity"], item["risk_score"], item["source_ip"], item["destination_ip"],
                  item["destination_port"], item["protocol"], item["observed_at"], item["observed_at"],
                  now, now, json.dumps(evidence, ensure_ascii=False)))
            db.execute(
                "INSERT INTO incident_events(incident_id,event_type,message,created_at,metadata_json) VALUES(?,?,?,?,?)",
                (incident_id, "created", "Incident created from a detection", now,
                 json.dumps({"type": item["type"], "severity": item["severity"]})),
            )
            row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            return self._row(row), False

    def list_incidents(self, status: str | None = None, severity: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if status and status not in STATUSES:
            raise ValueError("Invalid incident status")
        if severity and severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("Invalid severity")
        limit = max(1, min(int(limit), 200))
        clauses, values = [], []
        if status:
            clauses.append("status=?"); values.append(status)
        if severity:
            clauses.append("severity=?"); values.append(severity)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._session() as db:
            rows = db.execute(
                "SELECT * FROM incidents" + where +
                " ORDER BY CASE status WHEN 'new' THEN 0 WHEN 'acknowledged' THEN 1 WHEN 'investigating' THEN 2 ELSE 3 END, risk_score DESC, updated_at DESC LIMIT ?",
                (*values, limit),
            ).fetchall()
            return [self._row(row) for row in rows]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._session() as db:
            row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if row is None:
                return None
            incident = self._row(row)
            incident["timeline"] = [dict(event) for event in db.execute(
                "SELECT event_type,message,created_at,metadata_json FROM incident_events WHERE incident_id=? ORDER BY id",
                (incident_id,),
            ).fetchall()]
            for event in incident["timeline"]:
                event["metadata"] = json.loads(event.pop("metadata_json"))
            return incident

    def update_status(self, incident_id: str, status: str, note: str | None = None) -> dict[str, Any] | None:
        if status not in STATUSES:
            raise ValueError("Invalid incident status")
        if note is not None and (not isinstance(note, str) or len(note) > 1000):
            raise ValueError("resolution_note must be no longer than 1000 characters")
        now = utc_now()
        with self._session() as db:
            row = db.execute("SELECT status FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if row is None:
                return None
            previous = row["status"]
            if status != previous and status not in TRANSITIONS[previous]:
                raise ValueError(f"Cannot move incident from {previous} to {status}")
            db.execute(
                "UPDATE incidents SET status=?,updated_at=?,resolution_note=? WHERE id=?",
                (status, now, note if status in {"resolved", "false_positive"} else None, incident_id),
            )
            db.execute(
                "INSERT INTO incident_events(incident_id,event_type,message,created_at,metadata_json) VALUES(?,?,?,?,?)",
                (incident_id, "status_changed", f"Status changed from {previous} to {status}", now,
                 json.dumps({"from": previous, "to": status, "note": note})),
            )
            return self._row(db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone())

    def summary(self) -> dict[str, Any]:
        with self._session() as db:
            rows = db.execute("SELECT status,severity,COUNT(*) AS total FROM incidents GROUP BY status,severity").fetchall()
        result = {"total": 0, "open": 0, "critical": 0, "high": 0, "by_status": {s: 0 for s in STATUSES}}
        for row in rows:
            count = row["total"]
            result["total"] += count
            result["by_status"][row["status"]] += count
            if row["status"] in ACTIVE_STATUSES:
                result["open"] += count
                if row["severity"] == "critical": result["critical"] += count
                if row["severity"] == "high": result["high"] += count
        return result


def default_store() -> IncidentStore:
    directory = Path(os.environ.get("CYBERGUARD_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
    return IncidentStore(directory / "incidents.sqlite3")
