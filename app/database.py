# app/database.py
"""
Lightweight persistence layer for the SOC Multi-Agent platform.
Uses TinyDB to store incident records and analysis results.
No external DB server required - just a local JSON file.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage

# ── Database path ────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "incidents.json")

# ── Status constants ─────────────────────────────────────────────────────────
STATUS_PENDING = "pending"
STATUS_ANALYZING = "analyzing"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

# ── DB instance (lazy-loaded singleton) ─────────────────────────────────────
_db: Optional[TinyDB] = None


def get_db() -> TinyDB:
    global _db
    if _db is None:
        # We use direct JSONStorage instead of CachingMiddleware to ensure
        # that every write (insert/update) is immediately flushed to disk.
        # This prevents data loss during server reloads or forced shutdowns.
        _db = TinyDB(DB_PATH, storage=JSONStorage)
    return _db


def get_incidents_table():
    return get_db().table("incidents")


# ── CRUD helpers ─────────────────────────────────────────────────────────────


def create_incident(
    raw_text: str,
    source: str = "manual",
    severity: str = "unknown",
    attack_type: str = "Log Analysis",
) -> str:
    """Creates a new incident record. Returns the incident ID."""
    incident_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    record = {
        "id": incident_id,
        "source": source,  # "manual" | "webhook_snort" | "webhook_wazuh" | "n8n" …
        "severity": severity,  # "critical" | "high" | "medium" | "low" | "unknown"
        "attack_type": attack_type,  # e.g., "Log Analysis", "Phishing", "Malware"
        "status": STATUS_PENDING,
        "created_at": now,
        "updated_at": now,
        "raw_text": raw_text,
        "iocs": None,
        "ttps": None,
        "cves": None,
        "investigation_plan": None,
        "report": None,
        "report_text": None,
        "error": None,
    }

    get_incidents_table().insert(record)
    return incident_id


def update_incident(incident_id: str, updates: Dict[str, Any]) -> bool:
    """Updates fields of an existing incident."""
    Incident = Query()
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    result = get_incidents_table().update(updates, Incident.id == incident_id)
    return len(result) > 0


def get_incident(incident_id: str) -> Optional[Dict[str, Any]]:
    """Returns a single incident by ID or None."""
    Incident = Query()
    results = get_incidents_table().search(Incident.id == incident_id)
    return results[0] if results else None


def delete_incident(incident_id: str) -> bool:
    """Deletes an incident by ID. Returns True if deleted."""
    Incident = Query()
    removed = get_incidents_table().remove(Incident.id == incident_id)
    return len(removed) > 0


def delete_incidents_bulk(incident_ids: List[str]) -> int:
    """Deletes multiple incidents. Returns count of removed items."""
    Incident = Query()
    removed = get_incidents_table().remove(Incident.id.one_of(incident_ids))
    return len(removed)


def list_incidents(
    limit: int = 50,
    status: Optional[str] = None,
    source: Optional[str] = None,
    attack_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Returns incidents ordered by newest first with optional filters."""
    table = get_incidents_table()
    Incident = Query()

    # Dynamic query building
    query = None
    if status:
        query = Incident.status == status
    if source:
        q_source = Incident.source == source
        query = (query & q_source) if query else q_source
    if attack_type:
        q_attack = Incident.attack_type == attack_type
        query = (query & q_attack) if query else q_attack

    if query:
        records = table.search(query)
    else:
        records = table.all()

    # Sort newest first
    records.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return records[:limit]


def get_stats() -> Dict[str, Any]:
    """Returns summary statistics for the dashboard."""
    all_records = get_incidents_table().all()
    total = len(all_records)
    by_status = {
        STATUS_PENDING: 0,
        STATUS_ANALYZING: 0,
        STATUS_COMPLETED: 0,
        STATUS_FAILED: 0,
    }
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    by_source: Dict[str, int] = {}

    for rec in all_records:
        s = rec.get("status", STATUS_PENDING)
        if s in by_status:
            by_status[s] += 1

        sev = rec.get("severity", "unknown")
        if sev in by_severity:
            by_severity[sev] += 1

        src = rec.get("source", "manual")
        by_source[src] = by_source.get(src, 0) + 1

    return {
        "total": total,
        "by_status": by_status,
        "by_severity": by_severity,
        "by_source": by_source,
    }
