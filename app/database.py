# app/database.py
"""
Persistence layer for the SOC Multi-Agent platform.
Uses Supabase (PostgreSQL) for cloud-hosted, scalable storage.

Setup:
  1. Create a Supabase project at https://supabase.com
  2. Run migrations/supabase/001_create_incidents.sql in the SQL Editor
  3. Set SUPABASE_URL and SUPABASE_KEY in your .env file
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from supabase import create_client, Client

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

# ── Status constants ─────────────────────────────────────────────────────────
STATUS_PENDING = "pending"
STATUS_ANALYZING = "analyzing"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

_TABLE = "incidents"

# ── Supabase client (lazy singleton) ─────────────────────────────────────────
_supabase: Optional[Client] = None

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "SUPABASE_URL and SUPABASE_KEY are required. "
        "Add them to your .env file. "
        "Get them from: Supabase Dashboard → Project Settings → API"
    )


def get_client() -> Client:
    global _supabase
    if _supabase is None:
        _supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _supabase


def _serialize_jsonb(value: Any) -> Any:
    """Ensure JSONB columns receive a dict/list or None, never raw strings."""
    if value is None or isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return {"raw": value}
    return value


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
        "source": source,
        "severity": severity,
        "attack_type": attack_type,
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

    get_client().table(_TABLE).insert(record).execute()
    return incident_id


def update_incident(incident_id: str, updates: Dict[str, Any]) -> bool:
    """Updates fields of an existing incident."""
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    for jsonb_col in ("iocs", "ttps", "cves", "report"):
        if jsonb_col in updates:
            updates[jsonb_col] = _serialize_jsonb(updates[jsonb_col])
    response = (
        get_client().table(_TABLE).update(updates).eq("id", incident_id).execute()
    )
    return len(response.data) > 0


def get_incident(incident_id: str) -> Optional[Dict[str, Any]]:
    """Returns a single incident by ID or None."""
    response = (
        get_client().table(_TABLE).select("*").eq("id", incident_id).execute()
    )
    return response.data[0] if response.data else None


def delete_incident(incident_id: str) -> bool:
    """Deletes an incident by ID. Returns True if deleted."""
    response = (
        get_client().table(_TABLE).delete().eq("id", incident_id).execute()
    )
    return len(response.data) > 0


def delete_incidents_bulk(incident_ids: List[str]) -> int:
    """Deletes multiple incidents. Returns count of removed items."""
    response = (
        get_client().table(_TABLE).delete().in_("id", incident_ids).execute()
    )
    return len(response.data)


def list_incidents(
    limit: int = 50,
    status: Optional[str] = None,
    source: Optional[str] = None,
    attack_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Returns incidents ordered by newest first with optional filters."""
    query = (
        get_client()
        .table(_TABLE)
        .select("*")
        .order("created_at", desc=True)
        .limit(limit)
    )
    if status:
        query = query.eq("status", status)
    if source:
        query = query.eq("source", source)
    if attack_type:
        query = query.eq("attack_type", attack_type)
    response = query.execute()
    return response.data or []


def get_stats() -> Dict[str, Any]:
    """Returns summary statistics for the dashboard."""
    response = (
        get_client()
        .table(_TABLE)
        .select("status, severity, source")
        .execute()
    )
    all_records = response.data or []
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
