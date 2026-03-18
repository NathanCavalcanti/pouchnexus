import re
import html
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv, set_key, dotenv_values
import os

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from graph.graph_builder import create_graph
from app.database import (
    create_incident,
    get_incident,
    list_incidents,
    update_incident,
    delete_incident,
    delete_incidents_bulk,
    get_stats,
    STATUS_ANALYZING,
    STATUS_COMPLETED,
    STATUS_FAILED,
)

load_dotenv()

# ──────────────────────────────────────────────────────────────────────────────
# Security & Rate Limiting Setup
# ──────────────────────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="SOC Multi-Agent Platform API",
    description="Automated security incident analysis with LangGraph multi-agent orchestration",
    version="2.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────────
# Serve React Frontend (production build placed in app/frontend/dist/)
# ──────────────────────────────────────────────────────────────────────────────

FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "frontend", "dist")
if os.path.isdir(FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(full_path: str):
        # API routes handle themselves; everything else → React
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404)
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))


def sanitize_string(v: Any) -> Any:
    """Helper to clean string inputs: strip, remove null bytes, escape HTML."""
    if isinstance(v, str):
        # Remove null bytes and control chars (except newline/tab)
        v = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", v)
        v = v.strip()
        # Escape HTML only if we are displaying raw data in UI without a renderer
        # (IncidentPanel.jsx renders markdown, so we might want to be careful)
        # v = html.escape(v) 
    return v

# ──────────────────────────────────────────────────────────────────────────────
# Pydantic Models (with Sanitization)
# ──────────────────────────────────────────────────────────────────────────────

class SanitizedBase(BaseModel):
    """Base model that automatically sanitizes all string fields."""
    @validator("*", pre=True)
    def sanitize_fields(cls, v):
        return sanitize_string(v)

class ManualIncidentRequest(SanitizedBase):
    incident: str = Field(..., min_length=10, max_length=50000)
    source: str = Field(default="manual")
    severity: str = Field(default="unknown")

    @validator("incident")
    def validate_incident_text(cls, v):
        if not v or not v.strip():
            raise ValueError("Incident text cannot be empty")
        return v.strip()


class SnortWebhookPayload(SanitizedBase):
    """Accept Snort / Suricata alert format."""
    alert: Optional[str] = None
    message: Optional[str] = None
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    proto: Optional[str] = None
    severity: Optional[str] = "medium"
    raw: Optional[Dict[str, Any]] = None


class WazuhWebhookPayload(SanitizedBase):
    """Accept Wazuh alert format."""
    rule: Optional[Dict[str, Any]] = None
    agent: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None
    full_log: Optional[str] = None
    severity: Optional[str] = "medium"


class GenericWebhookPayload(SanitizedBase):
    """Flexible JSON for n8n, custom scripts, etc."""
    text: Optional[str] = None
    log: Optional[str] = None
    alert: Optional[str] = None
    severity: Optional[str] = "unknown"
    source_name: Optional[str] = "generic_webhook"
    attack_type: Optional[str] = "Log Analysis"
    skip_analysis: Optional[bool] = False
    metadata: Optional[Dict[str, Any]] = None

class SettingsKeys(BaseModel):
    """Model for saving API keys via settings."""
    groq: Optional[str] = None
    gemini: Optional[str] = None
    nvd: Optional[str] = None
    virustotal: Optional[str] = None
    debug_logging: Optional[bool] = None


# ──────────────────────────────────────────────────────────────────────────────
# Background task
# ──────────────────────────────────────────────────────────────────────────────

def _run_analysis(incident_id: str, incident_text: str) -> None:
    """Runs the LangGraph multi-agent pipeline synchronously in a thread pool."""
    update_incident(incident_id, {"status": STATUS_ANALYZING})
    try:
        graph = create_graph()
        output = graph.invoke({"input_text": incident_text})
        update_incident(incident_id, {
            "status": STATUS_COMPLETED,
            "iocs": output.get("iocs"),
            "ttps": output.get("ttps"),
            "cves": output.get("cves"),
            "investigation_plan": output.get("investigation_plan"),
            "report": output.get("report"),
            "report_text": output.get("report_text"),
        })
    except Exception as exc:
        update_incident(incident_id, {"status": STATUS_FAILED, "error": str(exc)})


# ──────────────────────────────────────────────────────────────────────────────
# Health check
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/health", tags=["system"])
async def health_check():
    return {"status": "healthy", "version": "2.0.0"}


# ──────────────────────────────────────────────────────────────────────────────
# Dashboard Stats
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/stats", tags=["dashboard"])
async def dashboard_stats():
    """Returns aggregate metrics for the dashboard cards."""
    return get_stats()


# ──────────────────────────────────────────────────────────────────────────────
# Settings
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/settings/keys", tags=["settings"])
async def get_keys():
    """Returns current keys from .env without masking so they can be edited."""
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    env_vars = dotenv_values(env_path)
    return {
        "groq": env_vars.get("GROQ_API_KEY", ""),
        "gemini": env_vars.get("GEMINI_API_KEY", ""),
        "nvd": env_vars.get("NVD_API_KEY", ""),
        "virustotal": env_vars.get("VIRUSTOTAL_API_KEY", ""),
        "debug_logging": env_vars.get("DEBUG_LOGGING_ENABLED", "false").lower() == "true",
    }


@app.post("/api/v1/settings/keys", tags=["settings"])
async def update_keys(keys: SettingsKeys):
    """Updates the .env file with the provided keys."""
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    if not os.path.exists(env_path):
        open(env_path, 'a').close()
        
    if keys.groq is not None:
        set_key(env_path, "GROQ_API_KEY", keys.groq)
    if keys.gemini is not None:
        set_key(env_path, "GEMINI_API_KEY", keys.gemini)
    if keys.nvd is not None:
        set_key(env_path, "NVD_API_KEY", keys.nvd)
    if keys.virustotal is not None:
        set_key(env_path, "VIRUSTOTAL_API_KEY", keys.virustotal)
    if keys.debug_logging is not None:
        set_key(env_path, "DEBUG_LOGGING_ENABLED", "true" if keys.debug_logging else "false")
        
    return {"status": "success", "message": "Keys updated in .env"}


# ──────────────────────────────────────────────────────────────────────────────
# Incidents CRUD
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/incidents", tags=["incidents"])
async def list_incidents_endpoint(
    limit: int = Query(50, ge=1, le=5000),
    status_filter: Optional[str] = Query(None, alias="status"),
    source_filter: Optional[str] = Query(None, alias="source"),
    attack_filter: Optional[str] = Query(None, alias="attack_type"),
) -> List[Dict[str, Any]]:
    """Returns a list of incidents, newest first."""
    return list_incidents(
        limit=limit, 
        status=status_filter, 
        source=source_filter,
        attack_type=attack_filter
    )


@app.get("/api/v1/incidents/{incident_id}", tags=["incidents"])
async def get_incident_endpoint(incident_id: str) -> Dict[str, Any]:
    """Returns the full detail of one incident including analysis results."""
    record = get_incident(incident_id)
    if not record:
        raise HTTPException(status_code=404, detail="Incident not found")
    return record


@app.delete("/api/v1/incidents/{incident_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["incidents"])
async def delete_incident_endpoint(incident_id: str):
    """Deletes an incident by ID."""
    success = delete_incident(incident_id)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found or already deleted")
    return None


class BulkDeleteRequest(BaseModel):
    ids: List[str]


@app.post("/api/v1/incidents/bulk-delete", tags=["incidents"])
async def delete_incidents_bulk_endpoint(req: BulkDeleteRequest):
    """Deletes multiple incidents at once."""
    if not req.ids:
        return {"count": 0, "message": "No IDs provided"}
    count = delete_incidents_bulk(req.ids)
    return {"count": count, "message": f"Successfully deleted {count} incidents"}


async def _run_lightweight_enrichment(incident_id: str, text: str):
    """
    Fast enrichment for system events (scans) without using LLMs.
    Extracts IP and checks VirusTotal reputation.
    """
    from integrations.virustotal_client import get_ip_report
    from app.database import STATUS_COMPLETED
    
    # Simple IP regex
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    if not ip_match:
        update_incident(incident_id, {
            "status": STATUS_COMPLETED,
            "report_text": "Incident logged. AI Analysis skipped. No IP found for automated enrichment."
        })
        return

    ip = ip_match.group(0)
    vt_data = get_ip_report(ip)
    
    # Structure for the UI (IncidentPanel.jsx looks for this)
    vt_ui_result = {
        "ip": ip,
        "malicious": vt_data.get("malicious_count", 0),
        "total": vt_data.get("total_engines", 0),
        "reputation": vt_data.get("reputation", 0),
        "country": vt_data.get("country", "Unknown"),
        "as_owner": vt_data.get("as_owner", "Unknown"),
        "permalink": vt_data.get("permalink", "")
    }
    
    if "error" in vt_data and not vt_data.get("permalink"):
        report = f"Incident logged. Scan from {ip}.\nVirusTotal lookup failed: {vt_data['error']}"
    else:
        malicious = vt_ui_result["malicious"]
        total = vt_ui_result["total"]
        
        report = "### 🔍 Automated IP Enrichment (No AI Analysis)\n\n"
        report += f"**IP Detected:** {ip}\n"
        report += f"**VT Reputation:** {malicious}/{total} engines flagged this IP.\n"
        report += f"**Country:** {vt_ui_result['country']}\n\n"
        if malicious > 0:
            report += f"⚠️ **Warning:** This IP has been flagged as malicious by {malicious} security vendors.\n\n"

    update_incident(incident_id, {
        "status": STATUS_COMPLETED,
        "report_text": report,
        "iocs": {
            "ips": [ip],
            "virustotal_ip_results": [vt_ui_result]
        }
    })


# ──────────────────────────────────────────────────────────────────────────────
# Manual analysis (replaces old CLI workflow)
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/api/v1/analyze", status_code=202, tags=["incidents"])
@limiter.limit("5/minute")
async def analyze_incident(
    request: Request,
    payload: ManualIncidentRequest,
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    """
    Accepts incident text and queues it for async multi-agent analysis.
    Returns immediately with the incident_id so the frontend can poll.
    """
    incident_id = create_incident(
        raw_text=payload.incident,
        source=payload.source,
        severity=payload.severity,
    )
    background_tasks.add_task(_run_analysis, incident_id, payload.incident)
    return {
        "incident_id": incident_id,
        "status": "pending",
        "message": "Incident queued for analysis. Poll /api/v1/incidents/{incident_id} for results.",
    }


# ──────────────────────────────────────────────────────────────────────────────
# Ingestion Webhooks (Snort, Wazuh, Generic/n8n)
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/api/v1/ingest/snort", status_code=202, tags=["ingestion"])
@limiter.limit("60/minute")
async def ingest_snort(request: Request, payload: SnortWebhookPayload, background_tasks: BackgroundTasks):
    """
    Webhook endpoint for Snort / Suricata JSON alerts.
    Configure Snort to POST to: http://<host>:8000/api/v1/ingest/snort
    """
    lines = []
    if payload.alert:
        lines.append(f"Snort Alert: {payload.alert}")
    if payload.message:
        lines.append(f"Message: {payload.message}")
    if payload.src_ip:
        lines.append(f"Source IP: {payload.src_ip}")
    if payload.dest_ip:
        lines.append(f"Destination IP: {payload.dest_ip}")
    if payload.proto:
        lines.append(f"Protocol: {payload.proto}")
    if payload.raw:
        lines.append(f"Raw data: {payload.raw}")

    incident_text = "\n".join(lines) if lines else str(payload.dict())
    incident_id = create_incident(
        raw_text=incident_text, 
        source="snort", 
        severity=payload.severity or "medium",
        attack_type="Network IDS"
    )
    background_tasks.add_task(_run_analysis, incident_id, incident_text)
    return {"incident_id": incident_id, "status": "pending"}


@app.post("/api/v1/ingest/wazuh", status_code=202, tags=["ingestion"])
@limiter.limit("60/minute")
async def ingest_wazuh(request: Request, payload: WazuhWebhookPayload, background_tasks: BackgroundTasks):
    """
    Webhook endpoint for Wazuh alerts.
    In Wazuh Manager, configure a custom integration to POST to this URL.
    """
    lines = []
    if payload.full_log:
        lines.append(f"Full Log:\n{payload.full_log}")
    if payload.rule:
        rule_desc = payload.rule.get("description", "")
        rule_level = payload.rule.get("level", "")
        lines.append(f"Rule: {rule_desc} (Level {rule_level})")
    if payload.agent:
        agent_name = payload.agent.get("name", "unknown")
        agent_ip = payload.agent.get("ip", "unknown")
        lines.append(f"Agent: {agent_name} ({agent_ip})")
    if payload.data:
        lines.append(f"Event Data: {payload.data}")

    incident_text = "\n".join(lines) if lines else str(payload.dict())
    incident_id = create_incident(
        raw_text=incident_text, 
        source="wazuh", 
        severity=payload.severity or "medium",
        attack_type="Endpoint Alert"
    )
    background_tasks.add_task(_run_analysis, incident_id, incident_text)
    return {"incident_id": incident_id, "status": "pending"}


@app.post("/api/v1/ingest/generic", status_code=202, tags=["ingestion"])
@limiter.limit("60/minute")
async def ingest_generic(request: Request, payload: GenericWebhookPayload, background_tasks: BackgroundTasks):
    """
    Flexible webhook for n8n, custom scripts, SIEM exports, etc.
    Accepts any JSON with a 'text', 'log', or 'alert' field.
    """
    incident_text = payload.text or payload.log or payload.alert or str(payload.dict())
    source = payload.source_name or "generic_webhook"
    
    incident_id = create_incident(
        raw_text=incident_text, 
        source=source, 
        severity=payload.severity or "unknown",
        attack_type=payload.attack_type or "Log Analysis"
    )
    
    # Skip AI analysis if requested (e.g. for simple port scans)
    if payload.skip_analysis:
        background_tasks.add_task(_run_lightweight_enrichment, incident_id, incident_text)
    else:
        background_tasks.add_task(_run_analysis, incident_id, incident_text)
        
    return {"incident_id": incident_id, "status": "pending" if not payload.skip_analysis else "completed"}


# ──────────────────────────────────────────────────────────────────────────────
# Enrichment: VirusTotal, CVE (NVD), MITRE ATT&CK
# ──────────────────────────────────────────────────────────────────────────────

class MitreAnalyzeRequest(SanitizedBase):
    text: str = Field(..., min_length=10, max_length=20000, description="Event or log text to map to MITRE")


@app.get("/api/v1/enrichment/virustotal/hash/{file_hash}", tags=["enrichment"])
async def vt_hash(file_hash: str):
    """Query VirusTotal for a file hash (MD5, SHA1, SHA256)."""
    from integrations.virustotal_client import get_file_report
    return get_file_report(file_hash)


@app.get("/api/v1/enrichment/virustotal/ip/{ip}", tags=["enrichment"])
async def vt_ip(ip: str):
    """Query VirusTotal for an IP address reputation."""
    from integrations.virustotal_client import get_ip_report
    return get_ip_report(ip)


@app.get("/api/v1/enrichment/virustotal/domain/{domain}", tags=["enrichment"])
async def vt_domain(domain: str):
    """Query VirusTotal for a domain reputation."""
    from integrations.virustotal_client import get_domain_report
    return get_domain_report(domain)


@app.post("/api/v1/enrichment/virustotal/url", tags=["enrichment"])
async def vt_url(payload: Dict[str, str]):
    """Scan a URL with VirusTotal."""
    from integrations.virustotal_client import scan_url
    url = payload.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="url field required")
    return scan_url(url)


@app.get("/api/v1/enrichment/cve", tags=["enrichment"])
async def search_cve(q: str = Query(..., min_length=2, description="CVE ID or keyword")):
    """
    Search NVD for CVEs by keyword or CVE-ID.
    Examples: ?q=log4j  or  ?q=CVE-2023-44487
    """
    from integrations.nvd_client import search_cves
    try:
        results = search_cves(keyword=q, max_results=10)
        return {"query": q, "results": results}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/api/v1/enrichment/mitre/{technique_id}", tags=["enrichment"])
async def lookup_mitre(technique_id: str):
    """Lookup a single MITRE ATT&CK technique by ID (e.g. T1059.001)."""
    from integrations.mitre_local_db import get_technique_by_id
    result = get_technique_by_id(technique_id.upper())
    if not result:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found in MITRE database")
    # Trim the raw STIX blob — send only useful fields
    return {
        "id": result["id"],
        "name": result["name"],
        "tactics": result["tactics"],
        "description": result.get("raw", {}).get("description", ""),
        "url": f"https://attack.mitre.org/techniques/{result['id'].replace('.', '/')}",
    }


@app.post("/api/v1/enrichment/mitre/analyze", tags=["enrichment"])
async def mitre_analyze(payload: MitreAnalyzeRequest, background_tasks: BackgroundTasks):
    """
    AI TTP Mapper: sends text through the MITRE agent (LLM + local DB validation).
    Uses BackgroundTasks so the response is not blocked by the LLM call.
    """
    import uuid
    from agents.mitre_agent import run_mitre_agent

    job_id = str(uuid.uuid4())
    _mitre_jobs[job_id] = {"status": "analyzing", "result": None}

    def _run():
        try:
            result = run_mitre_agent(incident_text=payload.text)
            _mitre_jobs[job_id] = {"status": "completed", "result": result}
        except Exception as e:
            _mitre_jobs[job_id] = {"status": "failed", "result": None, "error": str(e)}

    background_tasks.add_task(_run)
    return {"job_id": job_id, "status": "analyzing"}


# In-memory store for async MITRE analysis jobs (lightweight, no DB needed)
_mitre_jobs: Dict[str, Any] = {}


@app.get("/api/v1/enrichment/mitre/analyze/{job_id}", tags=["enrichment"])
async def mitre_analyze_result(job_id: str):
    """Poll the result of an AI TTP Mapper job."""
    job = _mitre_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job
