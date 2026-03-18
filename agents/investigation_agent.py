# agents/investigation_agent.py
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from app.config import call_llm, extract_json_block, GROQ_MODEL_ANALYSIS


def run_investigation_agent(
    event_text: Optional[str] = None,
    incident_text: Optional[str] = None,
    iocs: Optional[Dict[str, Any]] = None,
    ttps: Optional[Dict[str, Any]] = None,
    cves: Optional[Dict[str, Any]] = None,
    mitre_context: Optional[Dict[str, Any]] = None,
    cve_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Agent 4: DFIR Planner / Investigation Agent

    Flexible signature to adapt to graph calls:

    - Some graphs pass `event_text=...`
    - Others might pass `incident_text=...`
    - MITRE can arrive as `ttps` or `mitre_context`
    - CVEs can arrive as `cves` or `cve_context`

    Returns a dict with an investigation and containment plan.
    """

    # Unify parameter names
    text = incident_text or event_text or ""
    mitre_data: Optional[Dict[str, Any]] = mitre_context or ttps
    cve_data: Optional[Dict[str, Any]] = cve_context or cves

    ioc_snippet = json.dumps(iocs, ensure_ascii=False) if iocs else "{}"
    mitre_snippet = json.dumps(mitre_data, ensure_ascii=False) if mitre_data else "{}"
    cve_snippet = json.dumps(cve_data, ensure_ascii=False) if cve_data else "{}"

    system_prompt = (
        "You are a Senior DFIR Analyst in a SOC. "
        "Based on the incident/event description, IOCs, MITRE mapping, "
        "and vulnerabilities (CVEs), you must propose a structured investigation "
        "and response plan, oriented towards L1/L2 analysts."
    )

    user_prompt = f"""
Incident / Event description:
{text}

Extracted IOCs:
{ioc_snippet}

MITRE Context (TTPs):
{mitre_snippet}

CVE Context:
{cve_snippet}

Return ONLY a valid JSON with the following structure:

{{
  "investigation_steps": [
    {{
      "step": 1,
      "category": "Artifact Collection",
      "description": "Detailed action description.",
      "tools": ["Splunk", "EDR", "Volatility"],
      "expected_outcome": "What is expected to be found."
    }}
  ],
  "containment_actions": [
    {{
      "priority": "high",
      "description": "Containment action.",
      "depends_on": [1]
    }}
  ],
  "eradication_and_recovery": [
    "Eradication action 1",
    "Recovery action 1"
  ],
  "notes": "Additional notes (e.g., communication, reporting, etc.)."
}}
"""

    response = call_llm(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        provider="groq",
        model=GROQ_MODEL_ANALYSIS,  # Analysis model for complex reasoning
    )

    try:
        json_str = extract_json_block(response)
        parsed = json.loads(json_str)
    except json.JSONDecodeError:
        parsed = {
            "parse_error": "LLM did not return valid JSON",
            "raw_response": response,
        }

    return parsed
