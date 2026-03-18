# agents/cve_agent.py
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from app.config import call_llm, extract_json_block
from integrations.nvd_client import search_cves


def _build_cve_keywords_with_llm(
    software_info: str,
    mitre_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Uses the LLM to extract product/technology keywords and time range
    from the incident text and MITRE context.

    Example output:
    {
      "keywords": ["Microsoft Office", "Windows 10"],
      "pub_start_date": "2020-01-01T00:00:00.000",
      "pub_end_date": "2024-12-31T23:59:59.999"
    }
    """

    mitre_snippet = ""
    if mitre_context:
        try:
            mitre_snippet = json.dumps(mitre_context, ensure_ascii=False)
        except TypeError:
            mitre_snippet = str(mitre_context)

    system_prompt = (
        "You are a vulnerability analyst. "
        "Based on an incident description and MITRE context, "
        "you must extract relevant product/technology names AND a reasonable time range to search for CVEs in NVD. "
        "CRITICAL: Only suggest CVEs from the last 10 years unless there is EXPLICIT evidence of older software. "
        "If the incident mentions specific software versions or years, use those to determine the date range. "
        "Do not invent versions if they are not clear; focus on product and vendor."
    )

    user_prompt = f"""
Incident text / affected software:
{software_info}

MITRE Context (JSON):
{mitre_snippet}

Return ONLY a JSON with this structure:

{{
  "keywords": [
    "Product1",
    "Product2"
  ],
  "pub_start_date": "YYYY-MM-DDTHH:MM:SS.000",
  "pub_end_date": "YYYY-MM-DDTHH:MM:SS.999"
}}

IMPORTANT:
- Only include 2-3 most relevant products
- Date range should be based on evidence in the incident (e.g., if Windows Server 2019 is mentioned, use 2018-2024)
- If no specific dates are mentioned, use the last 5 years from today
- DO NOT suggest dates older than 10 years unless explicitly justified by the incident
"""

    response = call_llm(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        provider="groq",  # Gemini for keyword extraction
    )

    try:
        json_str = extract_json_block(response)
        parsed = json.loads(json_str)
        keywords = parsed.get("keywords", [])
        pub_start_date = parsed.get("pub_start_date")
        pub_end_date = parsed.get("pub_end_date")

        # Normalizar a lista de strings
        return {
            "keywords": [str(k).strip() for k in keywords if str(k).strip()],
            "pub_start_date": pub_start_date,
            "pub_end_date": pub_end_date,
        }
    except json.JSONDecodeError:
        # Fallback: usar texto bruto como keyword, sin filtro de fecha (usará default de 10 años)
        return {
            "keywords": [software_info[:200]],
            "pub_start_date": None,
            "pub_end_date": None,
        }


def run_cve_agent(
    software_info: str,
    mitre_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Agent 3: CVE Retriever (Realistic version with NVD)

    1) Uses LLM to extract technology/product keywords and time range.
    2) Calls NVD API with those keywords and date filters.
    3) Validates each CVE's relevance to the incident.
    4) Returns real CVEs (id, cvss, description) and annotates the used keyword.

    Mapping logic with MITRE (related_techniques) is left optional,
    as NVD does not return MITRE directly; it could be derived if needed.
    """

    extraction = _build_cve_keywords_with_llm(software_info, mitre_context)
    keywords = extraction["keywords"]
    pub_start_date = extraction.get("pub_start_date")
    pub_end_date = extraction.get("pub_end_date")

    all_cves: List[Dict[str, Any]] = []
    for kw in keywords:
        try:
            cves = search_cves(
                kw,
                max_results=3,
                pub_start_date=pub_start_date,
                pub_end_date=pub_end_date,
            )
        except Exception as e:
            # We don't want to break the flow due to network or rate-limit issues
            all_cves.append(
                {
                    "id": None,
                    "cvss": None,
                    "description": f"Error querying NVD with keyword '{kw}': {e}",
                    "source_keyword": kw,
                    "confidence": "low",
                }
            )
            continue

        for c in cves:
            # Validate CVE relevance before adding
            if _validate_cve_relevance(c, software_info):
                c2 = dict(c)
                c2["source_keyword"] = kw
                # Here you could add heuristics for related_techniques using mitre_context
                c2["related_techniques"] = []
                c2["confidence"] = "medium"
                all_cves.append(c2)

    result: Dict[str, Any] = {
        "cves": all_cves,
        "notes": (
            "CVEs obtained from official NVD API using keywords extracted "
            "from the incident. Manual review is required to determine relevance "
            "to the specific incident."
        ),
    }

    return result


def _validate_cve_relevance(
    cve: Dict[str, Any],
    incident_text: str,
) -> bool:
    """
    Uses LLM to validate if a CVE is actually relevant to the incident.
    Returns True if relevant, False otherwise.
    """
    system_prompt = (
        "You are a cybersecurity analyst. "
        "Determine if a given CVE is relevant to an incident description. "
        "A CVE is ONLY relevant if: "
        "1) The affected software/version matches what's in the incident, "
        "2) The vulnerability type matches the attack pattern, "
        "3) The CVE publication date is reasonable for the software mentioned. "
        "CRITICAL: Ancient CVEs (from 1999-2005) are almost NEVER relevant to modern incidents unless explicitly justified."
    )

    user_prompt = f"""
Incident description:
{incident_text}

CVE to validate:
ID: {cve.get("id")}
Description: {cve.get("description", "")[:500]}

Is this CVE relevant to the incident? Answer with ONLY a JSON:

{{
  "relevant": true/false,
  "reason": "Brief explanation"
}}
"""

    try:
        response = call_llm(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            provider="groq",
        )

        json_str = extract_json_block(response)
        parsed = json.loads(json_str)
        return parsed.get("relevant", False)
    except Exception:
        # If validation fails, be conservative and exclude the CVE
        return False
