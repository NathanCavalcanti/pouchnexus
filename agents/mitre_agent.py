# agents/mitre_agent.py
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from app.config import call_llm, extract_json_block
from integrations.mitre_local_db import enrich_techniques


def run_mitre_agent(
    incident_text: str,
    iocs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Agent 2: MITRE/TTP Mapper (Hybrid version: LLM + Official MITRE DB)

    Flow:
    1) LLM proposes a list of techniques by ID (Txxxx / Txxxx.xx) + justification.
    2) Each ID is enriched with name, tactic, and tactic_id using the official
       MITRE enterprise-attack.json dataset.
    3) Returns a dict:
       {
         "techniques": [...enriched...],
         "summary": "Brief summary..."
       }
    """

    ioc_snippet = json.dumps(iocs, ensure_ascii=False) if iocs else "{}"

    system_prompt = (
        "You are a cybersecurity analyst expert in MITRE ATT&CK. "
        "Based on the incident description and IOCs, identify the most probable techniques "
        "and sub-techniques (ID Txxxx / Txxxx.xx). "
        "\n\nCRITICAL RULES:\n"
        "1. Do NOT invent IDs; use only valid MITRE ATT&CK Enterprise IDs.\n"
        "2. ONLY map techniques if there is DIRECT EVIDENCE in the incident text.\n"
        "3. DO NOT map T1027.003 (Steganography) to ZIP files - ZIP is compression, NOT steganography.\n"
        "4. DO NOT map T1071 (C2) or T1071.001 (Web Protocols) unless there is evidence of BEACONING or persistent communication.\n"
        "5. DO NOT map T1190 (Exploit Public-Facing Application) unless there is evidence of exploitation (RCE, injection, etc).\n"
        "6. For file downloads, prefer T1105 (Ingress Tool Transfer).\n"
        "7. For phishing with malicious links, use T1566.002 only if there is evidence.\n"
        "8. If the incident involves ransomware execution, focus on execution techniques (T1204, T1059) and impact (T1486).\n"
        "\nDo not provide names or tactics, only IDs and justification: the system will enrich them later."
    )

    user_prompt = f"""
Incident description:

{incident_text}

Extracted IOCs (JSON):

{ioc_snippet}

IMPORTANT GUIDELINES:
- Only map techniques with DIRECT evidence from the incident
- For downloads: use T1105 (Ingress Tool Transfer)
- For ZIP files: use T1560.001 (Archive via Utility) if relevant, NOT T1027.003
- For C2: ONLY if there's evidence of beaconing/persistent communication
- For exploitation: ONLY if there's evidence of RCE, injection, or vulnerability exploitation
- For ransomware execution: focus on T1204 (User Execution), T1059 (Command/Scripting), T1486 (Data Encrypted for Impact)

Return ONLY a valid JSON with the following structure:

{{
  "techniques": [
    {{
      "id": "T1059.001",
      "justification": "Briefly explain why this technique applies based on EVIDENCE"
    }}
  ],
  "summary": "Summary in 3-5 lines of the observed MITRE pattern."
}}
"""

    # 1) Call model to get IDs + justification
    response = call_llm(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        provider="groq",  # Groq for technique extraction
    )

    try:
        json_str = extract_json_block(response)
        parsed = json.loads(json_str)
    except json.JSONDecodeError:
        # Unparseable response -> return minimal error object
        return {
            "parse_error": "LLM did not return valid JSON",
            "raw_response": response,
        }

    raw_techniques = parsed.get("techniques", [])
    summary = parsed.get("summary", "")

    # Normalize minimal structure
    norm_techniques = []
    for t in raw_techniques:
        if not isinstance(t, dict):
            continue
        tech_id = t.get("id")
        if not tech_id:
            continue
        norm_techniques.append(
            {
                "id": str(tech_id).strip(),
                "justification": t.get("justification", ""),
            }
        )

    # 2) Enrich against local official MITRE DB
    enriched = enrich_techniques(norm_techniques)

    # 3) STRICT VALIDATION: Filter out invalid techniques (hallucinations)
    valid_techniques = [t for t in enriched if t.get("source") == "Enterprise MITRE"]
    rejected_techniques = [t for t in enriched if t.get("source") != "Enterprise MITRE"]

    # Log rejected techniques for debugging
    if rejected_techniques:
        print(f"\n[MITRE] ⚠️  Rejected {len(rejected_techniques)} invalid technique(s):")
        for t in rejected_techniques:
            print(f"  ❌ {t.get('id')}: {t.get('justification')[:80]}...")
        print(f"[MITRE] ✅ Accepted {len(valid_techniques)} valid technique(s)\n")

    return {
        "techniques": valid_techniques,  # Only return validated techniques
        "summary": summary,
        "validation_stats": {
            "total_proposed": len(enriched),
            "valid": len(valid_techniques),
            "rejected": len(rejected_techniques),
        },
    }
