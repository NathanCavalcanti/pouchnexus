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
        "9. DO NOT assume C2, payload execution, or lateral movement without explicit evidence.\n"
        "10. DO NOT map T1059.001 (PowerShell) unless PowerShell commands appear in logs.\n"
        "11. For SSH/RDP failed logins followed by success: use T1078 (Valid Accounts) with tactic TA0001 (Initial Access). "
        "Do NOT assign T1078 to TA0005 (Defense Evasion) for login scenarios.\n"
        "12. EVIDENCE THRESHOLD for T1110 (Brute Force): requires MANY failed attempts (tens or hundreds). "
        "If there are fewer than 5 failed attempts, classify as 'Suspicious Authentication Activity' with confidence LOW, not brute force. "
        "Use T1110 ONLY when the volume of failed attempts clearly indicates automated/brute force behavior.\n"
        "13. For HTTP brute force: use T1110.001 or T1110.003 (Password Spraying), NOT T1190.\n"
        "14. If you are uncertain about a technique, DO NOT include it. Include ONLY high-confidence mappings.\n"
        "15. For each technique, the justification MUST quote specific evidence from the incident text (timestamps, IPs, log lines).\n"
        "16. TACTIC SELECTION: T1078 (Valid Accounts) -> TA0001 (Initial Access) when credentials are used to gain access. "
        "Only map T1078 to TA0005 (Defense Evasion) when valid accounts are used to BLEND IN after initial access is already established.\n"
        "17. SEVERITY GUIDANCE: If a privileged account (root, admin, SYSTEM) is successfully accessed, this is CRITICAL, not HIGH. "
        "A successful login to root/admin = confirmed compromise regardless of how few attempts preceded it.\n"
        "\nEXAMPLES OF CORRECT vs INCORRECT MAPPING:\n"
        "\n[CORRECT] 100+ SSH failed logins followed by success -> T1110 (Brute Force, high confidence) + T1078 (Valid Accounts, TA0001)"
        "\n[CORRECT] 2 SSH failed logins + 1 success -> T1078 (Valid Accounts, TA0001, high confidence). T1110 NOT justified (too few attempts)."
        "\n[INCORRECT] 2 failed + 1 success -> T1110 (Brute Force) <- insufficient evidence for brute force"
        "\n[INCORRECT] SSH login -> T1078 with TA0005 <- TA0005 is for defense evasion, not initial access"
        "\n[INCORRECT] SSH failed logins -> T1059.001 (PowerShell) <- NO PowerShell in SSH"
        "\n[INCORRECT] SSH auth events -> T1071.001 (Web Protocols) <- SSH is NOT a web protocol"
        "\n[CORRECT] HTTP POST with SQLi payload -> T1190 (Exploit Public-Facing App)"
        "\n[CORRECT] PowerShell.exe -enc Base64... in logs -> T1059.001 (PowerShell)"
        "\n\nDo not provide names or tactics, only IDs and justification: the system will enrich them later.\n"
        "However, DO specify in your justification which tactic applies (e.g., 'Initial Access' for T1078 login scenarios)."
    )

    user_prompt = f"""
Incident description:

{incident_text}

Extracted IOCs (JSON):

{ioc_snippet}

IMPORTANT GUIDELINES:
- Only map techniques with DIRECT evidence from the incident text
- For each technique, QUOTE the specific log line or data that justifies it
- For downloads: use T1105 (Ingress Tool Transfer)
- For ZIP files: use T1560.001 (Archive via Utility) if relevant, NOT T1027.003
- For C2: ONLY if there's evidence of beaconing/persistent communication
- For exploitation: ONLY if there's evidence of RCE, injection, or vulnerability exploitation
- For ransomware execution: focus on T1204 (User Execution), T1059 (Command/Scripting), T1486 (Data Encrypted for Impact)
- For SSH/RDP failed logins: use T1110 (Brute Force), NOT T1059 or T1071
- For successful login after brute force: add T1078 (Valid Accounts)
- DO NOT assume C2, lateral movement, or payload execution without explicit log evidence
- It is better to return fewer correct techniques than many incorrect ones

Return ONLY a valid JSON with the following structure:

{{
  "techniques": [
    {{
      "id": "T1110",
      "justification": "Multiple Failed password events from 185.220.101.45 indicate brute force activity.",
      "confidence": "high",
      "evidence_quote": "Failed password for root from 185.220.101.45 port 53422 ssh2"
    }}
  ],
  "summary": "Summary in 3-5 lines of the observed MITRE pattern.",
  "uncertainty_notes": "List anything that could NOT be determined from the data."
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
    uncertainty_notes = parsed.get("uncertainty_notes", "")

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
                "confidence": t.get("confidence", "medium"),
                "evidence_quote": t.get("evidence_quote", ""),
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
        "uncertainty_notes": uncertainty_notes,
        "validation_stats": {
            "total_proposed": len(enriched),
            "valid": len(valid_techniques),
            "rejected": len(rejected_techniques),
        },
    }
