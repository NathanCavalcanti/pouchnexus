# agents/report_agent.py
from __future__ import annotations

import json
from typing import Any, Dict, Optional, List

from app.config import call_llm, extract_json_block, GROQ_MODEL_ANALYSIS


def run_report_agent(
    incident_text: str,
    iocs: Optional[Dict[str, Any]] = None,
    mitre_context: Optional[Dict[str, Any]] = None,
    cve_context: Optional[Dict[str, Any]] = None,
    investigation_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Agent 5: Report Agent
    Generates a structured report (in JSON) based on:
    - Incident description
    - IOCs
    - MITRE mapping
    - Relevant CVEs
    - Investigation / response plan
    """

    ioc_snippet = json.dumps(iocs, ensure_ascii=False) if iocs else "{}"
    mitre_snippet = (
        json.dumps(mitre_context, ensure_ascii=False) if mitre_context else "{}"
    )
    cve_snippet = json.dumps(cve_context, ensure_ascii=False) if cve_context else "{}"
    investigation_snippet = (
        json.dumps(investigation_context, ensure_ascii=False)
        if investigation_context
        else "{}"
    )

    system_prompt = (
        "You are an L2 SOC Analyst responsible for writing incident reports. "
        "You must generate a clear, structured, and actionable report for a SOC environment, "
        "separating an executive section (for managers) and a technical section (for analysts). "
        "Use a professional and concise tone.\n\n"
        "CRITICAL REQUIREMENTS:\n"
        "1. ALL timestamps MUST be in UTC format (YYYY-MM-DDTHH:MM:SSZ). Example: '2025-12-07T18:30:00Z'\n"
        "2. DO NOT use local time or omit the 'Z' suffix.\n"
        "3. Include specific attack details: HTTP methods (GET/POST), failed vs successful attempts, ports, user-agents.\n"
        "4. Link each malicious IP to specific threat intelligence findings.\n\n"
        "ANTI-HALLUCINATION RULES:\n"
        "5. DO NOT attribute to C2 activity unless there is explicit evidence of beaconing or persistent outbound connections in the data.\n"
        "6. DO NOT assign reputation scores, threat intel findings, or VirusTotal results unless they are EXPLICITLY present in the IOCs input. "
        "If IOCs do not contain virustotal_results, do NOT mention VirusTotal in the report.\n"
        "7. If threat actor is unknown, set attribution to 'Unknown' and confidence to 'low'. Do NOT invent threat group names.\n"
        "8. MITRE mapping: use ONLY the techniques provided in the MITRE Context input. Do NOT add, modify, or invent new techniques. "
        "Copy the tactic_id exactly as provided.\n"
        "9. If the mitre_mapping input is empty, set mitre_mapping to an empty list [].\n"
        "10. INCIDENT CLASSIFICATION - use precise language based on evidence:\n"
        "    - Few failed attempts (< 5) + success = 'Suspicious SSH Authentication' or 'Unauthorized Access', NOT 'Brute Force Attack'\n"
        "    - Many failed attempts (10+) + success = 'Brute Force Attack Leading to Successful Authentication'\n"
        "    - Many failed attempts, no success = 'Brute Force Attempt (Blocked)'\n"
        "    - Never use 'Authentication Bypass' or 'Exploitation' for password-based login scenarios.\n"
        "11. DO NOT assume post-compromise activity (persistence, lateral movement, data exfiltration) unless evidence exists. "
        "Instead write: 'Post-compromise activity: Unknown (pending investigation)'.\n"
        "12. SEVERITY RULES based on evidence:\n"
        "    - Successful login to root/admin/SYSTEM account = CRITICAL (confirmed compromise of privileged account)\n"
        "    - Successful login to regular user account = HIGH\n"
        "    - Failed attempts only, no success = MEDIUM\n"
        "    - The severity justification MUST reference concrete evidence.\n"
        "13. RECOMMENDATIONS must be specific and applicable to the actual attack vector:\n"
        "    - For SSH incidents: 'PermitRootLogin no' in sshd_config, fail2ban/sshguard, key-based auth, disable password auth.\n"
        "    - DO NOT recommend WAF for SSH attacks (WAF protects HTTP, not SSH).\n"
        "    - DO NOT recommend generic measures without specific commands or config changes.\n"
        "14. IOC COMPLETENESS: include ALL observable indicators from the incident:\n"
        "    - Source IPs AND destination IPs\n"
        "    - Ports (source and destination)\n"
        "    - Protocol (ssh, http, etc.)\n"
        "    - Targeted usernames\n"
        "    - Count of failed vs successful attempts\n"
        "15. TIMELINE must include: total number of events, duration of the attack window, and explicitly note if the sample is small."
    )

    user_prompt = f"""
Original incident description:
{incident_text}

IOCs (JSON):
{ioc_snippet}

MITRE Context (JSON):
{mitre_snippet}

CVE Context (JSON):
{cve_snippet}

Investigation / Response Plan (JSON):
{investigation_snippet}

Generate ONLY a valid JSON with the following structure:

{{
  "metadata": {{
    "title": "Incident Title",
    "severity": "high",
    "status": "under_investigation",
    "tlp": "TLP:AMBER",
    "detected_by": "SOC L1 - SIEM alert",
    "environment": "production"
  }},
  "executive_summary": "Summary in 5-8 lines, oriented to non-technical managers.",
  "technical_summary": "Technical summary of the attack, vectors, IOCs, MITRE, and CVEs.",
  "timeline": [
    {{
      "timestamp": "2025-11-30T08:14:00Z",
      "event": "First SIEM alert for suspicious traffic to malicious IP."
    }}
  ],
  "involved_parties": {{
    "affected_users": ["List of victim accounts/users"],
    "suspicious_accounts": ["List of suspicious/compromised accounts"],
    "threat_actor": {{
      "attribution": "Threat group name or 'Unknown'",
      "confidence": "high|medium|low",
      "indicators": ["List of attribution indicators based on TTPs"]
    }},
    "incident_responders": ["SOC team members handling the incident"]
  }},
  "ioc_section": {{
    "ips": [],
    "domains": [],
    "urls": [],
    "emails": [],
    "hashes": {{
      "md5": [],
      "sha1": [],
      "sha256": []
    }},
    "file_paths": []
  }},
  "mitre_mapping": [
    {{
      "id": "T1059.001",
      "name": "Command Shell",
      "tactic": "Execution",
      "tactic_id": "TA0002",
      "justification": "Brief explanation of why it applies."
    }}
  ],
  "cve_section": [
    {{
      "id": "CVE-XXXX-YYYY",
      "cvss": 9.8,
      "description": "Vulnerability summary.",
      "related_techniques": ["T1059.001"],
      "confidence": "high"
    }}
  ],
  "investigation_summary": [
    "Brief list of investigation actions performed / planned."
  ],
  "containment_and_recovery": {{
    "containment_actions": [
      "Isolate affected host from corporate network."
    ],
    "eradication": [
      "Reimage machine or clean malicious artifacts according to playbook."
    ],
    "recovery": [
      "Return systems to production after validating integrity."
    ]
  }},
  "recommendations": {{
    "short_term": [
      "Immediate improvement actions."
    ],
    "long_term": [
      "Strategic long-term measures."
    ]
  }}
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

    # Manually inject VirusTotal results from input IOCs to ensure they appear
    if iocs and "virustotal_results" in iocs:
        if "ioc_section" not in parsed:
            parsed["ioc_section"] = {}
        parsed["ioc_section"]["virustotal_results"] = iocs["virustotal_results"]

    return parsed


def render_report_text(report: Dict[str, Any]) -> str:
    """
    Converts the report JSON into structured plain text,
    ready to be copied into a ticket, document, or email.
    """

    meta = report.get("metadata", {})
    exec_sum = report.get("executive_summary", "")
    tech_sum = report.get("technical_summary", "")
    timeline = report.get("timeline", [])
    involved_parties = report.get("involved_parties", {})
    ioc_sec = report.get("ioc_section", {})
    mitre_map = report.get("mitre_mapping", [])
    cve_sec = report.get("cve_section", [])
    inv_sum = report.get("investigation_summary", [])
    cont_rec = report.get("containment_and_recovery", {})
    recs = report.get("recommendations", {})

    lines: List[str] = []

    # Cabecera
    lines.append("=== INCIDENT REPORT ===")
    lines.append("")

    # Metadatos
    lines.append(">> Metadata")
    lines.append(f"  Title      : {meta.get('title', 'N/A')}")
    lines.append(f"  Severity   : {meta.get('severity', 'N/A')}")
    lines.append(f"  Status     : {meta.get('status', 'N/A')}")
    lines.append(f"  TLP        : {meta.get('tlp', 'N/A')}")
    lines.append(f"  Detected by: {meta.get('detected_by', 'N/A')}")
    lines.append(f"  Environment: {meta.get('environment', 'N/A')}")
    lines.append("")

    # Executive summary
    lines.append(">> Executive Summary")
    lines.append(exec_sum or "N/A")
    lines.append("")

    # Technical summary
    lines.append(">> Technical Summary")
    lines.append(tech_sum or "N/A")
    lines.append("")

    # Timeline
    lines.append(">> Timeline")
    if timeline:
        for ev in timeline:
            ts = ev.get("timestamp", "N/A")
            ev_desc = ev.get("event", "N/A")
            lines.append(f"  - [{ts}] {ev_desc}")
    else:
        lines.append("  - N/A")
    lines.append("")

    # Involved Parties (5W1H - Who)
    lines.append(">> Involved Parties (5W1H - Who)")
    if involved_parties:
        affected = involved_parties.get("affected_users", [])
        suspicious = involved_parties.get("suspicious_accounts", [])
        threat_actor = involved_parties.get("threat_actor", {})
        responders = involved_parties.get("incident_responders", [])

        lines.append(f"  Affected Users     : {', '.join(affected) or 'N/A'}")
        lines.append(f"  Suspicious Accounts: {', '.join(suspicious) or 'N/A'}")

        if threat_actor:
            attribution = threat_actor.get("attribution", "Unknown")
            confidence = threat_actor.get("confidence", "N/A")
            indicators = threat_actor.get("indicators", [])
            lines.append(
                f"  Threat Actor       : {attribution} [Confidence: {confidence}]"
            )
            if indicators:
                lines.append("    Attribution Indicators:")
                for ind in indicators:
                    lines.append(f"      - {ind}")

        lines.append(f"  Incident Responders: {', '.join(responders) or 'N/A'}")
    else:
        lines.append("  - N/A")
    lines.append("")

    # IOCs
    lines.append(">> Indicators of Compromise (IOCs)")
    lines.append(f"  IPs      : {', '.join(ioc_sec.get('ips', [])) or 'N/A'}")
    lines.append(f"  Domains  : {', '.join(ioc_sec.get('domains', [])) or 'N/A'}")
    lines.append(f"  URLs     : {', '.join(ioc_sec.get('urls', [])) or 'N/A'}")
    lines.append(f"  Emails   : {', '.join(ioc_sec.get('emails', [])) or 'N/A'}")

    hashes = ioc_sec.get("hashes", {})
    lines.append("  Hashes:")
    lines.append(f"    MD5    : {', '.join(hashes.get('md5', [])) or 'N/A'}")
    lines.append(f"    SHA1   : {', '.join(hashes.get('sha1', [])) or 'N/A'}")
    lines.append(f"    SHA256 : {', '.join(hashes.get('sha256', [])) or 'N/A'}")

    file_paths = ioc_sec.get("file_paths", [])
    lines.append("  File paths:")
    if file_paths:
        for p in file_paths:
            lines.append(f"    - {p}")
    else:
        lines.append("    - N/A")
    lines.append("")

    lines.append("")

    # VirusTotal Analysis
    vt_results = ioc_sec.get("virustotal_results", [])
    if vt_results:
        lines.append(">> VirusTotal Analysis")
        for res in vt_results:
            h = res.get("hash", "N/A")
            mal = res.get("malicious", 0)
            total = res.get("total", 0)
            label = res.get("threat_label", "N/A")
            verdicts = ", ".join(res.get("sandbox_verdicts", [])) or "None"

            lines.append(f"  Hash: {h}")
            lines.append(f"    Detection: {mal}/{total}")
            lines.append(f"    Threat Label: {label}")
            lines.append(f"    Sandbox Verdicts: {verdicts}")
            lines.append(f"    Link: {res.get('permalink', 'N/A')}")
            lines.append("")
        lines.append("")

    # MITRE
    lines.append(">> MITRE ATT&CK Mapping")
    if mitre_map:
        for t in mitre_map:
            tech_id = t.get("id", "TXXXX")
            name = t.get("name", "N/A")
            tactic_id = t.get("tactic_id", "TAXXXX")
            tactic_name = t.get("tactic", "N/A")

            source_raw = t.get("source", "")
            if source_raw == "Enterprise MITRE":
                source_label = "Enterprise MITRE"
            elif source_raw == "LLM supposition":
                source_label = "LLM supposition"
            else:
                source_label = source_raw or "Unknown"

            lines.append(
                f"  - {tech_id} ({name}) "
                f"[{tactic_id} - {tactic_name}] "
                f"[Source: {source_label}]"
            )
            lines.append(f"    Justification: {t.get('justification', 'N/A')}")
    else:
        lines.append("  - N/A")
    lines.append("")

    # CVEs
    lines.append(">> Vulnerabilities (CVEs)")
    if cve_sec:
        for c in cve_sec:
            lines.append(
                f"  - {c.get('id', 'CVE-XXXX-YYYY')} "
                f"(CVSS {c.get('cvss', 'N/A')}, confidence: {c.get('confidence', 'N/A')})"
            )
            lines.append(f"    Description       : {c.get('description', 'N/A')}")
            lines.append(
                f"    Related techniques: {', '.join(c.get('related_techniques', [])) or 'N/A'}"
            )
    else:
        lines.append("  - N/A")
    lines.append("")

    # Investigation summary
    lines.append(">> Investigation Summary")
    if inv_sum:
        for item in inv_sum:
            lines.append(f"  - {item}")
    else:
        lines.append("  - N/A")
    lines.append("")

    # Containment & Recovery
    lines.append(">> Containment & Recovery")
    cont_actions = cont_rec.get("containment_actions", [])
    erad = cont_rec.get("eradication", [])
    recv = cont_rec.get("recovery", [])

    lines.append("  Containment Actions:")
    if cont_actions:
        for a in cont_actions:
            lines.append(f"    - {a}")
    else:
        lines.append("    - N/A")

    lines.append("  Eradication:")
    if erad:
        for a in erad:
            lines.append(f"    - {a}")
    else:
        lines.append("    - N/A")

    lines.append("  Recovery:")
    if recv:
        for a in recv:
            lines.append(f"    - {a}")
    else:
        lines.append("    - N/A")
    lines.append("")

    # Recommendations
    lines.append(">> Recommendations")
    short_term = recs.get("short_term", [])
    long_term = recs.get("long_term", [])

    lines.append("  Short-term:")
    if short_term:
        for r in short_term:
            lines.append(f"    - {r}")
    else:
        lines.append("    - N/A")

    lines.append("  Long-term:")
    if long_term:
        for r in long_term:
            lines.append(f"    - {r}")
    else:
        lines.append("    - N/A")

    return "\n".join(lines)
