from __future__ import annotations

import json
from typing import Any, Dict

from app.config import call_llm, extract_json_block
from integrations.virustotal_client import get_file_report, scan_url, get_ip_report, get_domain_report
import time


def run_ioc_agent(incident_text: str) -> Dict[str, Any]:
    """
    Agent 1: IOC Extractor
    Extracts IPs, domains, URLs, hashes, emails, file paths, etc.
    Returns a dictionary with structured IOCs.
    """

    system_prompt = (
        "You are a SOC analyst specializing in IOC extraction. "
        "Your task is to read the incident description and extract indicators of compromise "
        "(IPs, domains, URLs, emails, malware hashes, file paths) "
        "into a valid JSON format.\n\n"
        "IMPORTANT RULES:\n"
        "- Do NOT extract memory addresses (e.g., 0x...) as hashes.\n"
        "- Do NOT extract usernames (e.g., 'john.doe') as emails. Emails MUST contain '@' and a domain.\n"
        "- Only extract valid IPv4 or IPv6 addresses."
    )

    user_prompt = f"""
Incident text:

{incident_text}

Return ONLY a valid JSON with the following structure:

{{
  "ips": ["1.2.3.4", ...],
  "domains": ["example.com", ...],
  "urls": ["http://example.com/malware.exe", ...],
  "emails": ["user@example.com", ...],
  "hashes": {{
    "md5": ["..."],
    "sha1": ["..."],
    "sha256": ["..."]
  }},
  "file_paths": ["C:\\\\Windows\\\\System32\\\\...", "/tmp/malicious", ...]
}}
"""

    response = call_llm(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        provider="groq"  # Groq for data extraction
    )

    try:
        json_str = extract_json_block(response)
        parsed = json.loads(json_str)
        parsed = validate_iocs(parsed)
        
        # Enrich with VirusTotal
        parsed = enrich_with_virustotal(parsed)
        
    except json.JSONDecodeError:
        parsed = {
            "parse_error": "LLM did not return valid JSON",
            "raw_response": response,
        }

    return parsed


def validate_iocs(iocs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates and cleans extracted IOCs.
    - Removes emails without '@'.
    - Removes hashes that look like memory addresses or have invalid lengths.
    """
    # Validate Emails
    if "emails" in iocs and isinstance(iocs["emails"], list):
        valid_emails = []
        for email in iocs["emails"]:
            if isinstance(email, str) and "@" in email and "." in email.split("@")[-1]:
                valid_emails.append(email)
        iocs["emails"] = valid_emails

    # Validate Hashes
    if "hashes" in iocs and isinstance(iocs["hashes"], dict):
        for hash_type, hash_list in iocs["hashes"].items():
            if not isinstance(hash_list, list):
                continue
            
            valid_hashes = []
            for h in hash_list:
                if not isinstance(h, str):
                    continue
                
                # Skip memory addresses
                if h.lower().startswith("0x"):
                    continue
                
                # Basic length validation (optional but good)
                # MD5=32, SHA1=40, SHA256=64
                l = len(h)
                if hash_type == "md5" and l != 32:
                    continue
                if hash_type == "sha1" and l != 40:
                    continue
                if hash_type == "sha256" and l != 64:
                    continue
                    
                valid_hashes.append(h)
            
            iocs["hashes"][hash_type] = valid_hashes

    return iocs


def enrich_with_virustotal(iocs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Checks extracted IOCs against VirusTotal:
    - Hashes (max 3)
    - IPs (public only, max 3)
    - URLs (max 3)
    - Domains (max 3)
    
    Rate limiting: 15 seconds between requests (4 req/min for free tier)
    """
    # === HASHES ===
    if "hashes" in iocs:
        vt_results = []
        hashes_checked = 0
        max_hashes = 3
        
        # Deduplicate hashes representing the same file:
        # Assuming that if a file has multiple hashes, they appear at the same index
        # in the extracted lists. We prioritize SHA256 > SHA1 > MD5.
        sha256_list = iocs.get("hashes", {}).get("sha256", [])
        sha1_list = iocs.get("hashes", {}).get("sha1", [])
        md5_list = iocs.get("hashes", {}).get("md5", [])
        
        all_hashes = []
        max_len = max(len(sha256_list), len(sha1_list), len(md5_list)) if iocs.get("hashes") else 0
        
        for i in range(max_len):
            if i < len(sha256_list):
                all_hashes.append(sha256_list[i])
            elif i < len(sha1_list):
                all_hashes.append(sha1_list[i])
            elif i < len(md5_list):
                all_hashes.append(md5_list[i])
                
        # Remove any resulting duplicates
        all_hashes = list(set(all_hashes))
        
        if all_hashes:
            print(f"[VirusTotal] Checking {min(len(all_hashes), max_hashes)} hash(es)...")
            
            for h in all_hashes:
                if hashes_checked >= max_hashes:
                    break
                    
                report = get_file_report(h)
                if report.get("error"):
                    print(f"[VirusTotal] Error for hash {h[:16]}...: {report.get('error')}")
                    continue
                    
                if report:
                    vt_results.append({
                        "hash": h,
                        "malicious": report.get("malicious_count", 0),
                        "total": report.get("total_engines", 0),
                        "permalink": report.get("permalink", ""),
                        "names": report.get("names", []),
                        "threat_label": report.get("threat_label", ""),
                        "sandbox_verdicts": report.get("sandbox_verdicts", []),
                        "sigma_rules": report.get("sigma_rules", []),
                        "signature": report.get("signature_description", "")
                    })
                    hashes_checked += 1
                    print(f"[VirusTotal] ✓ Hash {h[:16]}... - Detection: {report.get('malicious_count', 0)}/{report.get('total_engines', 0)}")
                    time.sleep(15)  # Rate limiting
                    
            if vt_results:
                iocs["virustotal_results"] = vt_results
                print(f"[VirusTotal] Added {len(vt_results)} hash result(s)")
    
    # === IPs ===
    if "ips" in iocs and isinstance(iocs["ips"], list):
        vt_ip_results = []
        ips_checked = 0
        max_ips = 3
        
        for ip in iocs["ips"]:
            if ips_checked >= max_ips:
                break
            
            # Skip private IPs
            if ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", 
                             "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                             "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                             "127.", "169.254.")):
                continue
            
            print(f"[VirusTotal] Checking IP {ip}...")
            report = get_ip_report(ip)
            
            if report.get("error"):
                print(f"[VirusTotal] Error for IP {ip}: {report.get('error')}")
                continue
            
            vt_ip_results.append({
                "ip": ip,
                "malicious": report.get("malicious_count", 0),
                "total": report.get("total_engines", 0),
                "reputation": report.get("reputation", 0),
                "country": report.get("country", "Unknown"),
                "asn": report.get("asn", "Unknown"),
                "as_owner": report.get("as_owner", "Unknown"),
                "permalink": report.get("permalink", "")
            })
            ips_checked += 1
            print(f"[VirusTotal] ✓ IP {ip} - Detection: {report.get('malicious_count', 0)}/{report.get('total_engines', 0)}, Reputation: {report.get('reputation', 0)}")
            time.sleep(15)  # Rate limiting
        
        if vt_ip_results:
            iocs["virustotal_ip_results"] = vt_ip_results
            print(f"[VirusTotal] Added {len(vt_ip_results)} IP result(s)")
    
    # === URLs ===
    if "urls" in iocs and isinstance(iocs["urls"], list):
        vt_url_results = []
        urls_checked = 0
        max_urls = 3
        
        for url in iocs["urls"]:
            if urls_checked >= max_urls:
                break
            
            print(f"[VirusTotal] Scanning URL {url[:50]}...")
            report = scan_url(url)
            
            if report.get("error"):
                print(f"[VirusTotal] Error for URL: {report.get('error')}")
                continue
            
            vt_url_results.append({
                "url": url,
                "malicious": report.get("malicious_count", 0),
                "total": report.get("total_engines", 0),
                "categories": report.get("categories", {}),
                "permalink": report.get("permalink", "")
            })
            urls_checked += 1
            print(f"[VirusTotal] ✓ URL - Detection: {report.get('malicious_count', 0)}/{report.get('total_engines', 0)}")
            time.sleep(15)  # Rate limiting
        
        if vt_url_results:
            iocs["virustotal_url_results"] = vt_url_results
            print(f"[VirusTotal] Added {len(vt_url_results)} URL result(s)")
    
    # === DOMAINS ===
    if "domains" in iocs and isinstance(iocs["domains"], list):
        vt_domain_results = []
        domains_checked = 0
        max_domains = 3
        
        for domain in iocs["domains"]:
            if domains_checked >= max_domains:
                break
            
            print(f"[VirusTotal] Checking domain {domain}...")
            report = get_domain_report(domain)
            
            if report.get("error"):
                print(f"[VirusTotal] Error for domain {domain}: {report.get('error')}")
                continue
            
            vt_domain_results.append({
                "domain": domain,
                "malicious": report.get("malicious_count", 0),
                "total": report.get("total_engines", 0),
                "categories": report.get("categories", []),
                "registrar": report.get("registrar", "Unknown"),
                "permalink": report.get("permalink", "")
            })
            domains_checked += 1
            print(f"[VirusTotal] ✓ Domain {domain} - Detection: {report.get('malicious_count', 0)}/{report.get('total_engines', 0)}")
            time.sleep(15)  # Rate limiting
        
        if vt_domain_results:
            iocs["virustotal_domain_results"] = vt_domain_results
            print(f"[VirusTotal] Added {len(vt_domain_results)} domain result(s)")
        
    return iocs
