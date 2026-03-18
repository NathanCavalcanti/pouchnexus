# integrations/virustotal_client.py
from __future__ import annotations

import time
from typing import Any, Dict

import requests

# VirusTotal API v3 URL
VT_API_URL = "https://www.virustotal.com/api/v3"


def get_file_report(file_hash: str) -> Dict[str, Any]:
    """
    Retrieves the file report from VirusTotal for a given hash (MD5, SHA1, SHA256).
    
    Returns a dictionary with:
    - malicious_count: number of engines detecting it as malicious
    - total_engines: total number of engines
    - permalink: URL to the VT report
    - error: error message if any
    """
    from app.config import VIRUSTOTAL_API_KEY
    
    if not VIRUSTOTAL_API_KEY:
        return {
            "error": "Missing VIRUSTOTAL_API_KEY",
            "malicious_count": 0,
            "total_engines": 0,
            "permalink": ""
        }

    url = f"{VT_API_URL}/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            return {
                "error": "Hash not found in VirusTotal",
                "malicious_count": 0,
                "total_engines": 0,
                "permalink": ""
            }
        
        if response.status_code == 429:
            return {
                "error": "Rate limit exceeded",
                "malicious_count": 0,
                "total_engines": 0,
                "permalink": ""
            }
            
        if response.status_code == 403:
             return {
                "error": "Forbidden (Invalid API Key)",
                "malicious_count": 0,
                "total_engines": 0,
                "permalink": ""
            }

        response.raise_for_status()
        data = response.json()
        
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        # Extract richer context
        threat_label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "")
        
        # Sandbox verdicts (e.g. "Metasploit", "Rozena")
        sandbox_verdicts = []
        for _, verdict in attributes.get("sandbox_verdicts", {}).items():
            if "malware_names" in verdict:
                sandbox_verdicts.extend(verdict["malware_names"])
        sandbox_verdicts = list(set(sandbox_verdicts))
        
        # Sigma rules (behavioral)
        sigma_rules = []
        for rule in attributes.get("sigma_analysis_results", []):
            if rule.get("rule_title"):
                sigma_rules.append(rule.get("rule_title"))
                
        # Signature info (masquerading check)
        signature_info = attributes.get("signature_info", {}).get("description", "")
        
        return {
            "malicious_count": stats.get("malicious", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            "scan_date": attributes.get("last_analysis_date", 0),
            "names": attributes.get("names", [])[:5],
            "threat_label": threat_label,
            "sandbox_verdicts": sandbox_verdicts[:5],
            "sigma_rules": sigma_rules[:3],
            "signature_description": signature_info
        }

    except Exception as e:
        return {
            "error": str(e),
            "malicious_count": 0,
            "total_engines": 0,
            "permalink": ""
        }


def scan_url(url: str) -> Dict[str, Any]:
    """
    Scans a URL in VirusTotal and returns analysis results.
    
    POST https://www.virustotal.com/api/v3/urls
    
    Returns:
    - analysis_id: ID for retrieving results
    - malicious_count: detections
    - total_engines: total scanners
    - categories: URL categories
    - permalink: VT report link
    """
    from app.config import VIRUSTOTAL_API_KEY
    
    if not VIRUSTOTAL_API_KEY:
        return {
            "error": "Missing VIRUSTOTAL_API_KEY",
            "malicious_count": 0,
            "total_engines": 0,
            "permalink": ""
        }

    # Step 1: Submit URL for scanning
    submit_url = f"{VT_API_URL}/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    data = {"url": url}

    try:
        response = requests.post(submit_url, headers=headers, data=data, timeout=10)
        
        if response.status_code == 429:
            return {"error": "Rate limit exceeded", "malicious_count": 0, "total_engines": 0, "permalink": ""}
        
        if response.status_code == 403:
            return {"error": "Forbidden (Invalid API Key)", "malicious_count": 0, "total_engines": 0, "permalink": ""}
        
        response.raise_for_status()
        submit_data = response.json()
        
        # Get analysis ID
        analysis_id = submit_data.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "No analysis ID returned", "malicious_count": 0, "total_engines": 0, "permalink": ""}
        
        # Step 2: Wait and retrieve analysis results
        time.sleep(10)  # Wait for analysis to complete
        
        analysis_url = f"{VT_API_URL}/analyses/{analysis_id}"
        analysis_response = requests.get(analysis_url, headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=10)
        analysis_response.raise_for_status()
        analysis_data = analysis_response.json()
        
        attributes = analysis_data.get("data", {}).get("attributes", {})
        stats = attributes.get("stats", {})
        
        # Extract URL for permalink
        # url_id = attributes.get("url", "")
        
        return {
            "malicious_count": stats.get("malicious", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "categories": attributes.get("categories", {}),
            "permalink": f"https://www.virustotal.com/gui/url/{analysis_id}" if analysis_id else ""
        }

    except Exception as e:
        return {
            "error": str(e),
            "malicious_count": 0,
            "total_engines": 0,
            "permalink": ""
        }


def get_ip_report(ip: str) -> Dict[str, Any]:
    """
    Retrieves IP address reputation from VirusTotal.
    
    GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
    
    Returns:
    - reputation: score
    - malicious_count: detections
    - country: geolocation
    - asn: autonomous system number
    - as_owner: ISP/Organization
    """
    from app.config import VIRUSTOTAL_API_KEY
    
    if not VIRUSTOTAL_API_KEY:
        return {
            "error": "Missing VIRUSTOTAL_API_KEY",
            "malicious_count": 0,
            "total_engines": 0,
            "reputation": 0,
            "country": "Unknown",
            "asn": "Unknown",
            "permalink": ""
        }

    url = f"{VT_API_URL}/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            return {
                "error": "IP not found in VirusTotal",
                "malicious_count": 0,
                "total_engines": 0,
                "reputation": 0,
                "country": "Unknown",
                "asn": "Unknown",
                "permalink": ""
            }
        
        if response.status_code == 429:
            return {"error": "Rate limit exceeded", "malicious_count": 0, "total_engines": 0, "reputation": 0, "country": "Unknown", "asn": "Unknown", "permalink": ""}
        
        if response.status_code == 403:
            return {"error": "Forbidden (Invalid API Key)", "malicious_count": 0, "total_engines": 0, "reputation": 0, "country": "Unknown", "asn": "Unknown", "permalink": ""}

        response.raise_for_status()
        data = response.json()
        
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        return {
            "malicious_count": stats.get("malicious", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "reputation": attributes.get("reputation", 0),
            "country": attributes.get("country", "Unknown"),
            "asn": attributes.get("asn", "Unknown"),
            "as_owner": attributes.get("as_owner", "Unknown"),
            "permalink": f"https://www.virustotal.com/gui/ip-address/{ip}"
        }

    except Exception as e:
        return {
            "error": str(e),
            "malicious_count": 0,
            "total_engines": 0,
            "reputation": 0,
            "country": "Unknown",
            "asn": "Unknown",
            "permalink": ""
        }


def get_domain_report(domain: str) -> Dict[str, Any]:
    """
    Retrieves domain reputation from VirusTotal.
    
    GET https://www.virustotal.com/api/v3/domains/{domain}
    
    Returns:
    - malicious_count: detections
    - categories: domain categorization
    - registrar: domain registrar
    - creation_date: domain age
    """
    from app.config import VIRUSTOTAL_API_KEY
    
    if not VIRUSTOTAL_API_KEY:
        return {
            "error": "Missing VIRUSTOTAL_API_KEY",
            "malicious_count": 0,
            "total_engines": 0,
            "categories": [],
            "registrar": "Unknown",
            "permalink": ""
        }

    url = f"{VT_API_URL}/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            return {
                "error": "Domain not found in VirusTotal",
                "malicious_count": 0,
                "total_engines": 0,
                "categories": [],
                "registrar": "Unknown",
                "permalink": ""
            }
        
        if response.status_code == 429:
            return {"error": "Rate limit exceeded", "malicious_count": 0, "total_engines": 0, "categories": [], "registrar": "Unknown", "permalink": ""}
        
        if response.status_code == 403:
            return {"error": "Forbidden (Invalid API Key)", "malicious_count": 0, "total_engines": 0, "categories": [], "registrar": "Unknown", "permalink": ""}

        response.raise_for_status()
        data = response.json()
        
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        # Extract categories
        categories_dict = attributes.get("categories", {})
        categories_list = list(set(categories_dict.values())) if categories_dict else []
        
        return {
            "malicious_count": stats.get("malicious", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "categories": categories_list,
            "registrar": attributes.get("registrar", "Unknown"),
            "creation_date": attributes.get("creation_date", 0),
            "permalink": f"https://www.virustotal.com/gui/domain/{domain}"
        }

    except Exception as e:
        return {
            "error": str(e),
            "malicious_count": 0,
            "total_engines": 0,
            "categories": [],
            "registrar": "Unknown",
            "permalink": ""
        }
