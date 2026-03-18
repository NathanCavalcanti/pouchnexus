# integrations/nvd_client.py
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _get_nvd_api_key() -> Optional[str]:
    """
    Returns the NVD API key from the NVD_API_KEY environment variable.
    Optional: without key there are more rate-limits, but it's sufficient for lab use.
    """
    return os.getenv("NVD_API_KEY")


def search_cves(
    keyword: str,
    max_results: int = 5,
    pub_start_date: Optional[str] = None,
    pub_end_date: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Searches for CVEs in NVD using keywordSearch.
    Returns a list of simplified dicts: id, cvss, description.
    
    Args:
        keyword: Keyword to search for
        max_results: Maximum number of results to return
        pub_start_date: Start date for publication date filter (ISO 8601 format: YYYY-MM-DDTHH:MM:SS.000)
        pub_end_date: End date for publication date filter (ISO 8601 format: YYYY-MM-DDTHH:MM:SS.000)
    """
    from datetime import datetime
    
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    
    # NVD API has a strict limit of 120 days for date ranges.
    # We only apply date filters if explicitly provided AND within the limit.
    # Otherwise, we rely on keyword search (which returns most recent by default).
    if pub_start_date and pub_end_date:
        try:
            start_dt = datetime.strptime(pub_start_date, "%Y-%m-%dT%H:%M:%S.%f")
            end_dt = datetime.strptime(pub_end_date, "%Y-%m-%dT%H:%M:%S.%f")
            delta = end_dt - start_dt
            
            if delta.days <= 120:
                params["pubStartDate"] = pub_start_date
                params["pubEndDate"] = pub_end_date
            # else: Range > 120 days, skip date params to avoid 404 error
        except ValueError:
            # Date format error, skip filtering
            pass

    api_key = _get_nvd_api_key()
    headers = {
        "User-Agent": "SOC-MultiAgent-Assistant/1.0"
    }
    if api_key:
        headers["apiKey"] = api_key

    resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=20)
    resp.raise_for_status()
    data = resp.json()

    cves: List[Dict[str, Any]] = []

    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id")

        descriptions = cve_data.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

        metrics = cve_data.get("metrics", {})
        cvss = None

        # NVD API 2.0: CVSS in different keys depending on version
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                break

        cves.append(
            {
                "id": cve_id,
                "cvss": cvss,
                "description": desc_text,
            }
        )

    return cves
