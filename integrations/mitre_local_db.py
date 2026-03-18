# integrations/mitre_local_db.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# Official Enterprise ATT&CK URL on GitHub (STIX bundle)
MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Path to the local file in the project
DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "enterprise-attack.json"

# In-memory structures
_TECHNIQUES_BY_ID: Dict[str, Dict[str, Any]] = {}
_TACTICS_BY_SHORTNAME: Dict[str, Dict[str, Any]] = {}
_LOADED: bool = False


# ---------------------------------------------------------------------------
# MITRE bundle download and loading
# ---------------------------------------------------------------------------


def _fetch_remote_bundle() -> Optional[Dict[str, Any]]:
    """
    Attempts to download the Enterprise ATT&CK bundle from GitHub.
    If there is any issue (network, GitHub, invalid JSON), returns None
    and prints a warning to the console.
    """
    print(
        f"[MITRE] Attempting to download Enterprise ATT&CK from GitHub:\n        {MITRE_URL}"
    )
    try:
        resp = requests.get(MITRE_URL, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[MITRE] Warning: could not download ATT&CK from GitHub ({e}).")
        return None

    try:
        data = resp.json()
    except json.JSONDecodeError as e:
        print(f"[MITRE] Warning: GitHub response is not valid JSON ({e}).")
        return None

    if "objects" not in data or not isinstance(data["objects"], list):
        print(
            "[MITRE] Warning: downloaded JSON does not appear to be a valid ATT&CK bundle (no 'objects')."
        )
        return None

    print(
        f"[MITRE] Download successful from GitHub. Objects in bundle: {len(data['objects'])}"
    )
    return data


def _save_bundle_to_disk(data: Dict[str, Any]) -> None:
    """Saves the bundle to data/enterprise-attack.json."""
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DATA_PATH.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[MITRE] Updated bundle saved to {DATA_PATH}")


def _load_bundle_from_disk() -> Optional[Dict[str, Any]]:
    """Loads the bundle from disk if it exists and is valid. Otherwise, returns None."""
    if not DATA_PATH.exists():
        print(f"[MITRE] Warning: no local copy at {DATA_PATH}.")
        return None

    try:
        with DATA_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[MITRE] Warning: error reading local copy ({e}).")
        return None

    if "objects" not in data or not isinstance(data["objects"], list):
        print(
            "[MITRE] Warning: local copy does not appear to be a valid ATT&CK bundle (no 'objects')."
        )
        return None

    print(f"[MITRE] Bundle loaded from local copy: {DATA_PATH}")
    return data


def _load_bundle() -> Dict[str, Any]:
    """
    Bundle loading logic:
    1) Attempt download from GitHub.
       - If successful -> save to disk and use it.
    2) If download fails or is invalid:
       - Attempt to load local copy.
    3) If no valid local copy exists either:
       - Raise error.
    """
    # 1) Attempt remote
    data = _fetch_remote_bundle()
    if data is not None:
        # Save to disk for future offline executions
        _save_bundle_to_disk(data)
        print("[MITRE] Using bundle downloaded from GitHub.")
        return data

    # 2) Fallback to local copy
    print("[MITRE] Warning: using local ATT&CK copy (no connectivity to GitHub).")
    local_data = _load_bundle_from_disk()
    if local_data is not None:
        print("[MITRE] MITRE bundle loaded successfully from local copy.")
        return local_data

    # 3) Neither remote nor local is valid
    raise RuntimeError(
        "[MITRE] Critical error: could not obtain ATT&CK bundle "
        "from GitHub or local copy. Verify connectivity "
        "and that data/enterprise-attack.json exists and is valid."
    )


# ---------------------------------------------------------------------------
# MITRE Index Construction (Tactics and Techniques)
# ---------------------------------------------------------------------------


def _load_data() -> None:
    """Loads Enterprise ATT&CK and builds in-memory indices."""
    global _LOADED, _TECHNIQUES_BY_ID, _TACTICS_BY_SHORTNAME

    if _LOADED:
        return

    bundle = _load_bundle()
    objects = bundle.get("objects", [])

    # 1) Tactics by shortname (execution, persistence, etc.)
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname")
            if not shortname:
                continue

            tactic_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    tactic_id = ref["external_id"]
                    break

            _TACTICS_BY_SHORTNAME[shortname] = {
                "tactic_id": tactic_id,
                "tactic": obj.get("name"),
                "shortname": shortname,
            }

    # 2) Techniques by external_id (Txxxx / Txxxx.xx)
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        external_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                external_id = ref["external_id"]
                break

        if not external_id:
            continue

        tactics: List[Dict[str, Any]] = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name")
                tac = _TACTICS_BY_SHORTNAME.get(phase_name)
                if tac:
                    tactics.append(
                        {
                            "tactic_id": tac["tactic_id"],
                            "tactic": tac["tactic"],
                            "shortname": tac["shortname"],
                        }
                    )

        _TECHNIQUES_BY_ID[external_id] = {
            "id": external_id,
            "name": obj.get("name"),
            "tactics": tactics,
            "raw": obj,
        }

    _LOADED = True


def get_technique_by_id(tech_id: str) -> Optional[Dict[str, Any]]:
    """Returns the MITRE technique by ID (e.g. 'T1059.001'), or None if it does not exist."""
    _load_data()
    return _TECHNIQUES_BY_ID.get(tech_id)


def enrich_techniques(techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrichment of techniques proposed by the LLM with official MITRE data.

    Typical input:
      [{"id": "T1059.001", "justification": "..."}]

    Output:
      [
        {
          "id": "T1059.001",
          "name": "Command Shell",
          "tactic_id": "TA0002",
          "tactic": "Execution",
          "justification": "...",
          "source": "Enterprise MITRE"  # or "LLM supposition"
        },
        ...
      ]
    """
    _load_data()
    enriched: List[Dict[str, Any]] = []

    for t in techniques:
        tech_id = t.get("id")
        justification = t.get("justification", "")

        base = get_technique_by_id(str(tech_id)) if tech_id else None

        if base:
            tactics = base.get("tactics") or []
            tactic_id = tactics[0].get("tactic_id") if tactics else None
            tactic_name = tactics[0].get("tactic") if tactics else None

            enriched.append(
                {
                    "id": base.get("id"),
                    "name": base.get("name"),
                    "tactic_id": tactic_id,
                    "tactic": tactic_name,
                    "justification": justification,
                    "source": "Enterprise MITRE",
                }
            )
        else:
            # ID not found in MITRE database (possible error / LLM supposition)
            enriched.append(
                {
                    "id": tech_id,
                    "name": t.get("name"),
                    "tactic_id": None,
                    "tactic": None,
                    "justification": justification,
                    "source": "LLM supposition",
                }
            )

    return enriched


def validate_technique_id(tech_id: str) -> bool:
    """
    Validates if a technique ID exists in the MITRE ATT&CK database.

    Args:
        tech_id: Technique ID (e.g., 'T1059.001')

    Returns:
        True if the technique exists, False otherwise
    """
    _load_data()
    return tech_id in _TECHNIQUES_BY_ID


def get_all_technique_ids() -> List[str]:
    """
    Returns a list of all valid technique IDs in the database.
    Useful for debugging and validation.

    Returns:
        List of technique IDs (e.g., ['T1059', 'T1059.001', ...])
    """
    _load_data()
    return list(_TECHNIQUES_BY_ID.keys())
