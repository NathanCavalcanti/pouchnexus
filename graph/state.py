# graph/state.py

from typing import Dict, Optional, Any
from pydantic import BaseModel


class SOCState(BaseModel):
    """
    Global state object shared across all agents in the SOC pipeline.
    Each agent adds or modifies fields during the LangGraph execution.
    """

    # Initial input
    input_text: str

    # Agent outputs
    iocs: Optional[Dict[str, Any]] = None
    ttps: Optional[Dict[str, Any]] = None
    cves: Optional[Dict[str, Any]] = None
    investigation_plan: Optional[Dict[str, Any]] = None

    # Final report
    report: Optional[Dict[str, Any]] = None
    report_text: Optional[str] = None
