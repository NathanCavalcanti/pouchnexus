# graph/graph_builder.py
from __future__ import annotations

from typing import Any, Dict

from langgraph.graph import StateGraph, END

from graph.state import SOCState
from agents.ioc_agent import run_ioc_agent
from agents.mitre_agent import run_mitre_agent
from agents.cve_agent import run_cve_agent
from agents.investigation_agent import run_investigation_agent
from agents.report_agent import run_report_agent, render_report_text


# ===== GRAPH NODES =====


def node_iocs(state: SOCState) -> Dict[str, Any]:
    """
    IOC Agent Node: extracts IOCs from incident text.
    """
    iocs = run_ioc_agent(state.input_text)
    return {"iocs": iocs}


def node_mitre(state: SOCState) -> Dict[str, Any]:
    """
    MITRE Agent Node: maps TTPs from text and IOCs.
    """
    ttps = run_mitre_agent(state.input_text, state.iocs)
    return {"ttps": ttps}


def node_cve(state: SOCState) -> Dict[str, Any]:
    """
    CVE Agent Node: proposes CVEs from text and MITRE context.
    """
    cves = run_cve_agent(
        software_info=state.input_text,
        mitre_context=state.ttps,
    )
    return {"cves": cves}


def node_investigation(state: SOCState) -> Dict[str, Any]:
    """
    Investigation Agent Node: generates a DFIR investigation and containment plan.
    """
    plan = run_investigation_agent(
        event_text=state.input_text,
        iocs=state.iocs,
        ttps=state.ttps,
        cves=state.cves,
    )
    return {"investigation_plan": plan}


def node_report(state: SOCState) -> Dict[str, Any]:
    """
    Report Agent Node:
    - Generates a JSON report
    - Converts it to structured plain text (report_text)
    """
    report_json = run_report_agent(
        incident_text=state.input_text,
        iocs=state.iocs,
        mitre_context=state.ttps,
        cve_context=state.cves,
        investigation_context=state.investigation_plan,
    )

    if "parse_error" in report_json:
        report_text = (
            "Could not generate structured report from JSON.\n"
            "Model response:\n\n"
            f"{report_json.get('raw_response', '')}"
        )
    else:
        report_text = render_report_text(report_json)

    return {
        "report": report_json,
        "report_text": report_text,
    }


# ===== GRAPH CONSTRUCTION =====


def create_graph():
    """
    Builds and compiles the LangGraph workflow for the SOC system.
    """

    workflow = StateGraph(SOCState)

    # Register nodes
    workflow.add_node("ioc_agent", node_iocs)
    workflow.add_node("mitre_agent", node_mitre)
    workflow.add_node("cve_agent", node_cve)
    workflow.add_node("investigation_agent", node_investigation)
    workflow.add_node("report_agent", node_report)

    # Define flow
    workflow.set_entry_point("ioc_agent")
    workflow.add_edge("ioc_agent", "mitre_agent")
    workflow.add_edge("mitre_agent", "cve_agent")
    workflow.add_edge("cve_agent", "investigation_agent")
    workflow.add_edge("investigation_agent", "report_agent")
    workflow.add_edge("report_agent", END)

    # Compile graph
    return workflow.compile()
