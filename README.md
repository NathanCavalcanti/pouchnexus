# 🛡️ Multi-Agent Automated SOC Analyst - Web Platform V2.0

![Python](https://img.shields.io/badge/python-3.12+-blue.svg)
![LangGraph](https://img.shields.io/badge/LangGraph-0.1.15+-green.svg)
![React](https://img.shields.io/badge/React-18+-61DAFB.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-v2.0-success.svg)

A professional, web-based **Security Operations Center (SOC) Multi-Agent AI Assistant**. This platform orchestrates specialized AI agents using **LangGraph** to automate incident triage, enrichment, and reporting, now featuring **Active Reconnaissance Detection**.

---

## ✨ Key Features (V2.0)

### 🚨 Smart Detection & Response
- ⚡ **Lightweight Enrichment** - Automatically extracts attacker IPs from scans and enrichs them via **VirusTotal API** without consuming LLM tokens.
- 🏷️ **Attack Categorization** - Automatic labeling of incidents as `Network IDS`, `Endpoint Alert`, or `Log Analysis` with distinct visual coding.

### 📊 Modern Dashboard & UX
- 🌐 **Real-time Interface** - Smooth React dashboard with **Silent Refresh** (updates background data without UI flickering).
- 🔍 **Advanced Filtering** - Filter by **Source, Status, and Attack Type**. Control row density (**20, 50, 200, or All**).
- 🛠️ **Enrichment Tools** - Dedicated pages for deep-dive investigations:
    - **MITRE ATT&CK**: Search techniques and sub-techniques.
    - **CVE Lookup**: Real-time NVD vulnerability validation.
    - **VirusTotal**: Global reputation check for IPs, Domains, and Hashes.

### ⚙️ Administration & Security
- 🔑 **API Management** - Centralized UI to configure Groq, Gemini, VirusTotal, and NVD keys.
- 🐞 **Developer Debug Mode** - Hidden "Easter Egg" menu (click Settings title 5 times) to toggle verbose LLM logging.
- 🗑️ **Bulk Operations** - Select and delete multiple incidents at once.

---

## 🚀 Quick Start (Windows)

1. Clone the repository.
2. Create your `.env` file (copy from `.env.example`).
3. Double-click **`start_platform.bat`**.

This launches the FastAPI Backend (Port 8000) and Vite Frontend (Port 3000) automatically.

---

## 🔗 Log Ingestion (Webhooks)

| Source | Endpoint | Description |
| :--- | :--- | :--- |
| **Generic/Honeypot** | `POST /api/v1/ingest/generic` | Supports `skip_analysis` for high-volume automated events. |
| **Wazuh** | `POST /api/v1/ingest/wazuh` | Ingest endpoint alerts and full logs. |
| **Snort / Suricata** | `POST /api/v1/ingest/snort` | Captures Network IDS signatures. |
| **Manual** | `POST /api/v1/analyze` | Manual incident text input. |

---

## 🤖 Multi-Agent Architecture (LangGraph)

1.  **IOC Agent**: Extracts indicators (IPs, Hashes, Domains).
2.  **Enrichment Node**: Queries VirusTotal API for reputation.
3.  **MITRE Agent**: Maps logs to TTPs using local Enterprise database.
4.  **CVE Agent**: Validates vulnerabilities via NVD.
5.  **Investigation Agent**: Drafts DFIR containment plans.
6.  **Report Agent**: Compiles the final SOC Executive Summary.

---

## ⚙️ CI/CD Pipeline

Automated via GitHub Actions (`.github/workflows/pipeline.yml`):
- **Lingting**: Ruff & ESLint.
- **Security**: Bandit scan.
- **Docker**: Automated build verification.

---

**Version**: 2.0.0 | **Status**: Stable & Active Defense Ready
**License**: MIT - Created for AI-driven SOC automation demonstration.
