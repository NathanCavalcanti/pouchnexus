# 🛡️ PouchNexus - SOC Multi-Agent platform

![Python](https://img.shields.io/badge/python-3.12+-blue.svg)
![LangGraph](https://img.shields.io/badge/LangGraph-0.1.15+-green.svg)
![React](https://img.shields.io/badge/React-18+-61DAFB.svg)
![Status](https://img.shields.io/badge/v2.2.0-Security_Hardened-success.svg)

A professional, web-based **Security Operations Center (SOC) Multi-Agent AI Assistant**. **PouchNexus** orchestrates specialized AI agents using **LangGraph** to automate incident triage, enrichment, and reporting.

---

## ✨ New in V2.2 (Security Hardening)

- 🔒 **Full Rate Limiting Coverage**: All 19 API endpoints now protected with calibrated limits via `slowapi`.
- 🛡️ **Input Validation**: Strict regex validation on route params (`file_hash`, `ip`, `domain`, `technique_id`, `incident_id`).
- 🔑 **API Key Masking**: `GET /settings/keys` now returns masked keys (`xxxx***yyyy`) — never exposes secrets.
- 🌐 **CORS Hardening**: `ALLOWED_ORIGINS` env var support; `allow_credentials` disabled with wildcard origins.
- 🧹 **Error Sanitization**: Internal stack traces no longer leak via HTTP responses or stored DB errors.
- 📦 **Pydantic URL Model**: `POST /virustotal/url` replaced `Dict[str,str]` with typed `VtUrlRequest` model.
- 🗑️ **Bulk Delete Cap**: `bulk-delete` limited to 500 IDs per request to prevent accidental data loss.
- 🧠 **Memory Guard**: `_mitre_jobs` in-memory store auto-evicts at 500 entries to prevent unbounded growth.
- 🛡️ **Honeypot V8.1**: Advanced TCP Multi-Flag detection (SYN, ACK, RST, PSH, FIN) included in `examples/`.

---

## 🚀 Installation & Setup

### 1. Prerequisites
- **Python 3.12+**
- **Node.js 18+** (for frontend development/build)
- API Keys for: **Groq** (Primary LLM), **VirusTotal** (Enrichment).

### 2. Environment Setup
```powershell
# Clone the repository
git clone <repo-url>
cd soc-multiagent-assistant

# Create and Activate Virtual Environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install Dependencies
pip install -r requirements.txt
```

### 3. Configuration
1. Copy `.env.example` to `.env`.
2. Open `.env` and configure your keys:
   - `GROQ_API_KEY`: Required for AI analysis.
   - `VIRUSTOTAL_API_KEY`: Required for reputation checks.

---

## 🏃 Running the Platform

Once configured, simply double-click the automation script:
### 📂 **`start_platform.bat`**

This script will:
1. Start the **FastAPI Backend** on `http://localhost:8000`.
2. Start the **React Dashboard** (Vite) on `http://localhost:3000`.

---

## 🔗 Log Ingestion (Webhooks)

| Source | Endpoint | Rate Limit | Description |
| :--- | :--- | :--- | :--- |
| **Generic/Honeypot** | `POST /api/v1/ingest/generic` | 60/min | Supports `skip_analysis` for high-volume logs. |
| **Wazuh** | `POST /api/v1/ingest/wazuh` | 60/min | Endpoint security alerts. |
| **Snort / Suricata** | `POST /api/v1/ingest/snort` | 60/min | Network IDS alerts. |
| **Manual Analysis** | `POST /api/v1/analyze` | 5/min | Direct text input for analysis. |

---

## 🤖 Multi-Agent Architecture (LangGraph)

1.  **IOC Agent**: Extracts indicators (IPs, Hashes, Domains).
2.  **VT Node**: Global reputation enrichment.
3.  **MITRE Agent**: TTP mapping using local Enterprise DB.
4.  **CVE Agent**: Vulnerability validation via NVD.
5.  **Investigation Agent**: DFIR and containment strategy.
6.  **Report Agent**: Structured Executive Summary generation.

---

## ⚙️ CI/CD & Quality
Automated via GitHub Actions:
- **Linting**: Ruff (Python) & ESLint (React).
- **Security**: Bandit security scanning.
- **Docker**: Automated container builds.

**Version**: 2.2.0 | **Status**: Production-Ready Security Assistant (PouchNexus)
**License**: MIT
