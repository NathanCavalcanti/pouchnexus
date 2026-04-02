# 🏗️ Build Report: SOC Platform V2.0 Implementation

This document details how the Backend and Frontend of the SOC Multi-Agent Platform were constructed, the design patterns used, and the integration between them.

## 1. Backend Construction (FastAPI + LangGraph)

The backend acts as the orchestration engine, handling API requests, database persistence, and the execution of AI agents.

### Core Technologies:

- **FastAPI:** Chosen for its high performance, native support for `asyncio`, and automatic OpenAPI (Swagger) documentation.
- **LangGraph:** Used to manage the complex state machine of the multi-agent pipeline. It allows for cyclical or linear workflows where state is passed between specialized agents.
- **Supabase:** PostgreSQL cloud database. Provides persistent, scalable storage with a generous free tier. Accessed via the official `supabase-py` SDK.
- **Pydantic:** Used for data validation and settings management (via `.env`).

### Key Design Choices:

- **Asynchronous Jobs:** Incident analysis is triggered via a `POST` request which returns immediately with an `incident_id`. The actual AI processing runs in a `FastAPI.BackgroundTasks`, allowing the UI to remain responsive.
- **State Management:** The `SOCState` TypedDict is the "single source of truth" passed through the LangGraph. Each agent (IOC, MITRE, CVE, etc.) contributes its findings to this state.
- **Enrichment Deduplication:** Optimized VirusTotal calls by correlating hashes (MD5, SHA1, SHA256) to prevent redundant API usage and quota exhaustion.

---

## 2. Frontend Construction (React + Vite)

The frontend provides a premium, real-time dashboard for security analysts to monitor and trigger investigations.

### Core Technologies:

- **React (Vite):** Vite was used as the build tool for its extremely fast development server and optimized production bundles.
- **Vanilla CSS + CSS Variables:** Instead of heavy frameworks like Tailwind, we used native CSS variables for a custom, high-performance design system Supporting "Glassmorphism" and "Dark Mode" aesthetics.
- **Lucide React:** A consistent icon set for professional look and feel.
- **React Router:** For seamless client-side navigation between Dashboard, Incidents, and Settings.

### Key Design Choices:

- **Polling Strategy:** The interface uses an intelligent polling mechanism to refresh the list of incidents. The interval is user-configurable (10s, 5m, etc.) to balance real-time awareness with server load.
- **Component Modularity:**
  - `IncidentPanel.jsx`: A slide-over detail view that uses conditional rendering to show analysis results as they become available.
  - `api.js`: A centralized Axios-like wrapper around `fetch` that handles common logic (like the 204 No Content fix).
- **Dynamic Design:** Implemented interactive cards, status badges, and an "Easter Egg" debug mode (triggered by 5 clicks on the title) to keep the dev-experience high.

---

## 3. The Bridge (The API Contract)

The two parts communicate via a RESTful API:

1.  **Ingestion:** Security tools (Honeypots, Wazuh) hit `/api/v1/ingest/...` endpoints.
2.  **Observation:** The Frontend queries `/api/v1/incidents` to list events.
3.  **Action:** The Frontend triggers manual analysis via `/api/v1/analyze`.
4.  **Configuration:** The Frontend reads/writes `.env` variables via `/api/v1/settings/keys`.

## 4. Operational Setup

- **Local Dev:** `start_platform.bat` automates the dual-window startup.
- **Production:** `Dockerfile` uses a multi-stage build to compile the React assets and serve them via FastAPI static mounting, resulting in a single container image.
