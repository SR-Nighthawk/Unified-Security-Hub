# Unified Security Hub - Complete Module Documentation

This document provides an in-depth architectural and functional overview of the core modules powering the **Unified Security Hub**. The platform is logically divided into multiple specialized Python Blueprints located in the `backend/modules/` directory, orchestrating offensive automation, threat intelligence, and vulnerability analytics.

---

## 1. Authentication & Multi-Tenant Module (`auth_module.py`)
**Purpose:** Handles secure user authentication, session management, and data isolation for the multi-tenant architecture.
- **Core Functionality:** Utilizes `Flask-Login` combined with SQLAlchemy to manage user sessions. Support for user registration, encrypted password storage (via Werkzeug), login, and secure logouts.
- **Data Isolation:** Ensures that security scans, AI chat histories, and platform reports are exclusively accessible to the user who created them (`owner_id`), forming the foundation of a multi-tenant platform.
- **Endpoints:** `/login`, `/logout`, `/profile`, `/api/auth/login`, `/api/auth/register`.

---

## 2. AI Chat & Reporting Module (`ai_module.py`)
**Purpose:** Powers the "Cyber Sentinel AI" – an advanced cybersecurity expert assistant built using Google GenAI / NVIDIA API integrations.
- **LLM Integrations:** Seamlessly supports multiple AI models such as NVIDIA's LLaMa/Nemotron/Qwen and Google's Gemini-2.5/2.0-Flash to construct a continuous chat context.
- **Key Features:**
    - Contextual security advice based on uploaded reports.
    - Automatic explanation of CVEs, MITRE ATT&CK techniques, and threat actor details.
    - AI-generated executive summaries (`/api/ai/summary`) appended to completed Nmap and ZAP scan reports.
- **Data Storage:** Stores persistent chat sessions as JSON objects in the local workspace, tightly coupled with the active user's session.

---

## 3. Network Scanner Module (`nmap_module.py`)
**Purpose:** Deep-layer asset discovery wrapping the system-native Nmap execution suite via `subprocess`.
- **Core Functionality:** Provides asynchronous execution of network scans avoiding blocking the main server thread.
- **Sanitization:** Implements an advanced URL sanitization routine `sanitize_target()` to safely convert complex user input (e.g., `https://example.com:8443/app`) into an enforceable CIDR, IP or hostname before launching scans.
- **Scan Profiles:** Supports custom scan intensities (`Quick Scan`, `Regular Scan`, `Intense Scan`).
- **Telemetry & Results:** Outputs in real-time, extracts live progress matching STDOUT polling, parses the generated XML file, and translates the data into an organized JSON schema including identified hosts, open ports, protocols, and raw service banners.

---

## 4. Web Vulnerability Scanner Module (`zap_module.py`)
**Purpose:** Integrates the OWASP ZAP (Zed Attack Proxy) Dynamic Application Security Testing (DAST) engine.
- **Job Configuration:** Automatically generates ZAP Automation Framework YAML dynamically to direct spidering, AJAX spidering, and active scanning.
- **Automated Authentication:** Injects login form payloads dynamically when valid authentication parameters and targets are supplied, enabling authenticated deep-crawling capabilities.
- **High-Fidelity Action:** Exerts "insane" level active thresholds based on configuration.
- **Outcome:** Parses the legacy HTML ZAP reports via BeautifulSoup, restructuring risk scores (High/Medium/Low/Info), attack payloads, and evidence lines into standardized JSON report blueprints within the `reports/` directory.

---

## 5. Security Analytics Module (`analytics_module.py`)
**Purpose:** Serves as the correlation engine bridging isolated network and web scanner tools together.
- **Correlation Mapping:** Synthesizes `Nmap` output maps with `ZAP` vulnerability triggers to assess combined threat risks. It adjusts vulnerability tracking based on situational awareness (e.g., scoring critical vectors if Web Application Firewalls (WAF) are bypassed).
- **Attack Graph Generation:** Dynamically writes custom Mermaid.js visualization syntax establishing potential step-by-step external attack pathways connecting open ports, found services, and web exploitation points.
- **Persistent Analytics Dashboard:** Generates trend graphs comparing findings over the last 7 days and displays global statistical distribution for an overarching snapshot.

---

## 6. Autonomous AI Pentesting Pipeline (`pentest_module.py`)
**Purpose:** A robust 4-agent autonomous pipeline combining custom native Python exploitation and external tool reconnaissance to execute simulated SANS Top 25 and OWASP Top 10 vulnerabilities.
- **Tool Orchestration:** Invokes `Nmap` and `Nikto` robustly by circumventing OS PTY limits utilizing `pexpect` logic for raw STDOUT extraction.
- **Native Exploitation Coverage:** Capable of natively validating vulnerabilities such as:
    - **A01 IDOR & CORS:** Missing access limits and malicious origin reflection tests.
    - **A03 Injections:** Pattern matching for blind and error-based SQLi (SQL Injection), Command Injections, Server Side Template Injection (SSTI), and Reflected XSS escapes.
    - **A05 Misconfigurations:** Local File Inclusion/Path Traversal probes, sensitive file enumeration (`.env`, `.git/config`, `backup.sql`, `docker-compose.yml`), and unintended open HTTP methods (PUT/DELETE/TRACE).
    - **A07 Default Credentials:** Attempts brute-forcing default and supplied credential chains with lockout detection logic.
    - **A10 SSRF:** Internal AWS metadata and localhost mapping proxy probes.
- **Validation Engine Limits:** Features an advanced `AIRateLimiter` to proactively identify and suspend tasks upon receiving HTTP `429 Too Many Requests` when leveraging GenAI constraints. Employs stringent deduplication constraints. Only evidence-proven responses are appended to the JSON records.

---

## 7. Ransomware Intelligence Engine (`ransomware_module.py`)
**Purpose:** Operationalizes Dark Web Threat Intelligence using the `Ransomware.live` Pro API to keep up with contemporary Advanced Persistent Threats and their victims.
- **Data Ingestion:** Paginates and commits historic and real-time records into local SQLite relations (`RansomwareGroup` and `RansomwareVictim`). Tracks target countries, targeted sectors, post URLs, website availability, and screenshots.
- **Watchlist Telegram Alerting:** Features an active background rule-listener. When ingested threat actors publish compromises matching user-defined thresholds (e.g., a specific sector or targeted country), real-time notification traces are dispatched to connected Telegram chatbots.
- **Proxy Views:** Exposes proxy API layers to distribute Threat Group Dossiers, associated Indicators of Compromises (IoCs), known YARA rules, and dark-web ransom negotiations directly to the UI dashboards.
