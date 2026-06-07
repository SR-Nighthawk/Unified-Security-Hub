# Unified Security Hub

**Unified Security Hub** is a modular, high-fidelity security platform that integrates offensive automation, vulnerability scanning, and threat intelligence under a single interactive web interface. Built heavily on Python native stacks, it offers a clean, multi-tenant ecosystem for tracking global threat campaigns while launching sophisticated network and web application security tests.

## 🚀 Features

The platform is structured into distinct, specialized modules (for a deep dive, see the complete [Module Documentation](MODULE_DOCUMENTATION.md)):

### 1. Autonomous AI Pentesting Pipeline
A comprehensive 4-agent AI offensive automation engine utilizing **Google GenAI**.
*   **High-fidelity exploitation:** Automates context-aware discovery, scanning, and real-world exploitation paths based on OWASP/SANS standards.
*   **Interactive toolchain:** Utilizes `pexpect` for robust, tool-based reconnaissance using native CLI apps.
*   **Visual Evidence:** Automatically generates and associates Playwright screenshots of vulnerable instances.
*   **Robust Delivery:** Automatically writes detailed action-and-response reports upon completing complex attacks without API-quota exhaustion.

### 2. 🌐 Web Vulnerability Scanner (OWASP ZAP)
Integrated Dynamic Application Security Testing (DAST) using the `python-owasp-zap-v2.4` API.
*   Triggers active web scans, passive traffic sniffing, and multi-spider scans.
*   Saves robust JSON/HTML reports to the multi-tenant dashboard.

### 3. 🔍 Network Scanner (Nmap)
Deep-layer asset discovery wrapping the local Nmap installation (`python-nmap`).
*   Configurable scanning arrays (Quick Scan, Regular Scan, Intense Scan).
*   Live web sockets integration using `Flask-SocketIO` to stream scan progress directly to the user interface.

### 4. 🥷 Ransomware Intelligence Module
Operationalizes Ransomware.live intelligence.
*   Actionable threat actor dossiers and real-time victim tracking.
*   Responsive dashboard interface dedicated to current Indicators of Compromise (IoCs).

### 5. 🕸️ Dark Web & APT Threat Intelligence
A background orchestration system using `APScheduler` to monitor specific Advanced Persistent Threat (APT) groups.
*   Identifies active domains and malicious dark web links.
*   Maintains historical link statuses and discovery logs inside an SQLite database.

### 6. 🔐 Multi-Tenant User System & Chat
*   Complete user authentication using `Flask-Login` isolating session reporting and tasks.
*   Persistent chat integrations giving contextual security advice.
*   Premium dark/light mode toggle with vibrant glassmorphism design.

## 🛠️ Technology Stack

*   **Backend:** Python 3, Flask, Flask-SQLAlchemy, Flask-SocketIO
*   **Frontend:** HTML5, CSS (Vanilla Custom CSS), modern JS (socket.io)
*   **Generative AI:** `google-genai`
*   **Security CLI Tools:** Nmap, OWASP ZAP CLI, Nikto (handled via `pexpect`), Playwright
*   **Database:** SQLite (`flask-sqlalchemy`, `flask-migrate`)
*   **Task Management:** `apscheduler`, `eventlet`

## ⚙️ Prerequisites & Installation

### 1. Requirements

Before starting the server, ensure you have the following CLI tools installed and accessible in your system `PATH`:
*   [Nmap](https://nmap.org/download.html)
*   [OWASP ZAP](https://www.zaproxy.org/download/)
*   [Python 3.9+](https://www.python.org/)

### 2. Clone and Install Dependencies

```bash
git clone <repository-url>
cd Unified_Security_Hub

# (Optional) Create a virtual environment
python -m venv venv
venv\Scripts\activate # On Windows

# Install Python requirements
pip install -r requirements.txt
```

### 3. Install Playwright Browsers
The AI Pentesting engine relies heavily on Playwright for reconnaissance and visual evidence.
```bash
playwright install
```

### 4. Environment Variables
Create a `.env` file in the root directory providing your configuration tokens:

```ini
# Flask Secret
SECRET_KEY=your-super-strong-secret-key

# Generative AI Key (For Autonomous Pentest Engine & Chat)
GEMINI_API_KEY=your-google-genai-key
```

## 🏁 How to Run

### Option A: Local Development

```bash
python app.py
```
> **Note:** The server defaults to running on port `5000` via SocketIO wrapper. Access the hub at `http://127.0.0.1:5000/`.

### Option B: 🐳 Docker Deployment (Production)

Deploy the full platform with a single command using Docker Compose:

#### 1. Prerequisites
*   [Docker](https://docs.docker.com/get-docker/) (v20+)
*   [Docker Compose](https://docs.docker.com/compose/install/) (v2+)

#### 2. Configure Environment
```bash
# Copy the template and fill in your API keys
cp .env.example .env
# Edit .env with your GEMINI_API_KEY, NVIDIA_API_KEY, etc.
```

#### 3. Build & Launch
```bash
# Build all containers and start in detached mode
docker compose up -d --build

# View logs
docker compose logs -f app
```

#### 4. Access the Platform
*   **Web Interface:** `http://localhost/` (via Nginx reverse proxy)
*   **Direct Flask:** `http://localhost:5000/` (bypassing Nginx)

#### Services
| Container | Port | Purpose |
|-----------|------|---------|
| `sechub-app` | 5000 (internal) | Flask + Gunicorn application |
| `sechub-nginx` | **80** → app:5000 | Nginx reverse proxy + static files |
| `sechub-tor` | 9050 (internal) | Tor SOCKS5 proxy for dark web intel |
| `sechub-zap` | 8080 (internal) | OWASP ZAP scanner (API mode) |

#### Common Commands
```bash
# Stop all services
docker compose down

# Rebuild after code changes
docker compose up -d --build

# View container status
docker compose ps

# Shell into the app container
docker exec -it sechub-app bash

# Reset everything (⚠️ deletes data volumes)
docker compose down -v
```

## 📂 Project Structure

```text
Unified_Security_Hub/
├── app.py                      # Main entry point and router definition
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Container image definition
├── docker-compose.yml          # Multi-service orchestration
├── gunicorn.conf.py            # Production WSGI server config
├── nginx/nginx.conf            # Reverse proxy configuration
├── .env.example                # Environment variable template
├── backend/
│   ├── core/                   # Central configs, background task queues, report handling
│   ├── dark_web_logic/         # Scripts for mapping APT footprints
│   ├── modules/                # Blueprints for Nmap, ZAP, AI Chat, Ransomware, Pentest
│   ├── apt_worker.py           # Background monitoring thread
│   ├── extensions.py           # Flask db, socket, login initiation
│   └── models.py               # SQLAlchemy Database schemas
├── frontend/
│   ├── static/                 # Custom CSS, JS, and global styles
│   └── templates/              # Jinja2 Layouts and isolated module views
├── database/                   # SQLite payload location
├── sessions/                   # Short-term JSON dumps of AI chats
└── reports/                    # VAPT and pentest results saved in JSON
```


