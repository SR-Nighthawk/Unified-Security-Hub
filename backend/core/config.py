import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
CHATS_DIR = BASE_DIR / "sessions"

# Ensure directories exist
REPORTS_DIR.mkdir(exist_ok=True)
CHATS_DIR.mkdir(exist_ok=True)

SCAN_PROFILES = {
    "Quick Scan": "-T4 -F -Pn -sV",
    "Regular Scan": "-T4 -Pn -sV",
    "Intense Scan": "-T4 -A -Pn",
}

# ZAP path: configurable via env var for cross-platform support
# Docker/Linux: /usr/bin/zap.sh or use ZAP_API_URL for remote API mode
# Windows: C:\Program Files\ZAP\Zed Attack Proxy\ZAP.exe
DEFAULT_ZAP_PATH = os.getenv("ZAP_PATH", r"C:\Program Files\ZAP\Zed Attack Proxy\ZAP.exe")

# ZAP API mode (Docker): connect to remote ZAP instance via REST API
ZAP_API_URL = os.getenv("ZAP_API_URL", "")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

# Nmap path: auto-detected across platforms
DEFAULT_NMAP_CANDIDATES = [
    os.environ.get("NMAP_PATH", ""),
    # Linux paths (Docker)
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    # Windows paths
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    # Fallback to PATH
    "nmap",
]

# ── Tor Proxy Configuration ──────────────────────────────────
# Docker: TOR_PROXY_HOST=tor, TOR_PROXY_PORT=9050
# Local:  TOR_PROXY_HOST=127.0.0.1, TOR_PROXY_PORT=9150 (Tor Browser)
TOR_PROXY_HOST = os.getenv("TOR_PROXY_HOST", "127.0.0.1")
TOR_PROXY_PORT = os.getenv("TOR_PROXY_PORT", "9150")

TOR_SOCKS_URL = f"socks5://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}"
TOR_SOCKS_H_URL = f"socks5h://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}"
TOR_PROXIES = {
    'http': TOR_SOCKS_H_URL,
    'https': TOR_SOCKS_H_URL,
}
