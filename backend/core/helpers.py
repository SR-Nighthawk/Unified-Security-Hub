import socket
import os
import nmap
import json
from .config import DEFAULT_NMAP_CANDIDATES, REPORTS_DIR

# Map old tool identifiers to new ones for backward compatibility
TOOL_NAME_MAP = {
    "NMAP": "NETWORK",
    "ZAP": "WEBAPP",
}

def normalize_tool_name(tool):
    """Normalize legacy tool names (NMAP→NETWORK, ZAP→WEBAPP)."""
    return TOOL_NAME_MAP.get(tool, tool)

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def build_port_scanner():
    last_error = None
    for candidate in DEFAULT_NMAP_CANDIDATES:
        if not candidate:
            continue
        try:
            if os.path.isabs(candidate) and not os.path.exists(candidate):
                continue
            return nmap.PortScanner(nmap_search_path=(candidate,))
        except Exception as exc:
            last_error = exc
    raise RuntimeError("Nmap executable not found.") from last_error

def get_report_data(report_id):
    report_file = REPORTS_DIR / f"{report_id}.json"
    if not report_file.exists():
        return None
    try:
        with open(report_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Normalize legacy tool names
        if "tool" in data:
            data["tool"] = normalize_tool_name(data["tool"])
        return data
    except:
        return None

