# ═══════════════════════════════════════════════════════════════
# Gunicorn Configuration for Unified Security Hub
# ═══════════════════════════════════════════════════════════════
#
# IMPORTANT: Flask-SocketIO with in-memory state (SCAN_TASKS,
# PENTEST_SESSIONS) requires a SINGLE worker. If you scale to
# multiple workers, you MUST switch to a Redis message queue
# for SocketIO and move state to Redis/DB.
# ═══════════════════════════════════════════════════════════════

import os

# ── Server Socket ─────────────────────────────────────────────
# Railway / Render inject a PORT env variable — honour it
_port = os.getenv("PORT", "5000")
bind = os.getenv("GUNICORN_BIND", f"0.0.0.0:{_port}")

# ── Worker Configuration ──────────────────────────────────────
# eventlet worker class is REQUIRED for Flask-SocketIO
worker_class = "eventlet"

# Single worker — SocketIO and background tasks share in-memory
# state (SCAN_TASKS, PENTEST_SESSIONS, APScheduler jobs).
workers = 1

# ── Timeouts ──────────────────────────────────────────────────
# Long timeout for Nmap/ZAP scans that can run 5+ minutes
timeout = 600

# Graceful shutdown period
graceful_timeout = 30

# Keep-alive for persistent connections (SocketIO long-poll)
keepalive = 65

# ── Logging ───────────────────────────────────────────────────
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info")

# ── Process Naming ────────────────────────────────────────────
proc_name = "sechub"

# ── Security ──────────────────────────────────────────────────
# Limit request sizes (16MB for file uploads in AI chat)
limit_request_body = 16 * 1024 * 1024
