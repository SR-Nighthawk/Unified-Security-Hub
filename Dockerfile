# ═══════════════════════════════════════════════════════════════
# Unified Security Hub — Production Dockerfile
# ═══════════════════════════════════════════════════════════════

FROM python:3.11-slim AS base

# Metadata
LABEL maintainer="Unified Security Hub"
LABEL description="Unified Security Hub — All-in-One Security Operations Platform"

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ── System Dependencies ──────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Nmap for network scanning
    nmap \
    # Nikto dependencies (Perl + required modules)
    perl \
    libnet-ssleay-perl \
    libcrypt-ssleay-perl \
    libwhisker2-perl \
    libio-socket-ssl-perl \
    # Playwright system deps
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    libxshmfence1 \
    libx11-xcb1 \
    libxcb1 \
    # General build/network utils
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# ── Install Nikto ─────────────────────────────────────────────
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# ── Application Setup ────────────────────────────────────────
WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn==21.2.0 eventlet

# Install Playwright browsers (Chromium only to save space)
RUN playwright install chromium \
    && playwright install-deps chromium

# Copy application code
COPY . .

# ── Create required directories ──────────────────────────────
RUN mkdir -p \
    /app/database \
    /app/backend/reports \
    /app/backend/reports/screenshots \
    /app/backend/sessions \
    /app/data \
    /app/static/screenshots \
    /app/frontend/static/reports \
    /app/frontend/static/screenshots

# ── Create non-root user for security ─────────────────────────
RUN groupadd -r sechub && useradd -r -g sechub -d /app sechub \
    && chown -R sechub:sechub /app

USER sechub

# ── Default ENV for production platforms ─────────────────────
# These can be overridden by the platform's environment variables panel
ENV SOCKETIO_ASYNC_MODE=eventlet

# ── Expose & Run ──────────────────────────────────────────────
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:${PORT:-5000}/ || exit 1

# Production entry point via Gunicorn
# Shell form so that $PORT is expanded at runtime (Railway/Render inject PORT)
CMD gunicorn --config gunicorn.conf.py app:app
