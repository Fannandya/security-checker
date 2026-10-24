# SPDX-License-Identifier: AGPL-3.0-or-later
# Dockerfile for OSC - Open Security Checker Web UI

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OSC_OUTPUT_DIR=/app/output

WORKDIR /app

# Install curl for healthcheck and minimal networking tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definitions first for layer caching
COPY pyproject.toml requirements.txt README.md ./

# Install OSC and optional web/recon dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[recon,web]"

# Copy source code
COPY osc/ /app/osc/
COPY osc.py /app/osc.py

# Create directory for reports and persistent data
RUN mkdir -p /app/output

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/health || exit 1

CMD ["python", "-m", "osc", "web", "--host", "0.0.0.0", "--port", "8000"]
