# Phase 2C — Minimum Docker lab for triage-api
# Based on ARCHITECTURE.md §13, SECURITY.md §4
FROM python:3.11-slim-bookworm

# Security: pinned tag, minimal base, non-root user
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install build dependencies only if needed (slim has minimal gcc/lib); pin to lab needs
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        gcc \
        libpq-dev \
        libffi-dev \
        libyaml-dev \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy package manifest and source
COPY app/pyproject.toml ./
COPY app/src/ ./src/

# Install package (editable not needed in container; install as package)
RUN pip install --no-cache-dir -e .

# Non-root user (security baseline)
RUN groupadd -r appgroup && useradd -r -g appgroup -d /app -s /sbin/nologin app
RUN chown -R app:appgroup /app

# Persistent SQLite storage mounted at /data
RUN mkdir -p /data && chown -R app:appgroup /data

# Healthcheck on the FastAPI liveness route. The route is registered without the
# /api/v1 prefix in app/src/soc_triage/api/health.py, so the real URL is /health.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

USER app

# Default: bind to all interfaces for Docker lab preview compatibility
EXPOSE 8000

# Command: uvicorn with explicit bind
CMD ["uvicorn", "soc_triage.main:create_app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--access-log"]
