# Phase 2C - Minimum Docker lab for triage-api
# Based on ARCHITECTURE.md S13, SECURITY.md S4
FROM python:3.11-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        gcc \
        libpq-dev \
        libffi-dev \
        libyaml-dev \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
COPY app/pyproject.toml ./
COPY app/src/ ./src/
COPY app/alembic/ ./alembic/
COPY app/alembic.ini ./
COPY app/config/ ./config/
COPY app/console/ ./console/
RUN pip install --no-cache-dir -e .
RUN groupadd -r appgroup && useradd -r -g appgroup -d /app -s /sbin/nologin app
RUN chown -R app:appgroup /app
RUN mkdir -p /data && chown -R app:appgroup /data
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1
USER app
EXPOSE 8000
CMD ["uvicorn", "soc_triage.main:create_app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--access-log"]
