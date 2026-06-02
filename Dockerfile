FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src

# Build-Zeitstempel (von der CI gesetzt) -> zur Laufzeit lesbar (Start-Meldung).
ARG BUILD_TIME=unknown
ENV LOGWATCHER_BUILD_TIME=$BUILD_TIME

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY healthcheck.py ./healthcheck.py

VOLUME ["/data"]

# Healthcheck: der Loop schreibt alle HEARTBEAT_INTERVAL_SECONDS (Default 60s) einen
# Heartbeat; hier gilt er als ungesund, wenn er älter als HEALTH_MAX_STALENESS_SECONDS ist.
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
    CMD python /app/healthcheck.py || exit 1

CMD ["python", "-m", "watcher.main"]
