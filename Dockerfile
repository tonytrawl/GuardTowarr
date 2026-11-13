# GuardTowarr: lightweight media-stack monitor.
# Pure standard-library Python; no third-party packages needed for the server.
FROM python:3.12-slim

# Container mode: run web-only (no system tray) and persist data to /config.
ENV GUARDTOWARR_DOCKER=1 \
    GUARDTOWARR_CONFIG_DIR=/config \
    GUARDTOWARR_PORT=9595 \
    PYTHONUNBUFFERED=1

# The slim base ships without timezone data, so the TZ env var is ignored and
# timestamps fall back to UTC. Install tzdata so users can set e.g.
# TZ=America/Los_Angeles and have logs/history show their local time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY monitor.py webpage.html /app/

# Settings, dismissed issues, and history live here. Mount a volume to persist them.
VOLUME ["/config"]

# 9595: the main dashboard. 9596: the optional, restricted Remote-access port
# (only used if you enable it in Settings). Exposing it just makes it selectable
# in Docker Desktop / tooling; you still choose whether to publish it.
EXPOSE 9595 9596

CMD ["python", "monitor.py"]
