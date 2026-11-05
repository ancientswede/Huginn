# Huginn in a container (part of Huginn, AGPL-3.0-or-later). Only the Huginn side: the honeypot itself belongs on its
# own isolated VM/LXC (install-honeypot.sh), never next to your other containers.
#   docker compose up -d          (see docker-compose.yml and "Run Huginn in Docker" in README.md)
FROM python:3.13-slim

LABEL org.opencontainers.image.title="Huginn" \
      org.opencontainers.image.description="Attacker intelligence for a homelab honeypot" \
      org.opencontainers.image.source="https://github.com/ancientswede/Huginn" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Huginn itself needs only the Python standard library; ssh pulls the honeypot's read-only export.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --user-group --home-dir /data --no-create-home --shell /usr/sbin/nologin huginn \
 && install -d -o huginn -g huginn -m 750 /data

WORKDIR /app
COPY app.py ./
COPY static/ ./static/
COPY docker/entrypoint.sh /usr/local/bin/huginn
COPY docker/healthcheck.py ./

# Everything Huginn keeps lives in /data: database, session recordings, its SSH key, the honeypot's host key.
ENV HUGINN_BASE=/data HUGINN_BIND=0.0.0.0 HUGINN_PORT=8095 HOME=/data \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER huginn
VOLUME /data
EXPOSE 8095

HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 CMD ["python3", "/app/healthcheck.py"]

ENTRYPOINT ["huginn"]
CMD ["serve"]
