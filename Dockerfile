# Gateway image — GitHub webhook + OAuth front-end for review-api.
#
# Build from THIS directory (unlike backend/Dockerfile, which needs the
# repository root): the gateway never reads another component's source, it
# only calls review-api over HTTP.
#
#     docker build -t review-gateway .
#     docker run -p 8080:8080 --env-file .env review-gateway
FROM python:3.12-slim

# No git and no build toolchain on purpose. Unlike backend/mcp-server, this
# service never clones a repository or compiles anything — every package it
# needs ships as a wheel. Fewer packages in the image means fewer CVEs to
# answer for later.

WORKDIR /app

# Dependency metadata and source, then install. Note this does NOT give the
# classic "cache the dependency layer" win, because `pip install .` needs
# the source present — the same shape as Elad's two Dockerfiles. What it
# does buy: anything added below this line can change without triggering a
# reinstall.
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && pip cache purge || true

# --no-cache-dir above matters more here than it looks: pip's download
# cache would otherwise be baked permanently into this layer, growing the
# image by tens of MB that nothing inside a running container will ever read.

# Non-secret defaults only. GITHUB_WEBHOOK_SECRET, GITHUB_OAUTH_CLIENT_SECRET
# and REVIEW_API_KEY are deliberately absent: they arrive at run time from an
# env file or a Kubernetes Secret. Anything written here is readable forever
# by anyone who can `docker history` the image — including from a registry.
ENV REVIEW_API_BASE_URL=http://host.docker.internal:8000 \
    GATEWAY_CORS_ORIGINS=http://localhost:5173 \
    GATEWAY_FRONTEND_URL=http://localhost:5173 \
    GITHUB_OAUTH_REDIRECT_URI=http://localhost:8080/auth/github/callback \
    GATEWAY_DEFAULT_MODE=brief \
    PYTHONUNBUFFERED=1

# Session and trigger storage. Without a volume this lands in the
# container's writable layer and is destroyed on every restart, signing out
# every user. Four slashes: three are SQLAlchemy's scheme separator, the
# fourth is the leading "/" of the absolute path.
#
# SQLite is the DEVELOPMENT answer. It tolerates exactly one writer, so a
# gateway scaled past a single replica needs Postgres via this same variable
# — see docs/12-roadmap.md Phase 2.
ENV GATEWAY_DATABASE_URL=sqlite:////data/gateway.db

# --- hardening: drop root -------------------------------------------------
# Containers run as root unless told otherwise. A flaw in the gateway would
# then be root inside the container, next to a mounted volume. A fixed UID
# (not just a name) is what lets Kubernetes assert the same identity in a
# securityContext (runAsUser: 10001, runAsNonRoot: true).
#
# /data is created and owned here so the unprivileged user can write the
# database. Caveat worth knowing: a bind mount from the host replaces this
# directory and brings the host's ownership with it, which can make it
# unwritable. Named volumes inherit the image's ownership and just work.
RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin gateway \
    && mkdir -p /data \
    && chown -R gateway:gateway /data /app
USER gateway

VOLUME /data

# Documentation only — EXPOSE opens nothing. What actually decides who can
# reach this service is `-p` at run time, or the Kubernetes Service in front
# of it. Binding 0.0.0.0 inside the container is likewise confined to the
# container's own network namespace.
EXPOSE 8080

# Uses the interpreter already in the image rather than adding curl, keeping
# the package count down. Kubernetes ignores this and uses its own liveness
# and readiness probes instead.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health').read()"]

# Exec form, not shell form. This runs Python directly as PID 1, so SIGTERM
# from `docker stop` or a Kubernetes pod eviction reaches it and it can shut
# down cleanly. The shell form would put /bin/sh at PID 1, which does not
# forward the signal — the container would hang until SIGKILL.
CMD ["python", "-m", "review_gateway.app"]
