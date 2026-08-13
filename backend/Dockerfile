# Mykronos backend (spec 15 §2, D-038).
#
# Build from the REPOSITORY ROOT, not from backend/:
#
#   docker build -f backend/Dockerfile -t mykronos-backend .
#
# The workflow templates live at the repo root and are read from disk at
# startup, so the build context has to include them. A Dockerfile that cannot
# be built from the directory it sits in is worth saying out loud.
#
# Multi-stage so the runtime image carries the wheel and its dependencies but
# not the build toolchain. A smaller image is a smaller thing for the
# container scanner to find CVEs in, and this platform scans its own images.

FROM python:3.13-slim AS build

WORKDIR /src
RUN pip install --no-cache-dir --quiet build

# Dependency metadata before source, so editing a module does not invalidate
# the layer that resolved the dependencies.
COPY backend/pyproject.toml backend/README.md ./
COPY backend/mykronos ./mykronos

RUN python -m build --wheel --outdir /dist


FROM python:3.13-slim AS runtime

# Non-root, created before anything else so the layers it owns are correct
# from the start. This process holds the GitHub App key path, every repo's
# ingestion token and the lake; root inside the container buys nothing it
# needs and costs a container escape's worth of difference.
RUN useradd --create-home --uid 10001 mykronos

# curl is for the healthcheck, and is installed deliberately. The last
# healthcheck written for this platform used a binary the image did not ship
# and reported a working service as unhealthy for eleven minutes.
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir --quiet /tmp/*.whl && rm -f /tmp/*.whl

# The lake, the write-ahead buffer and the operational database all live here.
# Mounted as a volume in compose: without one, a deploy destroys every
# finding, decision and token the platform has recorded.
RUN mkdir -p /data && chown mykronos:mykronos /data
VOLUME ["/data"]

COPY --chown=mykronos:mykronos workflow-templates /app/workflow-templates
COPY --chown=mykronos:mykronos oracle-policy-v1.yaml maturity-model-v1.yaml /app/

USER mykronos
WORKDIR /app

ENV MYKRONOS_DATALAKE_DIR=/data/datalake \
    MYKRONOS_DATABASE_URL=sqlite:////data/mykronos.db \
    MYKRONOS_WORKFLOW_TEMPLATES_DIR=/app/workflow-templates \
    MYKRONOS_ORACLE_POLICY_PATH=/app/oracle-policy-v1.yaml \
    MYKRONOS_MATURITY_MODEL_PATH=/app/maturity-model-v1.yaml \
    PYTHONUNBUFFERED=1

EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8100/healthz || exit 1

CMD ["python", "-m", "uvicorn", "mykronos.main:app", \
     "--host", "0.0.0.0", "--port", "8100", "--log-level", "info"]
