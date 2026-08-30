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

# Security updates for the base image, and no curl.
#
# The platform's own container scan found curl and libcurl4 carrying four
# high-severity advisories in this image - installed only so a healthcheck
# could run, in an image that ships a Python interpreter perfectly capable of
# making an HTTP request. Removing a package removes every CVE it will ever
# have.
#
# The rule that put curl here still holds and is not being broken: a
# healthcheck must not use a binary the image does not ship. `python` is the
# entrypoint of this image, so it is the one binary guaranteed present.
RUN apt-get update -qq \
    && apt-get upgrade -y -qq \
    && rm -rf /var/lib/apt/lists/*

# pip and setuptools from the base image, not from this project's
# dependencies. The platform's own scan found the last remaining findings
# there: setuptools (CVE-2025-47273, path traversal) and the msgpack pip
# vendors (GHSA-6v7p-g79w-8964). Neither appears in pyproject.toml, which is
# exactly why they went unnoticed - a dependency audit of this project would
# never have looked at them.
RUN pip install --no-cache-dir --quiet --upgrade pip setuptools

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir --quiet /tmp/*.whl && rm -f /tmp/*.whl

# pip goes once it has done its job, following the same rule as npm in the
# frontend image: removing a package removes every CVE it will ever have.
#
# Upgrading was not enough here and the reason is worth knowing. pip carries
# its dependencies *vendored*, and declares their versions in
# `_vendor/vendor.txt` - which is what Trivy reads. Upgrading setuptools to
# 84.0.0 left that file still saying `setuptools==70.3.0` and
# `msgpack==1.1.2`, so the findings persisted against an image that no longer
# had the vulnerable code. Both readings are defensible; the way to satisfy
# both is for the package not to be there.
#
# Nothing at runtime needs pip: the entrypoint is uvicorn, and every
# dependency is already installed. `! command -v pip` fails the build if it
# survives, so a base-image change cannot quietly reinstate it.
RUN python -m pip uninstall -y -q pip \
    && rm -rf /usr/local/lib/python3.13/site-packages/pip \
              /usr/local/bin/pip /usr/local/bin/pip3 \
    && ! command -v pip

# The lake, the write-ahead buffer and the operational database all live here.
# Mounted as a volume in compose: without one, a deploy destroys every
# finding, decision and token the platform has recorded.
RUN mkdir -p /data && chown mykronos:mykronos /data
VOLUME ["/data"]

COPY --chown=mykronos:mykronos workflow-templates /app/workflow-templates
# All four reviewed policy files, not two. `governance-policy-v1.yaml` and
# `stride-map-v1.yaml` were absent from the image entirely, and their
# loaders fell back to a path relative to the module - the repo root from
# a checkout, the site-packages parent from a wheel. Production logged
# 'no score computed' and carried on with an empty weight table.
COPY --chown=mykronos:mykronos oracle-policy-v1.yaml maturity-model-v1.yaml \
     governance-policy-v1.yaml stride-map-v1.yaml /app/

USER mykronos
WORKDIR /app

ENV MYKRONOS_DATALAKE_DIR=/data/datalake \
    MYKRONOS_DATABASE_URL=sqlite:////data/mykronos.db \
    MYKRONOS_WORKFLOW_TEMPLATES_DIR=/app/workflow-templates \
    MYKRONOS_ORACLE_POLICY_PATH=/app/oracle-policy-v1.yaml \
    MYKRONOS_MATURITY_MODEL_PATH=/app/maturity-model-v1.yaml \
    MYKRONOS_GOVERNANCE_POLICY_PATH=/app/governance-policy-v1.yaml \
    MYKRONOS_STRIDE_MAP_PATH=/app/stride-map-v1.yaml \
    PYTHONUNBUFFERED=1

EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8100/healthz', timeout=3).status == 200 else 1)"]

CMD ["python", "-m", "uvicorn", "mykronos.main:app", \
     "--host", "0.0.0.0", "--port", "8100", "--log-level", "info"]
