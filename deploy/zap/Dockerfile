# The ZAP scanner the demo-and-dast lane runs: upstream's weekly ZAP, on a
# slim Alpine JRE instead of upstream's Debian.
#
# Why not Debian any more. Until 2026-10-18 this file was upstream's weekly
# image with Debian's fixes applied and the browser, X server, compiler, SSH
# client, Webswing and libcups removed (#855, #860, #925). That took HIGH and
# CRITICAL from 274 to under 90, and what was left could not go: with a
# current Trivy DB (0.73.0, 2026-10-18) the derivative still carried 76 HIGH,
# every one in a Debian trixie package with no Debian fix -- python3.13,
# util-linux, curl, perl, ncurses, systemd -- and several of those are in
# Debian's Essential set, so no purge can take them. The standing instruction
# (2026-10-11) is to fix a no-fix CVE at the code level, and for a base image
# that means not shipping the base. ZAP is Java plus a few Python scripts; it
# needs no Debian at all.
#
# **The `upstream` FROM is still the estate's one ZAP pin (D-128).** ZAP itself
# -- the jar, lib/, the add-ons in plugin/, the wrapper scripts zap-api-scan.py,
# zap-baseline.py, zap-full-scan.py and zap_common.py, and the scan policies
# and scripts under ~/.ZAP_D -- is copied out of that exact image rather than
# fetched again from the release zip and the zaproxy repository. So the
# scanner is byte for byte the one upstream built and TheHub's `zap` resource
# runs (deploy/concourse/pipelines/thehub.yml pins the same digest, and
# test_pipeline_conformance.py holds the two equal): the same ZAP version, the
# same add-on versions, the same scripts, with no second set of pins to drift
# from the first. The tag is cosmetic; the digest moves only by editing it.
# Only the files are taken: none of that image's Debian packages reach the
# image built here.
FROM ghcr.io/zaproxy/zaproxy:weekly@sha256:4ec932d24ee6fa7181333a719d519cdebf92df541058d48041ce3358528cd0ea AS upstream

# What MyKronos uses ZAP for, which is what decides what is carried over:
#
#   zap.sh -daemon       the API on the compose network; the lane drives the
#                        traditional spider, the active scan, the replacer and
#                        the custompayloads add-on (a marketplace install at
#                        run time) through it
#   zap-api-scan.py      the OpenAPI scan, in a one-off `docker run` with
#                        /zap/wrk mounted
#   zap-baseline.py      not run by this repository, kept working
#   curl                 the compose healthcheck and the image's own HEALTHCHECK
#
# Nothing runs the AJAX spider or Webswing (ZAP's GUI served to a browser), so
# Webswing and its launcher are dropped here, before the copy, so their bytes
# never reach a layer. Webswing's bundled jetty 9.4 and lz4 1.3.0 jars were
# five HIGH only a ZAP release could fix (#860). `zap-x.sh` stays although it
# names Xvfb: zap_common.py starts every wrapper scan through it, and with no
# Xvfb here (as in the Debian derivative, which purged it) it prints one
# "not found" and runs zap.sh headless. The webdriver and selenium add-ons
# stay in plugin/ untouched: they are upstream's add-on set, and with no
# browser in the image they never launch one.
USER root
RUN set -eux; \
    rm -rf /zap/webswing /zap/zap-webswing.sh; \
    if [ -e /zap/webswing ]; then echo "/zap/webswing is still present" >&2; exit 1; fi

# Temurin 21 JRE on Alpine, the Eclipse Adoptium build of the same Java 21 that
# upstream's image runs (21.0.12.1 in both on 2026-10-18). Measured with Trivy
# 0.73.0 that day: 0 CRITICAL, 1 HIGH (libexpat, fixed in Alpine and taken by
# the `apk upgrade` below). Held at one digest like every FROM here (D-114).
FROM eclipse-temurin:21-jre-alpine@sha256:51ab5e3302e7141ce665ca3ea85e8b5cd648eafbc3c0c90dd79d6537684e4555

# The same user upstream's image runs as, with the same ids, so a volume or
# a lane that relies on uid 1000 (the DAST lane chowns /zap/wrk for it, and
# TheHub's tasks write as `zap`) sees no difference.
#
# `apk upgrade` first, so whatever Alpine has fixed is fixed here. As before,
# that makes the build depend on the day it runs -- reproducible in its pins
# and its package set, not byte for byte -- which is the trade accepted for
# taking security fixes without waiting on a new base digest; the nightly
# zap-image workflow publishes a rebuild only when it is strictly better.
#
# The packages: bash, because zap.sh is a bash script; curl, for the
# healthchecks; python3, for the wrapper scripts. Python's libraries come from
# requirements.txt, pinned by hash, through a pip that is removed in the same
# layer. gnupg is in the base only because Temurin's own build verified its
# download with it; nothing here signs or verifies anything, so it goes.
# No git, no unzip, no X, no browser.
#
# The check at the end fails the build rather than shipping an image that lost
# Java, the Python client or curl, or that kept pip.
COPY requirements.txt /tmp/zap-requirements.txt
RUN set -eux; \
    apk upgrade --no-cache; \
    apk add --no-cache bash curl python3 py3-pip; \
    if apk info -e gnupg >/dev/null; then apk del --no-cache gnupg; fi; \
    PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 python3 -m pip install \
        --break-system-packages --no-compile --require-hashes --only-binary :all: \
        -r /tmp/zap-requirements.txt; \
    apk del --no-cache py3-pip; \
    rm -f /tmp/zap-requirements.txt; \
    addgroup -g 1000 zap; \
    adduser -D -u 1000 -G zap -h /home/zap -s /bin/bash zap; \
    if python3 -m pip --version >/dev/null 2>&1; then echo "pip is still installed" >&2; exit 1; fi; \
    java -version; \
    python3 -c 'import zapv2, yaml, requests, six'; \
    curl --version

# Upstream's layout, owned by `zap` as upstream's is: ZAP in /zap (which is
# why a lane can `mkdir -p /zap/wrk` as `zap`), and ZAP's home directory with
# the scan policies zap-api-scan.py and zap-full-scan.py select and the
# HTTP Sender scripts zap-baseline.py can load. ~/.mozilla is upstream's empty
# Firefox profile: no browser runs, but without it the client add-on logs an
# ERROR at every start looking for one, which the derivative never did.
# /zap/wrk is created here,
# empty and writable by `zap`; upstream leaves it to the mount or the lane.
COPY --from=upstream --chown=1000:1000 /zap /zap
COPY --from=upstream --chown=1000:1000 /home/zap/.ZAP_D /home/zap/.ZAP_D
COPY --from=upstream --chown=1000:1000 /home/zap/.mozilla /home/zap/.mozilla
RUN set -eux; \
    install -d -o 1000 -g 1000 /zap/wrk; \
    if [ -e /zap/webswing ]; then echo "/zap/webswing is still present" >&2; exit 1; fi; \
    test -x /zap/zap.sh; \
    test -x /zap/zap-x.sh; \
    test -x /zap/zap-api-scan.py; \
    test -x /zap/zap-baseline.py

# Upstream's environment, with JAVA_HOME pointing at Temurin's JRE. ZAP_PORT
# is upstream's 8080: the HEALTHCHECK reads it, and the lanes pass their own
# -port where they need another. Temurin's ENTRYPOINT (a CA-certificate
# importer) is cleared, so `docker run <image> zap-api-scan.py ...` and a
# Concourse task run the command directly, as they do on upstream's image.
ENV JAVA_HOME=/opt/java/openjdk \
    ZAP_PATH=/zap/zap.sh \
    ZAP_PORT=8080 \
    IS_CONTAINERIZED=true \
    HOME=/home/zap/ \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    LANGUAGE=C.UTF-8 \
    PATH=/opt/java/openjdk/bin:/zap/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /zap
ENTRYPOINT []
CMD ["bash"]

# Upstream's own check, restated so the image declares one in this file. The
# demo compose overrides it with an API call on its own port; a one-off
# `zap-api-scan.py` run never reports health.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl --silent --output /dev/null --fail "http://localhost:${ZAP_PORT}/" || exit 1

USER zap
