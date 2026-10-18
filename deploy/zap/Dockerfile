# The ZAP scanner the demo-and-dast lane runs: upstream's weekly image, with
# Debian's fixes applied and the parts our usage never touches removed.
#
# Why a derivative and not the upstream image. On 2026-10-14 all 46 open HIGH
# container findings against MyKronos were in this one third-party image, and
# no upstream tag is better: `stable` (2.17.0) is Debian 12 with hundreds of
# fixable CVEs, `nightly` is no newer, and this weekly is the newest build
# there is. So the fixes have to be applied here. Measured with Trivy 0.73.0
# (HIGH+CRITICAL): upstream 274 (3 critical), this build 87 (0 critical); what
# is left is in Protected/essential packages, in python3.13, expat, curl and
# perl that ZAP or git need (none with a Debian fix yet), or in ZAP's own jars,
# which only upstream can fix.
#
# **This FROM is the estate's one ZAP pin (D-128).** The tag is cosmetic; the
# digest is what holds the scanner still (D-114), and it moves only by editing
# this line. TheHub's `zap` resource in deploy/concourse/pipelines/thehub.yml
# pins the same digest, and `test_pipeline_conformance.py` holds the two equal.
FROM ghcr.io/zaproxy/zaproxy:weekly@sha256:4ec932d24ee6fa7181333a719d519cdebf92df541058d48041ce3358528cd0ea

USER root

# What MyKronos uses ZAP for, which is what decides what can go:
#
#   zap.sh -daemon       the API on the compose network; the lane drives the
#                        traditional spider, the active scan, the replacer and
#                        the custompayloads add-on through it
#   zap-api-scan.py      the OpenAPI scan, in a one-off `docker run`
#   zap-baseline.py      not run by this repository, kept working
#   curl                 the compose healthcheck and the image's own HEALTHCHECK
#
# Nothing runs the AJAX spider, `zap-x.sh` or Webswing, so the browser and the
# X server they need (firefox-esr, xvfb, x11vnc, openbox, xterm) go, and with
# them the media and GUI libraries only those pulled in (libav*, librsvg2,
# libxtst6, libx11, libtiff, ghostscript, ...). ZAP runs headless, so the full
# JDK becomes `openjdk-21-jre-headless`: same JAVA_HOME, no AWT/X11 stack.
# The C toolchain and the -dev packages built upstream's pip wheels and are not
# used at run time; linux-libc-dev alone carried ~60 of the HIGH findings.
# openssh-client is only a Recommends of git; wget and xmlstarlet fetched ZAP
# during upstream's own build. systemd itself is `Protected` and stays; the
# units nothing in a container starts go.
#
# Webswing (/zap/webswing) is ZAP's GUI served to a browser; it is not a
# package, so the purge cannot take it. Nothing here runs it, and its bundled
# jetty 9.4 and lz4 1.3.0 jars were the last five HIGH findings left after the
# purge (2026-10-15) -- ones only a ZAP release could fix -- so it is deleted.
#
# libcups2t64 is not purged but removed with --force-depends, the one package
# this file removes against a declared dependency. openjdk-21-jre-headless
# Depends on it for Java's print services (javax.print, sun.print), which a
# headless daemon never touches, and Debian has no fix for its two HIGH
# (CVE-2026-55453, code execution via printer status; CVE-2026-34980) and 25
# lower findings. Removed on 2026-10-18 and verified: `zap.sh -daemon` serves
# the API, the passive scanners load, the healthcheck passes, and a
# zap-baseline.py scan writes its JSON report -- no UnsatisfiedLinkError, no
# mention of cups. dpkg records the dependency as broken; nothing runs apt here
# afterwards, and the check below fails the build if libcups.so comes back.
#
# `apt-get upgrade` first, so whatever Debian has fixed is fixed here. That
# makes the build depend on the day it runs -- the derivative is reproducible
# in its pin and its package set, not byte for byte -- which is the trade
# accepted for picking up security fixes without waiting on upstream.
#
# The check at the end fails the build rather than shipping an image that
# quietly kept one of these, and proves Java and the Python client survived.
ARG DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-mark manual openjdk-21-jre-headless; \
    apt-get -y -o Dpkg::Options::=--force-confold upgrade; \
    apt-get -y purge --auto-remove \
        firefox-esr xvfb xserver-common x11vnc openbox xterm \
        openjdk-21-jdk openjdk-21-jre openjdk-21-jdk-headless \
        gcc g++ make automake autoconf \
        python3-dev python3.13-dev libpython3-dev libpython3.13-dev \
        libexpat1-dev zlib1g-dev uuid-dev libc6-dev linux-libc-dev \
        openssh-client libgs10 libgs10-common libgs-common \
        wget xmlstarlet shared-mime-info \
        systemd-timesyncd systemd-cryptsetup libnss-systemd libpam-systemd dbus-user-session; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    dpkg --remove --force-depends libcups2t64; \
    if ldconfig -p | grep -q 'libcups\.so'; then echo "libcups.so is still on the library path" >&2; exit 1; fi; \
    rm -rf /zap/webswing; \
    if [ -e /zap/webswing ]; then echo "/zap/webswing is still present" >&2; exit 1; fi; \
    for gone in firefox-esr xvfb xserver-common openssh-client libgs10 librsvg2-2 \
                libxtst6 libexpat1-dev python3.13-dev linux-libc-dev wget; do \
        if dpkg-query -W -f='${Status}' "$gone" 2>/dev/null | grep -q 'ok installed'; then \
            echo "$gone is still installed" >&2; exit 1; \
        fi; \
    done; \
    java -version; \
    python3 -c 'import zapv2, yaml, requests'; \
    curl --version

# Upstream's own check, restated so the image declares one in this file
# rather than by inheritance. The demo compose overrides it with an API call
# on its own port; a one-off `zap-api-scan.py` run never reports health.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl --silent --output /dev/null --fail "http://localhost:${ZAP_PORT}/" || exit 1

USER zap
