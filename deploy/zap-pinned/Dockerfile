# The ZAP the demo-and-dast lane runs: one published, reviewed build.
#
# deploy/zap/Dockerfile is the recipe. .github/workflows/zap-image.yml rebuilds
# it nightly and publishes ghcr.io/<owner>/mykronos-zap:weekly-p<date> only
# when the rebuild removes a HIGH/CRITICAL and adds none. This file adopts one
# of those dates, by digest, so every commit is scanned by the same bytes
# rather than by whatever that morning's `apt-get upgrade` produced.
#
# A build and not an `image:`, for the finding identity. A container finding is
# keyed on the image's repository with the registry host dropped
# (fingerprint.image_repository), and ghcr.io's path carries the owner, so
# scanning the published name would re-key every ZAP finding, close them all as
# fixed, and open them again without their risk acceptances. Built from this
# file, the containers lane pushes and scans it as `mykronos-zap`, as before.
#
# Adopting a newer date is a reviewed change to the line below, and to the
# recipe's `baseline:` in deploy/demo/docker-compose.yml, which must name the
# same image (test_zap_image.py holds the two together): the nightly rebuild is
# compared against what runs, so it publishes only what is better than that.
FROM ghcr.io/toddgbenson/mykronos-zap:weekly-p20261018@sha256:92d01f31a4a2095d66b73b3d1ee3c22771cc67d83eb9cd7a0896f4f2eaa9602f

# Restated, not changed: both are the recipe's. A build file that does not say
# them reads to Checkov as running as root with no health check.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl --silent --output /dev/null --fail "http://localhost:${ZAP_PORT}/" || exit 1
USER zap
