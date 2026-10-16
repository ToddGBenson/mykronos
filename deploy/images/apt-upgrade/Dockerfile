# A vendor image on Debian, plus the package fixes its vendor has not shipped
# yet. Built out of band by the `image-refresh` job (deploy/concourse/
# pipelines/mykronos.yml) for the services that declare it under
# `x-mykronos-build`: Concourse's Postgres.
#
# BASE_IMAGE is the vendor image pinned by digest in the recipe, so the only
# drift is the deliberate upgrade. APT_REFRESH carries the build date and
# busts the layer cache, for the reason apk-upgrade gives.
#
# RUN_AS restores the vendor's runtime user; Postgres's image has none (its
# entrypoint drops to `postgres` itself), so it stays root.
#
# checkov:skip=CKV_DOCKER_2: No HEALTHCHECK on purpose -- compose declares the probe, which overrides an image's anyway.
# checkov:skip=CKV_DOCKER_3: USER is the vendor's own, restored through RUN_AS; this layer must not change who the daemon runs as.
# checkov:skip=CKV_DOCKER_7: BASE_IMAGE is always pinned by digest; image_refresh.plan_mykronos refuses a recipe whose base is not.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG APT_REFRESH=unset
ARG RUN_AS=root
ARG DEBIAN_FRONTEND=noninteractive
USER root
RUN echo "apt refresh: ${APT_REFRESH}" \
    && apt-get update \
    && apt-get -y -o Dpkg::Options::=--force-confold upgrade \
    && rm -rf /var/lib/apt/lists/*
USER ${RUN_AS}
