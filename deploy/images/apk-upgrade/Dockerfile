# A vendor image on Alpine or Wolfi, plus the package fixes its vendor has not
# shipped yet. Built out of band by the `image-refresh` job (deploy/concourse/
# pipelines/mykronos.yml) for the services that declare it under
# `x-mykronos-build` in deploy/concourse/docker-compose.yml: Concourse (Wolfi),
# the registry and Vault (Alpine).
#
# Same recipe as TheHub's docker/apk-upgrade. BASE_IMAGE is the vendor image
# pinned by digest in the recipe, so the only drift is the deliberate upgrade.
# APK_REFRESH carries the build date and busts the layer cache: Docker caches
# `RUN apk upgrade` forever, so without a changing argument a rebuild would
# keep yesterday's packages.
#
# What this cannot fix: a vendor's own statically linked binaries. Concourse's
# `vrf` and `runc`, and Vault itself, carry the Go runtime they were built
# with; `apk upgrade` replaces packages, not those. The risk acceptances for
# those findings stay as they are - see the image-refresh job's notes.
#
# RUN_AS restores the vendor's runtime user after the upgrade, which has to
# run as root. It defaults to root because the registry and Concourse run as
# root; Vault's recipe passes `vault`, which its entrypoint expects.
#
# checkov:skip=CKV_DOCKER_2: No HEALTHCHECK on purpose -- each service declares its probe in compose, which overrides an image's anyway.
# checkov:skip=CKV_DOCKER_3: USER is the vendor's own, restored through RUN_AS; this layer must not change who the daemon runs as.
# checkov:skip=CKV_DOCKER_7: BASE_IMAGE is always pinned by digest; image_refresh.plan_mykronos refuses a recipe whose base is not.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG APK_REFRESH=unset
ARG RUN_AS=root
USER root
RUN echo "apk refresh: ${APK_REFRESH}" && apk upgrade --no-cache
USER ${RUN_AS}
