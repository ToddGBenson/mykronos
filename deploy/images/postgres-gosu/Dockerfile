# Concourse's database: the vendor's postgres:15 image with its bundled gosu
# rebuilt from source on a current Go toolchain, plus the Debian package fixes
# the vendor has not shipped yet (TheHub #61617).
#
# Why not apt-upgrade alone: the image's two CRITICALs survive every stock
# postgres:15 build. One is in /usr/local/bin/gosu, a static Go binary that
# upstream still ships built on go1.24.6, whose standard library carries
# CVE-2025-68121 (CRITICAL, fixed in 1.24.13) and CVE-2026-111943 (HIGH, fixed
# only on the 1.26 and 1.27 lines). No package upgrade reaches a Go binary's
# standard library, so the fix is a rebuild of the same gosu release. The other
# CRITICAL, libxml2 CVE-2026-6653, has no Debian fix yet and stays under a risk
# acceptance until one ships; the `apt-get upgrade` below takes it when it does.
#
# The toolchain is the registry-src one (golang:1.27.3, by digest): 1.24 is
# past end of life and never received the CVE-2026-111943 fix, so a 1.24.13
# build would close the CRITICAL and keep the HIGH. gosu is built CGO-free and
# static, so an Alpine builder is no different from a Debian one here.
#
# Everything is pinned: the toolchain and runtime by digest, the gosu source by
# commit (the build fails if the tag no longer names it), the module bumps by
# exact version. The flags are
# upstream's (gosu's Dockerfile at 1.19): -trimpath and -ldflags '-d -w'; no
# -s, so govulncheck and Trivy can still read the binary's build info.
#
# Nothing else changes: entrypoint, user, volumes and PGDATA are the vendor's,
# inherited from BASE_IMAGE. Postgres's image has no USER (its entrypoint drops
# to `postgres` through gosu), so this layer stays root, as apt-upgrade does.
#
# checkov:skip=CKV_DOCKER_2: No HEALTHCHECK on purpose -- compose declares the probe (pg_isready), which overrides an image's anyway.
# checkov:skip=CKV_DOCKER_3: No USER on purpose -- the vendor's entrypoint drops to `postgres` through gosu; this layer must not change who the daemon runs as.
# checkov:skip=CKV_DOCKER_7: The runtime base is the recipe's, passed as BASE_IMAGE; image_refresh.plan_mykronos refuses a base not pinned by sha256 digest, and the default here is one.
ARG BASE_IMAGE=postgres:15.20@sha256:ad51f1a9aec85898aff1d1702ac361039286460de92d25610c85d76950f5d212

FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS gosu
# The release postgres:15.20 ships (`gosu --version`), rebuilt unchanged.
ARG GOSU_TAG=1.19
ARG GOSU_COMMIT=6456aaa0f3c854d199d0f037f068eb97515b7513
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --depth 1 --branch "${GOSU_TAG}" https://github.com/tianon/gosu.git . \
 && test "$(git rev-parse HEAD)" = "${GOSU_COMMIT}"
# GOTOOLCHAIN=local refuses a silent toolchain download, so the standard
# library linked is the one this stage pins.
ENV GOTOOLCHAIN=local CGO_ENABLED=0
# The two module bumps Trivy reads in the 1.19 binary: moby/sys/user 0.4.1
# (CVE-2026-61801, MEDIUM; upstream's own gosu 1.20 change, go.mod and go.sum
# only) and x/sys 0.44.0 (CVE-2026-39824, unrated). The build fails unless the
# binary links exactly these.
ARG MOBY_SYS_USER=v0.4.1
ARG X_SYS=v0.44.0
RUN go get "github.com/moby/sys/user@${MOBY_SYS_USER}" "golang.org/x/sys@${X_SYS}" \
 && go mod tidy
RUN go build -trimpath -ldflags '-d -w' -o /out/gosu . \
 && go version -m /out/gosu \
 && go version /out/gosu | grep -q ' go1\.27\.3$' \
 && go version -m /out/gosu | grep -qE "^\s+dep\s+github\.com/moby/sys/user\s+${MOBY_SYS_USER}(\s|$)" \
 && go version -m /out/gosu | grep -qE "^\s+dep\s+golang\.org/x/sys\s+${X_SYS}(\s|$)" \
 && /out/gosu --version | grep -q "^${GOSU_TAG} "

FROM ${BASE_IMAGE}
ARG APT_REFRESH=unset
ARG DEBIAN_FRONTEND=noninteractive
RUN echo "apt refresh: ${APT_REFRESH}" \
    && apt-get update \
    && apt-get -y -o Dpkg::Options::=--force-confold upgrade \
    && rm -rf /var/lib/apt/lists/*
COPY --from=gosu /out/gosu /usr/local/bin/gosu
# The entrypoint's own check that the replacement can drop privileges.
RUN gosu nobody true
