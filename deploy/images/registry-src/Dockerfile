# The estate registry (registry:3, distribution v3.1.2) with its own binary
# rebuilt from source: golang.org/x/net moved past the HTTP/2 fixes and the
# current Go toolchain, on the vendor's runtime image plus `apk upgrade`.
#
# Why not apk-upgrade alone: that recipe replaces Alpine packages, and the
# findings that matter here are in /bin/registry, a statically linked Go
# binary carrying x/net v0.59.0 (4 HIGH HTTP/2 denial of service, fixed in
# 0.60.0) and the Go 1.26.8 standard library it was built with. Upstream has
# not released past v3.1.2, so the fix is a rebuild of the same tag: the
# operator decision of 2026-10-18 (registry and silo rebuilt; Concourse and
# Vault wait for their vendors).
#
# Go 1.27.3 (2026-11-04): the standard library fix for CVE-2026-111943 (HIGH),
# which the 1.27.2 build linked.
#
# Go 1.27.4 (2026-11-13, TheHub #61620): released 2026-11-10 with security
# fixes to net/http, cgo, the go command, the compiler and the linker. Was
# golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb
# (rollback: put that FROM back).
#
# x/net 0.62.0 (2026-11-05, TheHub #61076): the HTML parser fixes for
# CVE-2026-78661 and CVE-2026-97045 (both low), which 0.60.0 carried. The
# build fails unless the binary links exactly the pinned x/net.
#
# Everything is pinned: the toolchain and runtime by digest, the source by
# commit (the build fails if the tag no longer names it), the module bumps by
# exact version. The flags are upstream's (its Dockerfile and Makefile at
# v3.1.2): -trimpath, -s -w, and the version stamps `registry --version` reads.
#
# checkov:skip=CKV_DOCKER_2: No HEALTHCHECK on purpose -- the service declares its probe in compose, which overrides an image's anyway.
# checkov:skip=CKV_DOCKER_3: USER is the vendor's (root), as in apk-upgrade; this recipe must not change who the daemon runs as.
# checkov:skip=CKV_DOCKER_7: The runtime base is the recipe's, passed as BASE_IMAGE; image_refresh.plan_mykronos refuses a base not pinned by sha256 digest, and the default here is one.
ARG BASE_IMAGE=registry:3@sha256:852b3e4d378c426dda6b318fe9d9bfe8e92a0eccb9926671ec3d3ea17a196696

FROM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
ARG DISTRIBUTION_TAG=v3.1.2
ARG DISTRIBUTION_COMMIT=3220848f15d9279c66a41aa0a257469e6aede1e9
ARG X_NET=v0.62.0
ARG OTEL_EXPORTERS=v1.45.0
ARG KLAUSPOST_COMPRESS=v1.18.7
ARG GO_JOSE=v4.1.7
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --depth 1 --branch "${DISTRIBUTION_TAG}" https://github.com/distribution/distribution.git . \
 && test "$(git rev-parse HEAD)" = "${DISTRIBUTION_COMMIT}"
# go.mod says `go 1.26.0`; the toolchain is newer, so its standard library is
# what gets linked. GOTOOLCHAIN=local refuses a silent toolchain download.
ENV GOTOOLCHAIN=local CGO_ENABLED=0
# The OTLP trace exporters move together (CVE-2026-81870, fixed in 1.45.0);
# `go get` brings the otel modules they require along with them.
# klauspost/compress 1.18.7: CVE-2026-63209 (HIGH, s2 integer overflow and
# out-of-bounds write, GHSA-259r-337f-4rfw), raised on 3-p20261019 2026-10-20.
# go-jose/v4 4.1.7: distribution requires 4.1.4, which carries CVE-2026-116587
# (HIGH, GHSA-mgcc-cww5-fp2q, RSA JWK parsing denial of service, fixed in
# 4.1.6) and five MEDIUM/LOW advisories fixed in 4.1.7. It is linked through
# the token auth controller (registry/auth/token), and every API that package
# calls is unchanged in 4.1.7. Since 4.1.6 a JWK's RSA modulus is capped at
# 4096 bits.
RUN go get "golang.org/x/net@${X_NET}" \
      "go.opentelemetry.io/otel/exporters/otlp/otlptrace@${OTEL_EXPORTERS}" \
      "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@${OTEL_EXPORTERS}" \
      "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@${OTEL_EXPORTERS}" \
      "github.com/klauspost/compress@${KLAUSPOST_COMPRESS}" \
      "github.com/go-jose/go-jose/v4@${GO_JOSE}" \
 && go mod tidy \
 && go mod vendor \
 && go list -m golang.org/x/net go.opentelemetry.io/otel/exporters/otlp/otlptrace github.com/klauspost/compress github.com/go-jose/go-jose/v4
RUN PKG=github.com/distribution/distribution/v3 \
 && go build -trimpath \
      -ldflags "-s -w -X ${PKG}/version.version=${DISTRIBUTION_TAG#v}+mykronos -X ${PKG}/version.revision=${DISTRIBUTION_COMMIT} -X ${PKG}/version.mainpkg=${PKG}" \
      -o /out/registry ./cmd/registry \
 && go version -m /out/registry | grep -E '^\s+(dep\s+(golang.org/x/net|github.com/klauspost/compress|github.com/go-jose/go-jose/v4)|build\s+-trimpath)|go1\.' \
 && go version -m /out/registry | grep -qE "^\s+dep\s+golang\.org/x/net\s+${X_NET}(\s|$)"

FROM ${BASE_IMAGE}
ARG APK_REFRESH=unset
RUN echo "apk refresh: ${APK_REFRESH}" && apk upgrade --no-cache
COPY --from=build /out/registry /bin/registry
