# The artifact store: SILO's own distroless image, with Debian's current
# ca-certificates laid over it (TheHub #61023).
#
# Why a build at all. The vendor image is distroless Debian 12, and the one
# Debian package in it a scanner reports is ca-certificates 20250419~deb12u1
# (DLA-4845-1, fixed in 20250419~deb12u2). Every SILO release up to
# RELEASE.2026-10-26 still ships deb12u1, and distroless has no shell and no
# package manager, so neither an upstream pull nor the apt-upgrade recipe
# reaches it. What ca-certificates puts in a distroless image is data -- the
# PEM bundle, its copyright file and its dpkg record under status.d -- so the
# fix is to take those files from a Debian 12 that has the fixed package.
#
# The SILO binary does not change: the shipped stage is the vendor image at
# the digest compose ran before this, plus COPY and nothing else (a RUN cannot
# work without a shell, and USER/ENTRYPOINT/CMD would change how it runs).
# The bundle and the dpkg record move together: the TLS stack reads one and
# the scanner the other.
#
# checkov:skip=CKV_DOCKER_2: No HEALTHCHECK here on purpose -- the vendor image declares `silo healthcheck ready` and compose declares the same probe, which overrides an image's anyway.
# checkov:skip=CKV_DOCKER_3: USER is the vendor's; this layer must not change who the daemon runs as.
FROM debian:12-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS certs
# The fix this build exists for. The build fails rather than ship a bundle
# older than this, so a Debian mirror that has not caught up is a red build,
# not a silent no-op.
ARG CA_CERTIFICATES_FLOOR=20250419~deb12u2
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# Distroless keeps one dpkg record per package under status.d, without the
# `Status:` line a full dpkg database carries, beside its md5sums.
RUN version="$(dpkg-query -W -f='${Version}' ca-certificates)" \
 && echo "ca-certificates ${version}" \
 && dpkg --compare-versions "${version}" ge "${CA_CERTIFICATES_FLOOR}" \
 && mkdir -p /out/status.d \
 && dpkg-query -s ca-certificates | grep -v '^Status:' > /out/status.d/ca-certificates \
 && cp /var/lib/dpkg/info/ca-certificates.md5sums /out/status.d/ca-certificates.md5sums \
 && test -s /etc/ssl/certs/ca-certificates.crt

FROM pgsty/silo:RELEASE.2026-10-26T00-00-00Z-distroless@sha256:e6544a902f426f2b4e775b89f3c1cd78310dbffc262d1ed82e9800c1cb1b5885
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=certs /usr/share/doc/ca-certificates/copyright /usr/share/doc/ca-certificates/copyright
COPY --from=certs /out/status.d/ /var/lib/dpkg/status.d/
