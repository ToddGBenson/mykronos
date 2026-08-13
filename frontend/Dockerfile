# Mykronos dashboard (spec 15 §2, D-038).
#
#   docker build -f frontend/Dockerfile -t mykronos-frontend ./frontend
#
# Unlike the backend this builds from frontend/, because nothing outside it is
# needed.
#
# Three stages. `next start` needs production node_modules and .next, and
# nothing else -- copying the whole working tree would ship source maps, the
# dev toolchain and 400MB of dev dependencies into a container this platform
# then scans for vulnerabilities.
#
# `output: standalone` would produce a smaller image still, and is not used:
# it changes the start command from `next start` to running a generated
# server.js, which would silently diverge from how the app is run locally.
# One way to start it is worth more than the megabytes.

FROM node:22-slim AS deps

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund


FROM node:22-slim AS build

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# The dashboard reaches the backend server-side, so this is a build-time
# default rather than a secret. Compose overrides it at run time; the tokens
# are never baked in.
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build


FROM node:22-slim AS runtime

RUN useradd --create-home --uid 10001 mykronos

# Security updates for the base image, and no curl.
#
# This image carried every one of the five criticals the platform's own scan
# found, plus twelve highs across curl, libcurl4 and libssh2-1 - all three
# present only so a healthcheck could run, in an image whose entire purpose is
# running a JavaScript runtime with `fetch` built in.
#
# The rule that put curl here still holds: a healthcheck must not use a binary
# the image does not ship. `node` is that binary here.
RUN apt-get update -qq \
    && apt-get upgrade -y -qq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

COPY --from=build --chown=mykronos:mykronos /app/.next ./.next
COPY --from=build --chown=mykronos:mykronos /app/public ./public
COPY --from=build --chown=mykronos:mykronos /app/package.json ./package.json
COPY --from=build --chown=mykronos:mykronos /app/node_modules ./node_modules

USER mykronos

EXPOSE 3100

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["node", "-e", "fetch('http://localhost:3100/').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]

CMD ["npx", "next", "start", "--port", "3100", "--hostname", "0.0.0.0"]
