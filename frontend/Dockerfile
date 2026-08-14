# Mykronos dashboard (spec 15 §2, D-038).
#
#   docker build -f frontend/Dockerfile -t mykronos-frontend ./frontend
#
# Unlike the backend this builds from frontend/, because nothing outside it is
# needed.
#
# Four stages. `next start` needs production node_modules and .next, and
# nothing else -- copying the whole working tree would ship source maps, the
# dev toolchain and 400MB of dev dependencies into a container this platform
# then scans for vulnerabilities.
#
# It said three stages and shipped them anyway. `deps` ran a full `npm ci`
# because the build needs typescript, eslint and tailwind; `runtime` then
# copied that same node_modules. The platform's own container scan found the
# evidence: advisories in `@redocly/openapi-core`'s bundled js-yaml, a
# package used to generate the API client at development time and reachable
# from nothing the server runs. `prod-deps` resolves the runtime tree
# separately so the claim above is true.
#
# `output: standalone` would produce a smaller image still, and is not used:
# it changes the start command from `next start` to running a generated
# server.js, which would silently diverge from how the app is run locally.
# One way to start it is worth more than the megabytes.

FROM node:22-slim AS deps

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund


# The runtime tree, resolved from the same lockfile so it cannot drift from
# what the build compiled against.
FROM node:22-slim AS prod-deps

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund


FROM node:22-slim AS build

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# The dashboard reaches the backend server-side, so this is a build-time
# default rather than a secret. Compose overrides it at run time; the tokens
# are never baked in.
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build


# Distroless: a node runtime and nothing else.
#
# The platform's own scan is what drove this, and each step was measured on
# the built image rather than argued:
#
#   node:22-slim, curl removed, apt upgraded   5 critical  17 high
#   ... npm removed as well                    5 critical  17 high
#   distroless/nodejs22                        1 critical   5 high
#
# The five criticals that would not shift were four in perl-base and one in
# zlib1g, none of which has a fix in any Debian release - bookworm and trixie
# both carry them, so there was no base image to upgrade to. They are also
# unreachable here: perl is never executed by this image, and it is present
# only because Debian marks it Essential. The choice was therefore between
# accepting five permanent criticals for a language we do not run, or shipping
# an image that does not contain it.
#
# Distroless has no perl, no apt, no shell and no package manager, which is
# why the earlier curl and npm removals were the right instinct pointed at the
# wrong scope: removing packages one at a time from a distribution image loses
# to removing the distribution.
#
# What this costs, plainly: no shell means no `docker exec sh` into a running
# frontend. Debugging is `docker logs` and the node inspector. That is a real
# reduction in convenience and the reason this is not the right default for
# every image - the backend keeps its Debian base because it is the process
# holding the lake, and being able to get a shell next to it matters more
# there.
FROM gcr.io/distroless/nodejs22-debian13:nonroot AS runtime

# `nonroot` is uid 65532, built into the image. The previous stage created
# uid 10001 by hand because a Debian base ships only root; distroless does
# not, so the useradd - and the whole apt layer around it - goes.

WORKDIR /app
ENV NODE_ENV=production     NEXT_TELEMETRY_DISABLED=1

COPY --from=build --chown=nonroot:nonroot /app/.next ./.next
COPY --from=build --chown=nonroot:nonroot /app/public ./public
COPY --from=build --chown=nonroot:nonroot /app/package.json ./package.json
# `next start` reads this at run time, and without it every security header
# and `poweredByHeader: false` is silently dropped - the server starts, serves
# 200s, and simply does not set them. Found by adding the headers, rebuilding,
# and seeing none of them on the response.
COPY --from=build --chown=nonroot:nonroot /app/next.config.ts ./next.config.ts
COPY --from=prod-deps --chown=nonroot:nonroot /app/node_modules ./node_modules

USER nonroot

EXPOSE 3100

# Absolute path to node: the healthcheck is exec form, so it does not inherit
# the image ENTRYPOINT, and there is no shell to resolve a bare `node`.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3     CMD ["/nodejs/bin/node", "-e", "fetch('http://localhost:3100/').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]

# The distroless ENTRYPOINT is node itself, so CMD is the script and its
# arguments. `node_modules/.bin/next` is a symlink to a shebang script and
# there is no shell to honour the shebang, so the real entry module is named
# directly.
CMD ["node_modules/next/dist/bin/next", "start", "--port", "3100", "--hostname", "0.0.0.0"]