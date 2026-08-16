# Mykronos dashboard

The JDED unified dashboard ([spec 10](../specs/10-jded-dashboard.md)): portfolio,
per-repo drill-down, triage queue, trends, pull requests, decisions, and retro views,
rendered from the backend's dashboard API.

Next.js App Router, server components by default. The admin token never reaches the
browser: client components that write (finding dispositions, capability toggles) post
to route handlers under `app/api/`, which attach the credential server-side —
see the note at the top of [`lib/api.ts`](lib/api.ts).

The standard set of fifteen checks is defined once in
[`components/primitives.tsx`](components/primitives.tsx) (`CAPABILITY_META`): one icon
per capability, used identically on every page. Solid means implemented and reporting;
dimmed means enabled but silent; greyed means not enabled. The per-repo
`CapabilityManager` toggles capabilities with one click through the backend's
capabilities endpoint — grants sync immediately for pipeline-scanned repos, and
Actions-scanned repos get a workflow-install PR instead.

## Develop

```bash
cd frontend
npm install
npm run dev          # http://localhost:3000, expects the backend on :8100
```

`MYKRONOS_API_URL`, `MYKRONOS_ADMIN_TOKEN`, and `MYKRONOS_GATE_TOKEN` come from
`.env.local` (gitignored). API types in `lib/api-types.d.ts` are generated — run
`python scripts/regen_api_types.py` from the repo root after any backend schema
change; a drifted copy types the whole app as `unknown`.

## Build

The production image is built by the pipeline (`mykronos/frontend` job) and published
by `publish-frontend`. `next.config.ts` ships in the runtime image on purpose: the
security headers live there, and an image without it serves none of them.
