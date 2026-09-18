# Mykronos dashboard

The JDED unified dashboard ([spec 10](../specs/10-jded-dashboard.md)): portfolio,
per-repo drill-down, triage queue, trends, pull requests, decisions, and retro views,
rendered from the backend's dashboard API.

Next.js App Router, server components by default. The admin token never reaches the
browser: client components that write (finding dispositions, capability toggles) post
to route handlers under `app/api/`, which attach the credential server-side —
see the note at the top of [`lib/api.ts`](lib/api.ts).

The per-repo page is one dashboard (spec 10 §2.2): scan health as a box per check
showing what fraction of its runs succeeded, pipeline stages and pipeline jobs as
rows of labelled indicator lights, and the open findings — grouped one row per
problem, triaged with Patchwork's own vocabulary, and with the toxic combinations
named above the table. Risk decisions, supply chain, insider risk and remediation
stay behind tabs, because each is a different subject rather than another view of
the same findings.

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

### Install the pre-commit hook, once per clone

```bash
python scripts/install_hooks.py      # sets core.hooksPath -> scripts/hooks
```

**This is opt-in and it is not installed for you.** It sets git config, which
is a per-clone decision rather than something a repository gets to make, so
nothing in CI or in any script runs it. It had never been run in this clone,
which is why `scripts/hooks/pre-commit` — and `regen_api_types.py`, whose only
invoker it is — were dead code (#60001).

Three things enforce this one rule, and they are deliberately not equivalent:

| Where | What it catches | When |
|---|---|---|
| `scripts/hooks/pre-commit` | staged API change with stale types | at commit, and it regenerates and stages them for you |
| `backend/tests/test_api_types_fresh.py` | a schema component, field or enum member the committed types do not declare | in the unit lane, seconds, no node and no network |
| `mykronos/frontend` lane | any byte-level difference in the generated file | in CI, after a build |

The hook is the cheapest and is optional. The test is the one that always runs.
The lane is the only one that compares the generated file byte for byte, and it
reimplements the comparison inline rather than calling
`scripts/regen_api_types.py` for a reason worth knowing before anyone
"deduplicates" it: that task runs in `node:slim`, which has no python.

## Build

The production image is built by the pipeline (`mykronos/frontend` job) and published
by `publish-frontend`. `next.config.ts` ships in the runtime image on purpose: the
security headers live there, and an image without it serves none of them.
