# `deploy/concourse/vars/` — the non-secret half of a pipeline's configuration

One file per pipeline, named for it. Each holds exactly the `((var))` values
that `deploy/concourse/set-*-pipeline.ps1` writes into its `--load-vars-from`
file **and that are not secrets**: host addresses, bucket names, the branch
scanned, the `mykronos-ref` pin, timeouts.

They exist because of the `set-pipeline` job the three pipelines now carry.

## Why a pipeline cannot apply itself without them

`fly set-pipeline --load-vars-from` interpolates **client side**. The
configuration Concourse ends up holding has every var from that file already
substituted — which is the whole of D-043 and the reason VAULT.md exists. So
the running pipelines are not `pipelines/thehub.yml`; they are that file plus a
vars file that lives only in a PowerShell script on the operator's machine and
in a temp file that is deleted on the way out.

A `set_pipeline: self` step that supplied no vars would therefore not "re-apply
the same pipeline". It would apply a *different* one, with `((thehub-branch))`,
`((mykronos-ref))` and a dozen others left for the credential manager to
resolve — and Vault does not hold them, because they are not secrets. The first
casualty would be `thehub.yml`'s `source` resource, whose `branch:` is one of
them: it would stop fetching, every job would stop with it, including the
`set-pipeline` job, and the only way back would be a hand `fly set-pipeline`.

That is precisely the lockout keel documents in its own `set-pipeline` comment,
and these files are what keeps it from happening here.

## What is deliberately NOT here

Secrets. Every one of them resolves from Vault at build time
(`concourse/main/<pipeline>/<name>`, then `concourse/main/<name>`), which is
PS-9 and is what the `Add-Secret` probe in each apply script already arranges.

Three values are neither committable nor, today, in Vault. They are named in
each pipeline's `set-pipeline` comment rather than left to be discovered:

| var | pipeline | why not |
|---|---|---|
| `hibp-api-key` | personal-soc | a secret; belongs in Vault, is not there yet |
| `monitor-emails` | personal-soc | an address list read out of `.env` |
| `azure-client-*`, `azure-tenant-id`, `azure-subscription-id` | thehub | secrets; belong in Vault, are not there yet |
| `github-token` | thehub | a GitHub App installation token, dead in an hour (CNC-2). Vault would serve a stale one, which set-thehub-pipeline.ps1 argues is worse than none |

## Keeping them true

`backend/tests/test_pipeline_conformance.py` asserts, for every pipeline, that
each value here equals what the apply script writes, and that every `((var))`
the pipeline uses is supplied by this file, by Vault, or is on the list above.
Change a default in a `set-*-pipeline.ps1` and the `unit` lane fails until this
file follows — which is the only thing that stops two copies of the same
configuration from drifting apart.
