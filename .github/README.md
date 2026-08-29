# What is here, and what is not

One workflow: `workflows/delivery.yml` — build, publish to GHCR, promote.
No scanners.

That split is the point, and the history behind it is worth keeping rather
than quietly replacing.

## Why there were no workflows at all

Five used to live here — `ci.yml` plus four `mykronos-*.yml` capability lanes.
They scanned the same commits `deploy/concourse/pipelines/mykronos.yml`
scanned, produced findings the ingestion upsert made indistinguishable, and
doubled the runner time to say the same thing twice. D-038 named that problem
and left it in place because nothing yet ran the full capability set in
Concourse. Something did, and D-039 removed them.

That decision was about **duplicate scanning**, and it still stands. Nothing
in this directory scans anything.

## Why delivery came back

Spec 32 moves this repository's CI/CD to GitHub Actions. The scanners will
follow, through the Workflow Installer like any other onboarded repository —
but delivery cannot, and the reason is a fact about the platform rather than a
scheduling choice.

**The installer's unit is a capability, and delivery is not one.** It renders
one workflow per entry in `enabled_capabilities`, and `build`, `publish` and
`promote` are not in the `Capability` enum. `ci.py` says why in a comment that
predates spec 32: *"`build` and `publish-backend` produce no findings and their
absence from the lake is not a fault."*

So `delivery.yml` is hand-written, committed here, and versioned with the code
it builds — ordinary CI for the repository it lives in. See spec 32 §5.

## The fork pull request problem, which has not gone away

D-039 recorded the cost of removing the Actions lanes: a pull request from a
fork gets no checks, because Concourse polls a branch and running an untrusted
contributor's code on a worker inside the LAN is what spec 14 §4 and spec 15 §7
both refuse.

`delivery.yml` does not change that — it triggers only on `push` to `main` and
on `workflow_dispatch`, never on `pull_request`. What *will* change it is the
scanner lanes arriving on GitHub-hosted runners, which have no LAN position to
abuse. Until then the answer to somebody else opening pull requests here is
still the one D-039 gave.

## What this does not mean

`workflow-templates/` and `actions/upload-results` are untouched and are not
going anywhere. They are the platform's product: the Workflow Installer
(spec 03) renders those templates into **other people's** repositories, and the
composite action is what every onboarded repo calls to report findings. What
runs in this directory is a decision about where our CI runs. It says nothing
about the GitHub Actions integration Mykronos exists to provide.
