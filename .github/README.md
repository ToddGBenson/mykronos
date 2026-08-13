# There are deliberately no workflows here

This repository's CI runs in Concourse, not in GitHub Actions. See
[spec 16 §4](../specs/16-thehub-delivery-pipeline.md) and D-039.

Five workflows used to live in `workflows/` — `ci.yml` plus the four
`mykronos-*.yml` capability lanes. They scanned the same commits
`deploy/concourse/pipelines/mykronos.yml` scans, produced findings the
ingestion upsert made indistinguishable from each other, and doubled the
runner time to say the same thing twice. D-038 named that problem and left it
in place because nothing yet ran the full capability set in Concourse.
Something does now.

**What that costs.** A pull request from a fork gets no checks. Concourse
polls a branch, and running an untrusted contributor's code on a worker inside
the LAN is what spec 14 §4 and spec 15 §7 both refuse. If somebody other than
the operator starts opening pull requests here, the answer is to restore the
Actions lanes *for pull requests only* — not to widen what Concourse trusts.

## What this does not mean

`workflow-templates/` and `actions/upload-results` are untouched and are not
going anywhere. They are the platform's product: the Workflow Installer
(spec 03) renders those templates into **other people's** repositories, and
the composite action is what every onboarded repo calls to report findings.
Removing this repository's own Actions is a decision about where our CI runs.
It says nothing about the GitHub Actions integration Mykronos exists to
provide.
