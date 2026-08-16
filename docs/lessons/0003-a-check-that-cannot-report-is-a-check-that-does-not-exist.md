# L0003: A check that cannot report is a check that does not exist

**Date:** 2026-08-15 · **Class:** learned here, across one 24-hour operational day
**Applies to:** every capability lane, every pipeline, and the platform's own views of them
**Landed as:** the grants-derived stages view (`coverage()` + the portfolio union),
`test_a_concourse_repo_is_enabled_by_its_grants`, and the multi-capability job map

## The lesson, in one line

**"The check ran" and "the check reported" are different facts, and every system that
conflated them was wrong in the same direction: silently, greenly, for weeks.**

## The day that taught it

One operational day, 2026-08-15, surfaced six instances of a single defect class —
a check that appeared to exist but whose result could not reach anyone:

1. **`repo_onboardings.scanned_by`** existed in every test database (built fresh) and no
   deployed one. 1088 tests agreed with the model; production disagreed. The suite
   structurally cannot see this class — its databases are never old. → D-052, the
   self-upgrading operational store, and a drift-guard test.
2. **The token rotation warning** logged on every upload for the whole 24-hour overlap
   window, then every lane 401ed at once. The warning had no deadline, GitHub-only advice,
   and lived in green build logs. A warning that looks like every other log line is not a
   signal. → the deadline now rides the header, and the last six hours are `::error::`.
3. **The unit lane had never reported once.** `git -C ../..` pointed above the repo,
   rev-parse printed nothing, the API refused the empty commit_sha, and `|| true` swallowed
   the refusal on every green build. Found within an hour of the stages cross-check
   existing — enabled-plus-never-reported is precisely the disagreement it renders.
4. **TheHub ran unit, functional and two AI lanes that uploaded nothing.** The lanes
   predate the capabilities; nothing failed, nothing reported, and the platform showed a
   repository one-third as covered as it was.
5. **The stages view itself lied in the other direction:** `enabled_capabilities` is the
   Actions installer's ledger, so Concourse-scanned repos showed `not_enabled` for eleven
   reporting capabilities. The truthful source was the grants — what may write is what is
   enabled.
6. **The DAST pause resurrected twice**, because a `fly pause` is state only an operator
   remembers and a re-apply for an unrelated token rotation quietly rescheduled a queued
   ZAP build. → the pause now lives in the set-pipeline scripts, re-asserted on every apply.

## The rule

For every check, three questions have answers somewhere a person will actually look:

- **Can it fire?** A rule that cannot match, a lane that cannot upload, a column no
  database has — each is a check that does not exist wearing the clothes of one.
- **Did it report?** Ran-and-uploaded is the only state that counts as coverage.
  `|| true` on an upload is acceptable *only* because the coverage cross-check is the
  detector; without that detector it is a silencer.
- **Who notices when it stops?** A deadline in a header beats a warning in a log.
  A red stage row beats both.

## What now enforces it

- `coverage()` renders enabled-versus-reporting per stage, per repo, with grants as the
  source of truth for pipeline-scanned repos and `event_driven` for capabilities that
  never produce a ScanRun.
- `reconcile()` cross-checks every mapped job against the newest scan run it should have
  produced — including jobs that upload two capabilities, each answering for itself.
- The rotated-token header carries its expiry; the uploader escalates as it approaches.
- Set-pipeline scripts re-assert operational pauses, so state an operator set once
  survives every re-apply.

## Promotable

Yes. Any platform that aggregates checks from pipelines it does not own will
independently discover at least instances 3, 4 and 5. The test to carry: for every
capability a repo claims, assert the claim is backed by an artifact that arrived —
not by a job that exited zero.
