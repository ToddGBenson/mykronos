# L0001: Every scanner needs an explicit no-input path

**Date:** 2026-08-12 · **Class:** promoted from `ToddGBenson/keel` (L0009, 2026-08-08)
**Applies to:** every capability lane in this repository
**Landed as:** the `NO_PACKAGES` path in `workflow-templates/atlas.yml.j2`, guarded by
`test_no_package_sources_is_an_empty_scan_not_a_failed_one`

## The lesson, in one line

**A scanner with nothing to scan is in a third state.** Not a pass, not a failure — and a
pipeline that only models two will get one of them wrong.

## How it arrived here

keel learned this on its first real CI run: SCA, IaC, SAST and secret scanning all failed at
once, none of them findings, all of them the same defect. Its write-up was marked
*promotable* — meaning a team on a different stack would hit the same wall.

They did. This repository hit it four days later, from the other side.

Atlas ran `osv-scanner scan source` against a repo with no dependency manifests. osv-scanner
exits **128 — "No package sources found"**, the template treated any exit above 1 as a scan
failure, and the lane went permanently red for a repository that will never have a manifest.

The near-miss is the instructive part. `--recursive` had already been added to this exact
call *for this exact exit code*, on the reasoning that manifests were merely in
subdirectories. That fixes a repo whose manifests are somewhere. It cannot help a repo that
has none — and nobody asked whether that case existed.

## The rule

Three states, not two:

```
input present   -> scan, gate on findings
input absent    -> record an EMPTY result, and say so LOUDLY.
                   "No package sources found. This is NOT a clean bill of
                    health for dependencies that exist; it is a statement
                    that none were declared."
scan failed     -> fail the lane
```

Three things make the middle branch safe rather than a hole:

1. **Match on the message, not the exit code alone.** 128 is overloaded; a different 128 is
   still a real failure. `[ "$rc" -eq 128 ] && grep -qi 'no package sources found'`.
2. **Keep the real-failure guard.** The `rc > 1` branch must survive, or the escape hatch
   swallows genuine breakage. This is the mutation most worth testing.
3. **Emit an explicit empty artifact.** Downstream reports "produced no output" as a failure,
   so an absent SARIF keeps the lane red anyway. `"results": []` with
   `"executionSuccessful": true` says *scanned, found nothing* — a different claim from
   *did not run*.

## Why the fix is riskier than it looks

Replacing a false red with a **false green is a worse trade**, because nobody investigates a
green lane. Loud announcement is not decoration here; it is the thing that keeps the empty
case auditable. The syft SBOM step twenty lines below had already got this right — warn,
omit the artifact, do not kill the lane — which is worth noting: the correct pattern was
already in the same file, and the SCA step still had the bug.

## The check worth stealing

Ask of every green lane: **what would this have to find to go red — and did it actually
look?** If the job summary cannot answer the second half, the summary is not saying enough.

## Related

- keel `docs/lessons/0009-scanners-need-a-no-input-path.md` — the original
- keel L0006 (claiming coverage you do not have) · keel L0007 (checkers that cry wolf get
  muted) · keel L0008 (fix the siblings — the SBOM step had the answer already)
