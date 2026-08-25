# Spec 28 — Threat Model Resolution: CWE From SARIF, a Controls Register, and Three Honest States

**Status:** Draft for review
**Depends on:** [04 — Scanner Workflows](04-scanner-workflows.md), [05 — Data Lake](05-datalake.md),
[18 — Repo Page Rework](18-repo-page-rework-threat-model-and-remediation.md),
[23 — Agentic Source Code Review](23-agentic-source-code-review.md)

---

## 0. What this spec is against

The Threat Model tab is honest about being coarse and coarse in a specific, fixable way.

**The stated reason for capability-level mapping is true of the schema and not of the data.** Spec 18
§6 and `dashboard.threat_model()` both say it: *"no `Finding` carries a structured CWE — `rule_id` is
a free-form string the reporting tool chose"*. That is accurate about what the lake stores. It is not
accurate about what arrives: SARIF carries `properties.tags`, CodeQL and Semgrep both populate it with
CWE identifiers, and `adapters/sarif.py` reads exactly one property — `security-severity` — and drops
the rest. The CWE is at the door and nobody opens it.

**A threat model is made of four things and this has one.** Assets, entry points, trust boundaries,
mitigations. The tab has findings, grouped six ways. It can say what was found; it cannot say what
could happen here or what stops it. As scanning improves it can only ever grow more red, and a team
that spends a quarter adding controls sees no change at all.

**An empty category reads as safe.** "Nothing here — not hidden, empty" applies the right instinct to
the wrong distinction. A STRIDE category with no findings because DAST has never run in this
repository renders identically to one with no findings because the code is clean. The scan-health
data that separates them is already fetched on the same page, one tab away.

## 0a. Implementation status

| Item | Status |
|---|---|
| CWE extraction from SARIF `properties.tags` (§1) | **Built** |
| STRIDE from CWE where present, capability where absent (§2) | **Built** — `stride-map-v1.yaml`, 56 entries |
| Controls register, admin-authored (§3) | **Built** — in the operational store rather than the lake; see §3.4 |
| Three-state categories: clean / unscanned / unmitigated (§4) | **Built** — four states, not three; §4 already listed four |

## 1. CWE at the door

### 1.1 Current state

`adapters/sarif.py` reads `rule.properties["security-severity"]` to derive severity. SARIF's
`properties.tags` array — where CodeQL writes `external/cwe/cwe-089` and Semgrep writes its own CWE
strings — is parsed by nothing. `FindingSubmission.raw_finding_json` preserves the original record
verbatim, so the data is *in the lake* today, unqueryable inside a JSON blob and unused.

### 1.2 What ships

- **`FindingSubmission.cwe_ids: list[str]`** and a `cwe_ids_json` lake column. Normalised to bare
  numeric form (`CWE-89`), because three tools write that identifier four ways.
- **Extraction in the SARIF adapter**, from `properties.tags` and from `properties.cwe` where a tool
  writes it directly. Tools that emit neither produce an empty list — which is *absent*, not "no
  CWE applies", and §2 depends on that distinction.
- **A list, not a field.** A rule legitimately maps to several CWEs, and picking one would be the
  adapter inventing precision. The consumers below handle multiplicity explicitly.
- **No inference.** The platform does not guess a CWE from a rule name or a title. A tool that
  declares one is a tool taking responsibility for it; a regex over `rule_id` would be this platform
  manufacturing a taxonomy claim, which is the exact thing spec 18 §6 refused to do.

## 2. STRIDE from CWE

### 2.1 What ships

`STRIDE_BY_CAPABILITY` gains a companion, `STRIDE_BY_CWE`, and the resolution becomes per finding:

- Finding has CWEs → categories from the CWE map, `mapping_resolution: cwe`.
- Finding has none → today's behaviour exactly, `mapping_resolution: capability`.
- The response reports resolution **per row as well as per page**, because a repository will
  routinely be mixed, and a page-level label would be wrong for half of it.

The CWE→STRIDE table is data, in a reviewed file (`stride-map-v1.yaml`), not a dict in a module. It
is a taxonomy judgement — CWE-89 is Tampering and Information Disclosure, CWE-306 is Elevation of
Privilege — and taxonomy judgements belong where they can be argued with in a pull request, next to
`oracle-policy-v1.yaml` and `maturity-model-v1.yaml`.

### 2.2 What this fixes, concretely

Today a SQL-injection SAST finding and a hardcoded-credential SAST finding land in the same two
categories, because both are `sast`. Spec 18 §6 names this failure in its own prose. With CWE
resolution they separate, and the tab starts distinguishing kinds of threat rather than kinds of
tool.

## 3. The controls register

### 3.1 Current state

Nothing anywhere records a mitigation. Every row on the tab is a problem; there is no representation
of "authentication is required on this route", "this input is validated here", "these secrets rotate
on this cadence".

### 3.2 What ships

A per-repository controls register — a lake table `repo_controls`, one row per declared control:
`control_id`, `repo_full_name`, `stride` (which category it mitigates), `kind` (`authentication` |
`authorization` | `input_validation` | `output_encoding` | `secrets_management` | `logging` |
`rate_limiting` | `encryption`), `description`, `evidence_ref` (a file path, a route, a policy
document, a test id), `declared_by`, `declared_at`, `verified_by_capability`, `last_verified_at`.

**Admin-authored first, discovered later.** V1 is a form on the Threat Model tab. The entry-point
inventory in spec 23 §2 is what eventually populates it from the codebase, and the regression tests
in spec 31 are what eventually verify individual controls — but a register that waits for both stays
unbuilt for a year, and an admin-authored one is useful the day it ships. It is also honest: a
declared control says *a person asserted this*, which is a weaker and clearer claim than a machine
implying it.

**`verified_by_capability` is where the register stops being a wiki.** A control claiming
`authentication` on a route that DAST reports as unauthenticated is a contradiction the platform can
detect, and §4 renders it as one.

### 3.3 What does not ship

No control framework mapping — no ASVS, no SSDF, no CIS. Those are worth doing and they are a
compliance surface, not a threat model, and bolting one on before the register has any rows would
produce a coverage report over an empty set.

### 3.4 Corrected while building

**Operational store, not a lake table.** §3.2 above says "a lake table `repo_controls`". That was
wrong, and by this platform's own stated rule: everything in the lake is append-only because its
history is evidence — you have to be able to say what a finding looked like in March. A declared
control is not an observation. It is an editable statement about the present, corrected in place when
it turns out to be wrong, and the lake's compaction and partitioning model is built for scan results
(spec 05 §2). `RiskProfile`, `ReachabilityReport` and `TriageState` all already follow that
distinction; this now does too, and D-089 records the deviation rather than leaving the spec and the
code disagreeing.

**`verified_by_capability` is derived, never declared.** §3.2 lists it as a column somebody fills in.
It is a property of the *kind* — `authentication` can be contradicted by DAST, `secrets_management`
by the secrets lane, `logging` by nothing this platform runs — so accepting it from the caller would
let a control name a capability that cannot see it and thereby look checked. The API refuses the
field outright, and a kind nothing can check reports `checkable: false` rather than staying silent.

**One STRIDE category per control, not a list.** A control claiming to mitigate four categories is a
description of a subsystem rather than a control. Declaring it four times is both more honest and
individually verifiable, and it keeps the contradiction check per-category, which is where it has to
be to mean anything.

**Withdrawing deletes.** Unlike almost everything else in this platform, which flags rather than
removes. A control is a claim about the present; a withdrawn one is not evidence of anything, and
nobody needs to know that somebody once believed authentication was enforced. The audit entry records
who removed it, which is the part that matters. Offboarding a repository does the same to its whole
register, for the same reason — and while wiring that up it turned out `worklist.purge_for_repo`
(spec 27 §3) had been written and never called, so triage claims were surviving offboarding too.

## 4. Three states per category

A STRIDE category renders as exactly one of:

| State | Meaning |
|---|---|
| **Findings open** | what the tab shows today — the rows, ranked |
| **Unmitigated** | no findings, and no control declared for this category |
| **Mitigated** | no findings, and a declared control, with its evidence and when it was last verified |
| **Unscanned** | no capability that feeds this category has ever reported for this repository |

`Unscanned` is computed from the scan-health data the page already fetches. It is the state that
matters most, because it is the one currently rendering as good news.

A category can be both — findings open *and* a declared control — and that combination is shown
prominently rather than resolved: a control that exists while findings accumulate underneath it is
either wrong, bypassed, or narrower than its description, and each of those is worth somebody's
attention.

### 4.1 Built

The heading says three states and the table under it lists four; four is right and four shipped. The
order the states are tested in is the design: `unscanned` is checked before anything else, because
whatever else is true of a category nothing has ever looked at, `clean` is not it.

`scanned` is computed from capabilities that have actually *reported*, not from capabilities that are
enabled. A lane switched on last week and never run is exactly the gap this exists for: the
repository believes it is covered, and no failing run disagrees, because there is no run. It reuses
`last_successful_scan_at`, which already refuses to count a lane whose every run failed.

`unmitigated` renders in the muted tone rather than green. Scanned, clean and nothing declared is a
fine place to be and is not an achievement; colouring it like `mitigated` would put it level with a
category somebody actually built a control for.

## 5. Acceptance criteria

- A CodeQL SARIF upload whose rule carries `external/cwe/cwe-089` produces a finding with
  `cwe_ids: ["CWE-89"]`.
- A SQL-injection finding and a hardcoded-credential finding from the same SAST tool appear in
  different STRIDE categories, and each row states `mapping_resolution: cwe`.
- A finding from a tool that emits no tags keeps today's categories exactly, and its row states
  `mapping_resolution: capability`.
- A repository where DAST has never run shows its DAST-derived categories as **Unscanned**, never as
  empty.
- A declared `authentication` control on a repository with an open DAST authentication finding renders
  as a contradiction on the tab.
- Deleting the controls register leaves the tab working exactly as it does today — the register is
  additive, and a repository that declares nothing loses nothing.

## 6. Edge cases

- **A rule with five CWE tags**, common in Semgrep. The finding appears in every category its CWEs
  map to, deduplicated per category; occurrences are not multiplied.
- **A CWE not in `stride-map-v1.yaml`.** Falls back to capability mapping for that row and is counted
  in an "unmapped CWEs" line at the foot of the tab — visible so the map gets extended, rather than
  silently degrading.
- **A finding whose CWE and capability disagree** — a `secrets` finding tagged CWE-798. CWE wins;
  it is the more specific claim and the tool made it deliberately.
- **A control declared with no evidence reference.** Allowed, and rendered as a weaker claim ("asserted,
  no evidence") — refusing it would mean the register only ever holds the controls somebody had time
  to document.
- **A control whose `last_verified_at` is a year old.** Rendered as stale. A mitigation nobody has
  checked since last year is a belief, and the tab should say which of the two it is showing.
- **A repository with every category unscanned.** The tab says so at the top, once, rather than
  rendering six identical empty sections.

## 7. Dependencies

Spec 04 (the SARIF contract §1 extends — this is a second read of output already uploaded, not a new
scan), spec 05 (the new column and table follow the existing lake conventions), spec 18 §6 (the tab,
`mapping_resolution`, and the honest posture this keeps while making the resolution finer), spec 23 §2
(the entry-point inventory that eventually populates the register), spec 31 (regression tests as
evidence for `verified_by_capability`).
