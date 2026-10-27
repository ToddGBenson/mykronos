## D-173 — Triage evidence is shown with its working, and model verdicts are graded before they act

**2026-10-22.** **Status:** Decided, implemented
**Stories:** TheHub #60889 (T2), #60890 (T3), #60893 (T6) of epic #60879 · Refs D-168, D-169, #60748, #713, [spec 17 §4](../../specs/17-harness-threat-intel-and-i2i.md), [spec 27 §1](../../specs/27-the-worklist.md)

Three rules for the evidence the triage workbench puts beside a finding.

**1. The rescore panel recomputes when the store is behind.** The record page
shows the environmental rescore as three ordered steps - base, environmental
(every fact, applied or not, as `metric from -> to` with its freshness:
`fresh`, `expiring` within 7 days, `lapsed`, `undated`), effective (the
scanner's word moved by the band shift, plus the KEV floor Oracle applies). It
reads the stored `EnvironmentalScore` only while that row still describes the
evidence: same vector, same scanner severity, no applied lowering fact
lapsed, and no evidence marked for the repository since that row was
computed (a mark the stored score already read does not count). Otherwise it computes on
read and says why (`recomputed_because`). The panel explains
`environment.score_vector` and `environment.effective_severity`; it never
computes a number of its own, so it cannot disagree with the store.

**2. Exploitability is a ladder with named sources.** `exploited` (CISA KEV)
> `weaponized` (a Metasploit module) > `public_poc` (Exploit-DB, or an NVD
reference tagged `Exploit` - which is where GitHub proofs of concept appear)
> `elevated_epss` (EPSS >= 0.1) > `no_known_exploit` (every source answered,
nothing found) > `not_checked` > `no_cve`. `no_known_exploit` and
`not_checked` are never merged: "nobody looked" must not read as "there is
nothing". Every source that spoke is listed with a link and the date it was
read, whatever the verdict. Fix availability is reported beside it
(`fix_available`, `no_fix_published`, `not_a_package`).

The catalogs follow `threat_intel`'s rules: public and unauthenticated, only
CVEs an open finding names are stored, and a feed that fails keeps what it
said before. NVD references are read in the same request as the vector, so a
row looked up before this change is eligible for exactly one more lookup.

The verdict reaches the rank as one term, `public_exploit` (policy 1.17):
15 points for `weaponized`, 8 for `public_poc`, and **never on top of
`in_kev`**, which already carries the larger term for the worse fact. No risk
score changes.

**3. Model proposals are recorded and graded, never applied.** A model that
has read the code records a proposed verdict (`true_positive`,
`false_positive`, `suppressed`, `accepted_risk`) under the
`finding_disposition` duty in `model_triage_proposals`, with its exact model
id, rationale, confidence and what it read. Nothing reads that table to change
a finding or to raise an approval. Each proposal is graded against the first
verdict a **person** (audit `actor_kind = human`) recorded **after** it, or a
scanner observing the finding fixed, which confirms `true_positive`; so
does a person reopening it, or accepting its risk (operator decision on
#1006). A
proposal made after the verdict could have read it and is `ineligible`, not
agreement. Grades are per model id and per model's latest proposal per
finding.

**Not done here.** Running a model over the code is not wired in: it sends
repository source to an external model (an opt-in in this platform, like
`ai_classifier_url`) and needs a credential, so turning it on is the
operator's decision. Letting graded proposals act is a later decision on
these numbers, not something this record grants.
