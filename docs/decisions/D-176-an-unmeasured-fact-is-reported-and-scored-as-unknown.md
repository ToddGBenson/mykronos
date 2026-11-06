## D-176 — An unmeasured fact is reported and scored as unknown, never as its comfortable answer

**2026-11-04.** **Status:** Decided, implemented (Oracle policy 1.19)
**Story:** TheHub #61349 · Refs D-116, D-145, B-041, [spec 17 §4.4](../../specs/17-harness-threat-intel-and-i2i.md), [spec 21 §1](../../specs/21-oracle-depth-and-risk-profile.md)

**The rule.** Where the platform has not measured a fact, what it says and what
it scores must not be the answer a measurement would have given if it had come
back clean. Five places broke that. Each now keeps the unknown as its own state:

| Where | Was | Now |
|---|---|---|
| Oracle exploitability snapshot (`oracle/engine.py`) | a CVE with no `ThreatIntelMatch` row counted as not KEV-listed, and the reason read "none is in CISA's KEV catalog" | each match carries `kev_checked`; the snapshot adds `kev_checked_findings`, `kev_not_checked_findings` and `kev_not_checked_cves`; the reason claims "not listed" only for the CVEs that were checked and says "KEV status not checked for N CVE(s)" for the rest |
| Work queue and threat-intel list (`dashboard.py`) | `in_kev: false` for a CVE never fetched; a null EPSS added no term, the same as EPSS 0, and the threat-intel list's "nulls last" sort tied a null with a measured 0 | `in_kev` is null until the CVE is fetched (`exploit_verdict` already says `not_checked`); a row naming a CVE always carries an `epss` term, at zero points, reading "EPSS not scored yet — unknown, not zero" or "EPSS 0.00"; at an equal rank an unscored row is listed above a measured one; the threat-intel list sorts nulls after a measured 0 |
| Oracle risk profile (`oracle/engine.py`, policy 1.19) | `internet_facing: null` on a recorded profile added nothing, the same as `false` | it adds `risk_profile.internet_facing_unknown_points` as its own term, and the snapshot carries `internet_facing_state` (`internet_facing`, `not_internet_facing` or `unknown`) |
| Risk-profile proposals (`risk_profile_builder.py`) | a declared surface's exposure proposed `internet_facing` at `observed`; so did any open network or cloud finding | a declared surface proposes at the new `declared` confidence; a network or cloud finding proposes at `inferred`, because the lake does not record where the scanner stood |
| Next-sprint ranking (`sprint_signal.py`) | an unknown severity weighed 1.0, which is `low`'s weight | it carries no weight, and the candidate's line says how many findings could not be weighed |

**Why the unknown internet exposure scores at the internet-facing weight.**
Three choices were open: zero (what it was, and the same as `false`), a middle
figure, or the worst answer. A middle figure is a number nobody could defend.
The worst answer is what CVSS's environmental metrics do with an undefined
modifier, and it is what the risk-profile proposal page has told every reader
the score does ("the score assumes the worst") since B-041, while it did not.
So 1.19 ships `internet_facing_unknown_points: 10`, equal to
`internet_facing_points`. The reasoning names the term "Internet exposure
unknown", never "Internet-facing". The operator can lower it in the policy file
with the usual version bump.

**What does not change.** No profile at all is still `available: false` and
adds nothing: an absent profile is its own state (spec 21 §1), and scoring it
would move every unprofiled repository on deploy day. A recorded `true` or
`false` scores as it did. Only a KEV listing boosts a score, so the KEV change
moves no number. The EPSS term at zero moves no rank; only the order of rows
whose rank is already equal changes. When environmental scoring is live for a
repository, the unknown term is trimmed with the internet-facing one
(`oracle/environmental.py` `DOUBLE_COUNTED`), because an unset profile leaves
the vector's attack vector at its base (network) value, which already counts it.

**Not done here.** Data classification and business criticality left unset on a
recorded profile still add nothing. The same argument applies to them; they were
outside the story, and changing them would move more scores. That is a follow-up
for the operator to choose. Network findings are not yet told apart by vantage
(the WAN-edge lane against a LAN sweep), which would let a WAN-edge finding
propose `observed` again.

**Guard.** `backend/tests/test_unknown_is_unknown.py` has one class per row of the
table. It was red on main (21 of 22 failed; the one that passed is the guard that
a row naming no CVE gets no EPSS term).
