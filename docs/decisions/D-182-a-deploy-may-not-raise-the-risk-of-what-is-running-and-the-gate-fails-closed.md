## D-182 — A deploy may not raise the risk of what is running, and the gate fails closed

**2026-11-15.** **Status:** Decided (operator), implemented for MyKronos's deploy; TheHub's deploy adopts the same endpoint in a TheHub follow-up
**Story:** operator decision 2026-11-15 ("ratchet") · supersedes D-126's fail-open posture and D-159 for deploys · follows D-048, #734, TheHub #61063

**The decision (operator, 2026-11-15), as given.**

> The oracle verdict is enforced on deploys of TheHub and MyKronos as follows:
> (a) a deploy of commit C for repo R is REFUSED if C's oracle decision raises
> R's risk relative to the commit currently deployed (raw_score higher than the
> deployed commit's decision, beyond a small tolerance, e.g. 0.5) OR C has an
> open high/critical finding that the deployed commit did not (introduced);
> (b) once R's decision is below the No-Go threshold (policy no_go, currently
> 70; i.e. Needs review or Go), a No-Go decision is a hard refusal ("latched":
> record per repo when it first reached < no_go);
> (c) the gate FAILS CLOSED: no decision, an unreachable oracle, or an unknown
> deployed baseline is a refusal with a named reason, never a pass;
> (d) a fix deploy that lowers the score is allowed even while R is still No-Go.

**Operator decisions later the same day (2026-11-15).** Two amendments, as given:

> While a repo is latched and the candidate is still No-Go, ALLOW only if the
> candidate lowers the score by more than the tolerance and introduces no high
> or critical; refuse everything else, with no repair exemption.

This replaces (b) as literally applied (see item 6). And the cost the
independent review named, accepted: a down backend or sealed Vault refuses
(`risk_unasked`) and needs the operator's `-Force` with a reason.

And the Product Owner's note on the same day, from live data: MyKronos main
`b11c74a6` scored raw 166.3 against the deployed `0e9a8886` at 165.2, and the
whole 1.1 was three otel-sdk mediums in two infrastructure images and a dpkg
low, all first seen 2026-11-14 04:54 because the CVEs were published then. The
baseline decision had been evaluated a day earlier. So the comparison must be
over one findings snapshot, and a finding that also affects the deployed
commit is not introduced by C; otherwise the ratchet refuses every deploy
whenever a CVE is published.

**What that means in this code.**

1. **`GET /api/oracle/deploy-gate?repo=&commit=&deployed=`** answers
   `allow`/`refuse` with every applicable reason code, the two scores, the
   introduced critical/high ids and the latch
   (`backend/mykronos/oracle/deploy_gate.py`). Always 200; a caller treats a
   non-200 or a body without `allow` as a refusal. An identical question is
   answered from a 15-second cache while nothing it read has changed (the
   lake's files, the latch, the creep ledger), so polling it cannot make the
   backend evaluate the backlog on every request.
2. **No stored score is compared, and every term is re-scored.** Oracle's
   score is the whole open backlog, so two stored decisions differ by whatever
   the vulnerability database did between them. The backlog is evaluated once,
   now (an unpublished `commit_gate` evaluation of C), and BOTH scores are that
   evaluation turned back into the state each commit carried: the findings it
   did not have are taken out and the closed ones it did have are put back.
   Every term a finding moves is re-scored from the snapshot, not only the
   severity bands: the bands with their dampened, in-flight and
   no-upstream-fix tallies, the age terms, the KEV boost
   (`exploitability.<id>`), toxic combinations (detected again over the edited
   findings) and the No-Go a critical one forces, blast radius and overdue
   findings. A CVE published since D was scanned is in both states and
   cancels. Reconstructing C too, rather than taking C to be "now", is what
   stops a candidate older than the branch head hiding a high it introduced
   and a later commit fixed. The stored decisions are reported beside the two
   scores for reference only.
3. **Introduced means blocking by effective severity.** A finding C carries
   and D does not refuses the deploy when it is critical or high, when a KEV
   listing boosts it to high or critical, or when it is a member of a high or
   critical toxic combination in C's state.
4. **Which commit carries a finding.** There is no occurrence table, and a
   finding's `last_seen_scan_run_id` is overwritten by any scan, pull-request
   scans included, so the rule is the conservative one. An open finding is
   carried by commit X unless it was introduced after X: first seen after X's
   first push scan on the branch, by any scan that is not of X or of a commit
   pushed before X, whichever kind of scan saw it first or last; or first seen
   on a pull request scanned before X whose pull request was scanned again
   after X existed. Minus what `DashboardQueries.split_disclosed` calls newly
   disclosed (a CVE in an image whose bytes did not change, corroborated in
   rebuilt images, a renamed tool image, a dependency version the baseline
   already carried), which every commit carries; a renamed image's old-name
   findings, closed by absence, are not put back on either side. A finding
   only its own pull request ever saw is on no branch and is the same on both
   sides. A closed finding is carried by X when it was not introduced after X
   and its last sighting is no earlier than X's last push scan of the same
   capability, so a rescan of D (the daily image refresh) does not credit D
   with a finding a range commit introduced and fixed. Where a finding cannot
   be placed it counts against C. The one case not placed: a pull request
   whose every scan predates D and that merged after D without being scanned
   again. A branch that is empty (push scans with no branch) is no line of
   history: `baseline_unknown`.
5. **Fix credit waits for two missed scans.** A finding is credited as fixed
   only once absence reconciliation has closed it, so a fix may read as
   "unchanged" until its second scan, which is still an allow. The answer says
   so (`fix_credit_pending`, and "Fix credit pending" in the message and on
   deploy.ps1's allow line), so nobody re-deploys to chase it.
6. **A rollback is the same reconstruction.** C lacks what the commits after
   it introduced and carries again what they fixed, so rolling back past a
   security fix is refused as introducing it.
7. **The tolerance is 0.5 in total, a constant, and a budget across
   deploys.** Half a point of the published integer score. Because both
   scores are one snapshot, it does not absorb drift; it absorbs the smallest
   real changes, which the log curve (D-018) makes tiny in a large band (one
   more medium on 13 adds 0.497). A critical or high is never let through by
   it. It does not reset per deploy: `oracle_ratchet_creep` keeps each
   repository's accumulated rise (`accepted_creep` in the answer), and
   `score_raised` refuses when that plus this deploy's rise passes 0.5, so
   three +0.3 deploys are refused at the second. A lowering subtracts its fall,
   never below zero: a net lowering pays the creep back, a token fall between
   two rises does not clear it. The gate learns that a deploy went through
   from the next question, not from the answer: an allow records its delta as
   pending against the candidate sha, and the next check that names that sha
   as the running baseline adds it. A candidate asked about and never run adds
   nothing; a forced deploy is never allowed, so it adds nothing either, and
   its record is deploy.ps1's ledger. A constant for the reason the floor is
   one.
8. **The latch** is `oracle_ratchet_latches`, one row per repository, written
   when a recorded decision (`/evaluate`) or a ratchet check first measures a
   raw score below `policy.no_go` with a `go` or `review_recommended`
   recommendation; `not_assessed` never latches. Never moved or cleared by
   code. No backfill from history: a repository latches the next time it is
   measured below the threshold. While latched, a candidate at or above No-Go
   is allowed only as the operator's amendment says: it lowers the score by
   more than the tolerance and introduces no critical or high
   (`lowered_while_latched`). Everything else at or above No-Go is refused
   `latched_no_go`, including a No-Go that is the backlog rather than the
   change (the refusal says which), with no repair exemption. Unlatched, a
   No-Go that does not raise the score is allowed (d).
9. **Fails closed.** `no_decision` (the gate never scored C, the state
   deploy.ps1 waits on), `not_assessed`, `baseline_unknown`,
   `baseline_disagrees`, `evaluation_failed`; on the client side an
   unreachable platform, a missing token, or a body that is not a verdict.
   The latch or creep store unreadable is `evaluation_failed`, never "not
   latched" or "no creep". An evaluation that raises answers with a generic
   message and an `error_id`; the detail is in the backend log, never in the
   response. A commit prefix is resolved to the one full sha the lake knows
   before its decision is read, so a prefix cannot borrow another commit's
   decision.
10. **The baseline is what runs.** The deploy host names D from the running
   container's build stamp (`MYKRONOS_BUILD_SHA`; TheHub's `HUB_BUILD_SHA`).
   For this platform's own repository the backend answering is the
   deployment, so its own `build_sha` is authoritative and a caller naming
   anything else is refused `baseline_disagrees`. For any other repository the
   deployment probe's last reading (#361) is reported beside the caller's
   claim and used when the caller names none; it is not a refusal on its own,
   because the probe runs half-hourly and lags every deploy.
11. **deploy.ps1 and the watcher use it.** `deploy.ps1` asks the ratchet and
   stops before anything is pulled on anything but an explicit allow; the
   pre-move refusal kinds are `risk_refused`, `risk_not_judged`,
   `risk_unasked`. `AutoDeploy.ps1`'s decision skips with `ratchet_unread` or
   `ratchet_refused`, and validates and URL-escapes both shas before asking.
   `-Force` still ships and still requires `-ForceReason`, recorded before
   the pull; it is the operator's alone, and agents never pass it.
   `-PlatformUrl` accepts only `http://127.0.0.1:8100`: since the gate fails
   closed, the address asked is the gate, and a listener elsewhere answering
   `allow` would otherwise ship anything with no override in the ledger.
   Every ledger line records `asked`. There is no `-Repo`: the script deploys
   MyKronos only.
12. **A platform override no longer clears a refusal.** Before D-182 a
   recorded override on the commit's decision cleared the floor
   (`test_a_recorded_override_clears_the_floor`). The ratchet reads the
   decision's `recommendation`, never an override, so an override changes
   nothing for any later check. deploy.ps1 `-Force` still records one against
   the decision, with the refusal's codes in its reason, as a record of the
   human call and not as a key.

**What it costs.** D-126 chose fail open on a measured case: Vault sealed four
days in September 2026, and a fail-closed gate would have blocked the deploy
that fixed it. That cost is now accepted, and its answer is the operator's
`-Force` with a reason. The backend that answers the ratchet is the one being
deployed, so a deploy that repairs a down backend always needs `-Force`. The
latch's literal reading also means a backlog pushed over No-Go by a newly
published CVE refuses every deploy, fixes included, until the backlog is
lowered or an override is recorded; that is the operator's (b) as written, and
the refusal names it so it can be revisited.

The operator revisited it the same day (above): a latched No-Go candidate that
lowers the score by more than the tolerance and introduces no critical or high
now ships, so the fix for the CVE that caused the No-Go does not need
`-Force`. A latched No-Go that is unchanged or raised still refuses, with no
repair exemption.

**Not changed.** The Concourse `oracle-gate` job still refuses only an
introduced critical or high (D-048, D-159); it judges a commit, not a deploy.
TheHub's `scripts/lib/risk_gate.py` is TheHub's to change; the contract it
should call is the endpoint above.
