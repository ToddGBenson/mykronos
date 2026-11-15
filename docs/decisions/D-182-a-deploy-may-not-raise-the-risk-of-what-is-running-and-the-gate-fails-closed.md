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
   non-200 or a body without `allow` as a refusal.
2. **No stored score is compared.** Oracle's score is the whole open backlog,
   so two stored decisions differ by whatever the vulnerability database did
   between them. The backlog is evaluated once, now (an unpublished
   `commit_gate` evaluation of C), and the baseline is that same evaluation
   with the change taken out: the findings attributable to the commits between
   D and C are removed from the severity bands and the ones they fixed are put
   back, and only the bands are re-scored. A CVE published since D was scanned
   is in both scores and cancels. The stored decisions are reported beside the
   two scores for reference only.
3. **Attributable is the commit gate's rule.** First seen by a scan of a
   commit in the range, minus what `DashboardQueries.split_disclosed` calls
   newly disclosed (a CVE in an image whose bytes did not change, corroborated
   in rebuilt images, a renamed tool image, a dependency version the baseline
   already carried). A finding that also affects D is therefore never
   introduced by C. The range is read from the lake, not from the caller: the
   commits with push scans on the branch both were scanned on, first scanned
   after D and no later than C. A finding first seen by a pull-request scan
   counts when a push scan on the branch has seen it since D, because a squash
   merge's commit never "first sees" what its pull request reported. Where it
   cannot be placed precisely it counts against C. Fixes are credited only
   for findings D carried that absence reconciliation has closed (two missed
   scans), so a fix may read as "unchanged" until its second scan, which is
   still an allow.
4. **A rollback is the same range read the other way.** C lacks what the
   range introduced and carries again what it fixed, so rolling back past a
   security fix is refused as introducing it.
5. **The tolerance is 0.5, a constant.** Half a point of the published integer
   score. Because both scores are one snapshot, it does not absorb drift; it
   absorbs the smallest real changes, which the log curve (D-018) makes tiny
   in a large band (one more medium on 13 adds 0.497). A critical or high is
   never let through by it: rule (a)'s second clause refuses any introduced
   critical or high outright. A constant for the reason the floor is one.
6. **The latch** is `oracle_ratchet_latches`, one row per repository, written
   when a recorded decision (`/evaluate`) or a ratchet check first measures a
   raw score below `policy.no_go` with a `go` or `review_recommended`
   recommendation; `not_assessed` never latches. Never moved or cleared by
   code. No backfill from history: a repository latches the next time it is
   measured below the threshold. While latched, a candidate at or above No-Go
   is refused, including one whose No-Go is the backlog rather than the change
   (the refusal says which). Unlatched, a No-Go that does not raise the score
   is allowed (d).
7. **Fails closed.** `no_decision` (the gate never scored C, the state
   deploy.ps1 waits on), `not_assessed`, `baseline_unknown`,
   `baseline_disagrees`, `evaluation_failed`; on the client side an
   unreachable platform, a missing token, or a body that is not a verdict.
   The latch store unreadable is `evaluation_failed`, never "not latched".
8. **The baseline is what runs.** The deploy host names D from the running
   container's build stamp (`MYKRONOS_BUILD_SHA`; TheHub's `HUB_BUILD_SHA`).
   For this platform's own repository the backend answering is the
   deployment, so its own `build_sha` is authoritative and a caller naming
   anything else is refused `baseline_disagrees`. For any other repository the
   deployment probe's last reading (#361) is reported beside the caller's
   claim and used when the caller names none; it is not a refusal on its own,
   because the probe runs half-hourly and lags every deploy.
9. **deploy.ps1 and the watcher use it.** `deploy.ps1` asks the ratchet and
   stops before anything is pulled on anything but an explicit allow; the
   pre-move refusal kinds are `risk_refused`, `risk_not_judged`,
   `risk_unasked`. `AutoDeploy.ps1`'s decision skips with `ratchet_unread` or
   `ratchet_refused`. `-Force` still ships and still requires `-ForceReason`,
   recorded before the pull; it is the operator's alone, and agents never
   pass it.

**What it costs.** D-126 chose fail open on a measured case: Vault sealed four
days in September 2026, and a fail-closed gate would have blocked the deploy
that fixed it. That cost is now accepted, and its answer is the operator's
`-Force` with a reason. The backend that answers the ratchet is the one being
deployed, so a deploy that repairs a down backend always needs `-Force`. The
latch's literal reading also means a backlog pushed over No-Go by a newly
published CVE refuses every deploy, fixes included, until the backlog is
lowered or an override is recorded; that is the operator's (b) as written, and
the refusal names it so it can be revisited.

**Not changed.** The Concourse `oracle-gate` job still refuses only an
introduced critical or high (D-048, D-159); it judges a commit, not a deploy.
TheHub's `scripts/lib/risk_gate.py` is TheHub's to change; the contract it
should call is the endpoint above.
