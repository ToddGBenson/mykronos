## D-165 — The deployment probe presents a perimeter token per origin, and "N commits behind" is GitHub's count

**2026-10-19.** **Status:** Decided, implemented
**Story:** #452 · follows D-157 · Refs #361, TheHub #60709, D-131

**The rule.** The deployment probe sends `X-Hub-Token` only to an origin
named in `MYKRONOS_DEPLOYMENT_PROBE_TOKENS`, a JSON object from
`scheme://host[:port]` to a token. `@gate` stands for `MYKRONOS_GATE_TOKEN`
and `@hub` for `MYKRONOS_HUB_API_TOKEN`; anything else is the token itself.
An origin not listed gets no header. Redirects are not followed.

Once the probe has read a revision, the sweep asks the GitHub compare API
(the App client) for `<deployed>...<default branch>` and stores the answer on
`repo_onboardings.deployment_lag`. The behind count is GitHub's `ahead_by`.
The briefing and the dashboard read that stored answer and never call GitHub
while rendering. If the probe could not read a revision on this sweep, the
lag is `unknown`, stored with the probe's reason. It is never computed from
a revision an earlier probe read.

**Why per origin and not one token.** D-157 made `/healthz` serve `build.sha`
only to a caller presenting the perimeter token, and TheHub's `/health` did
the same (#60709). With no credential the probe read `unparsed` everywhere,
so production lag was unknowable. There are two hosts and two different
secrets (D-131). An admin can edit the probe URL. A single global token
would hand whichever secret it was to whatever host the URL names, and
following a redirect would do the same by another route.

**Why GitHub's count.** `deployments.py` called "commits behind main" a
question for the compare API and refused to approximate it. Dating the image
or counting scans would both be proxies presented as the measurement.

**Findings next to the number.** The lake records the fixing commit only for
Patchwork's own fixes (`remediation_events.verification_commit_sha`). So a
finding is tied to the undeployed range in two ways:

1. its merged fix's merge commit is in the range, or
2. it is closed on the branch, and the last scan that still saw it was of
   the deployed revision or a later commit.

Findings closed since the deployed revision was committed that neither rule
ties to the range are counted, not listed, and the count is labelled "may or
may not be running". This is the one approximation, and the page says so.

**Not chosen.** Sending `MYKRONOS_GATE_TOKEN` to every probe URL: it is the
host-wide secret. Auto-deploying on merge: #452 asked for the lag to be
reported, not closed (#424, #355).
