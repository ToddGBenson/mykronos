"""Every configured task timeout against what the job has actually taken.

PS-7 says the numbers come from measurement, "comfortably above the worst
observed run", not from a target. Fifty of them were set from judgement in one
pass because there was no measured data to hand; there is now. A cap below the
observed worst case does not make a slow job fast, it makes a working job red.

Reads Concourse's API directly. It used to shell out to `fly builds` and parse
the human table, which meant it needed a logged-in target -- and its default
FLY path pointed into a different project's checkout, so it crashed with
FileNotFoundError before reaching any pipeline. The API is readable
anonymously, returns start/end timestamps rather than a formatted column, and
knows about every pipeline instead of the two that were hardcoded here.

    python scripts/audit_pipeline_timeouts.py
    CONCOURSE_URL=http://elsewhere:8080 python scripts/audit_pipeline_timeouts.py

Exit 0 when every cap clears its observed worst run with margin, 1 otherwise.
"""
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

import yaml

def _http_base(value, name):
    """An http(s) base, or nothing. `urlopen` honours `file://` (B-090).

    Concourse's answer is parsed with `json.load` straight off the response,
    so `CONCOURSE_URL=file:///etc/passwd` is a local file read wearing an
    API call's clothes. Nothing here is reachable by an attacker -- it is a
    developer script reading an env var -- and that is the reason to spend
    two lines on it rather than the reason not to: the check costs nothing
    and the next caller of `_api` may not be a developer script.

    Refused loudly rather than defaulted, because silently substituting
    localhost for what somebody typed is how an audit reports on the wrong
    Concourse.
    """
    scheme = urlsplit(value).scheme
    if scheme not in ("http", "https"):
        sys.exit(f"{name} must be an http:// or https:// URL, not {scheme or 'a bare path'!r}.")
    return value.rstrip("/")


CONCOURSE = _http_base(os.environ.get("CONCOURSE_URL", "http://127.0.0.1:8080"), "CONCOURSE_URL")
TEAM = os.environ.get("CONCOURSE_TEAM", "main")
#: Pipelines this repository holds the definition for. A pipeline Concourse
#: knows about and this checkout does not is somebody else's to audit.
PIPELINE_DIR = Path("deploy/concourse/pipelines")
HOOKS = {'preflight', 'report-to-hub', 'notify-slack'}
#: A failed build within this fraction of its cap is a timeout signature.
#: Not proof -- a job can fail at minute 59 of a 60m cap for its own reasons --
#: but it is the one sample the "worst SUCCESSFUL run" metric can never see,
#: and the jobs that matter most here are exactly the ones that never succeed.
TIMEOUT_MARGIN = 0.95

#: A cap must clear its job's worst observed run by at least this much. It is
#: the audit's pass threshold and it is also the floor used when SETTING a cap,
#: so a number chosen to satisfy this check is not one the check re-flags.
HEADROOM_FLOOR = 1.3

#: How far above its own routine worst a job's outlier run actually sits,
#: measured rather than assumed: the 90th percentile of `worst / p90` across
#: every job in the estate with at least ten successful builds.
#:
#: MEASURED 2026-09-18 over 53 such jobs: p50 2.65x, p75 4.02x, p90 5.10x,
#: p95 5.21x, max 8.16x. Recorded here because it is what the caps raised by
#: #60002 were derived from -- `cap >= max(p90 x OUTLIER_RATIO, worst x
#: HEADROOM_FLOOR)` -- and a derivation nobody can re-run is a round number
#: with a story attached. Re-measure it before leaning on it again; the estate
#: it describes is four pipelines whose jobs change.
OUTLIER_RATIO = 5.10

#: `(pipeline, job)` -> why this job is flagged and is NOT being given a bigger
#: cap. A waiver, not a suppression: the job still appears in the report, with
#: this reason beside it, and the run still says what it found.
#:
#: The bar for an entry is that raising the cap would be the WRONG FIX, not
#: that raising it is inconvenient. A cap exists to stop a hung task holding a
#: worker, so a hang is precisely the case where a bigger number makes things
#: worse: the job fails either way and burns the difference.
#:
#: `test_timeout_audit.py` holds these to the same rule
#: `ACKNOWLEDGED_UNMAPPED_JOBS` is held to -- every waiver must name a job that
#: exists in a pipeline file. A waiver outliving its job starts excusing a
#: future job that reuses the name.
TIMEOUT_WAIVERS = {
    ("thehub", "insider"): (
        "build #25 ran 15.3m against the 15m cap, but the log says "
        "`Are you sure you want to continue connecting (yes/no/[fingerprint])? "
        "timeout exceeded` -- it was waiting at an SSH host-key prompt, not "
        "working. Fixed by #496 (merged as #499) with StrictHostKeyChecking, "
        "not by a bigger number. Successful runs are p50 2.0m / p90 3.4m / "
        "worst 6.1m against 15m, so there is no evidence the task needs more "
        "time. Remove this when build #25 ages out of the sampled window."
    ),
}


def _observed_label(kind):
    """What the minutes beside a problem actually measure.

    Every row used to say "worst successful", including rows whose number came
    from a FAILED build that ran to its cap. Those are opposite facts and the
    reader acts on them differently.
    """
    return "worst successful" if kind == "headroom" else "a failed build ran"


def _api(path):
    with urlopen(f"{CONCOURSE}{path}", timeout=20) as response:
        return json.load(response)


def seconds(text):
    total, found = 0, False
    for value, unit in re.findall(r'(\d+)([hms])', text):
        total += int(value) * {'h': 3600, 'm': 60, 's': 1}[unit]
        found = True
    return total if found else None


def to_minutes(text):
    return seconds(text) // 60 if seconds(text) is not None else None


def walk(node, visit):
    if isinstance(node, dict):
        visit(node)
        for value in node.values():
            walk(value, visit)
    elif isinstance(node, list):
        for value in node:
            walk(value, visit)


def observed(pipeline):
    """job -> (worst successful duration in seconds, sample count, timeouts).

    `timeouts` is the count of FAILED builds that ran to within
    TIMEOUT_MARGIN of the job's cap. The original metric was the worst
    successful run, which is structurally blind to the jobs this audit exists
    for: `thehub/functional-dast` has eight builds and no successes, and two
    of the estate's security lanes were paused in August after dying with
    `timeout exceeded`. "No data" is the wrong thing to print about those.
    """
    worst, count, failed_durations = {}, {}, {}
    try:
        jobs = _api(f"/api/v1/teams/{TEAM}/pipelines/{pipeline}/jobs")
    except Exception as exc:  # noqa: BLE001 - an unreachable Concourse is reported, not raised
        print(f"  (could not read {pipeline} from {CONCOURSE}: {exc})")
        return worst, count, failed_durations

    for job in jobs:
        name = job.get("name")
        if not name:
            continue
        try:
            builds = _api(
                f"/api/v1/teams/{TEAM}/pipelines/{pipeline}/jobs/{name}/builds?limit=100"
            )
        except Exception as exc:  # noqa: BLE001 - one unreadable job is not the audit
            print(f'  (could not read builds for {pipeline}/{name}: {exc})')
            continue
        for build in builds:
            start, end = build.get("start_time"), build.get("end_time")
            if not start or not end:
                continue
            duration = int(end) - int(start)
            if build.get("status") == "succeeded":
                worst[name] = max(worst.get(name, 0), duration)
                count[name] = count.get(name, 0) + 1
            elif build.get("status") == "failed":
                failed_durations.setdefault(name, []).append(duration)
    return worst, count, failed_durations


problems = []
for path in sorted(PIPELINE_DIR.glob('*.yml')):
    pipeline = path.stem
    document = yaml.safe_load(path.read_text(encoding='utf-8'))
    worst, count, failed_durations = observed(pipeline)
    print('=' * 72)
    print(f'{pipeline}   ({sum(count.values())} successful builds sampled)')
    print('=' * 72)
    print(f"{'job':<18}{'cap':<8}{'worst ok':<11}{'n':<5}headroom")
    print('-' * 72)
    for job in document['jobs']:
        name = job['name']
        caps = []

        def visit(node, sink=caps):
            task = node.get('task')
            if isinstance(task, str) and task not in HOOKS and node.get('timeout'):
                sink.append((task, to_minutes(node['timeout'])))

        walk(job['plan'], visit)
        if not caps:
            continue
        # The job's own cap is the sum of its task caps, since they run in
        # sequence; compare that against the whole job's wall clock.
        total_cap = sum(minutes for _, minutes in caps)
        # A failed build that ran to within TIMEOUT_MARGIN of the cap is the
        # sample "worst successful run" can never contain, and it is the one
        # that matters: the cap is what ended it.
        # Against the LARGEST single task cap as well as the sum. A task
        # timeout fires on its own task, so a job whose caps sum to 145m dies
        # at 120m when its 120m task overruns -- and 120 is nowhere near 95%
        # of 145. `thehub/functional-dast` build 8 ran 120.4m against a 120m
        # `functional-and-scan` cap, and the sum-only test missed it.
        #
        # This does NOT catch every timeout. `thehub/cloud-posture` build 1
        # errored with `timeout exceeded` at 13.6m against a 60m task cap:
        # the step that timed out was a resource GET, pulling a 565 MB
        # prowler image, and no task cap was involved. Raising a task
        # timeout would not have helped it. Resource-get timeouts are a
        # different audit.
        biggest = max((m for _, m in caps), default=0)
        near_cap = [
            d for d in failed_durations.get(name, [])
            if (total_cap and d / 60 >= total_cap * TIMEOUT_MARGIN)
            or (biggest and d / 60 >= biggest * TIMEOUT_MARGIN)
        ]
        seen = worst.get(name)
        if seen is None:
            if near_cap:
                print(
                    f'{name:<18}{total_cap:<8}{"never ok":<11}{0:<5}'
                    f'!! {len(near_cap)} failed build(s) ran to the cap'
                )
                problems.append((pipeline, name, total_cap, round(max(near_cap) / 60)))
            else:
                print(f'{name:<18}{total_cap:<8}{"no data":<11}{0:<5}-')
            continue
        seen_min = seen / 60
        ratio = total_cap / seen_min if seen_min else 99
        flags = []
        if ratio < 1.0:
            flags.append(('headroom', '!! CAP BELOW OBSERVED WORST', round(seen_min)))
        elif ratio < HEADROOM_FLOOR:
            flags.append(('headroom', '!  under 30% headroom', round(seen_min)))
        # `and not flag` used to live here, so a job already carrying a headroom
        # flag never reported its timeouts. `mykronos/publish-frontend` had THREE
        # builds killed by the clock -- #78, #88, #89, all `timeout exceeded`
        # inside kaniko -- and the audit printed only "under 30% headroom" about
        # it. The two findings are different diagnoses with different fixes, and
        # the one that was being suppressed is the more serious of the pair: a
        # tight cap is a risk, a cap that has already fired is a build that died
        # for a reason unrelated to what it was checking. Both are reported now.
        if near_cap:
            flags.append((
                'timeout',
                f'!! {len(near_cap)} failed build(s) ran to the cap',
                round(max(near_cap) / 60),
            ))
        for kind, text, observed_minutes in flags:
            problems.append((pipeline, name, total_cap, observed_minutes, kind))
        shown = '  ' + '  '.join(text for _, text, _ in flags) if flags else ''
        print(f'{name:<18}{total_cap:<8}{round(seen_min):<11}{count.get(name, 0):<5}{ratio:.1f}x{shown}')
    print()

waived, unwaived = [], []
for problem in problems:
    pipeline, name = problem[0], problem[1]
    if (pipeline, name) in TIMEOUT_WAIVERS:
        waived.append(problem)
    else:
        unwaived.append(problem)

if waived:
    print('Waived, with the reason recorded:')
    for pipeline, job, cap, observed_minutes, kind in waived:
        print(f'  {pipeline}/{job}: cap {cap}m, {_observed_label(kind)} {observed_minutes}m')
        print(f'      {TIMEOUT_WAIVERS[(pipeline, job)]}')
    print()

if unwaived:
    print('Caps to raise:')
    for pipeline, job, cap, observed_minutes, kind in unwaived:
        # The label used to read "worst successful" for every row, including
        # rows whose number came from a FAILED build that ran to the cap. Those
        # are opposite facts -- one says the job finished in that time, the
        # other says it was killed at it -- and printing the wrong one sends the
        # reader looking for a slow success that never happened.
        print(f'  {pipeline}/{job}: cap {cap}m vs {_observed_label(kind)} {observed_minutes}m')
    sys.exit(1)
print('every cap clears its observed worst run with margin')
