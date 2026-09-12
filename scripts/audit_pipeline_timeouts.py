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
from urllib.request import urlopen

import yaml

CONCOURSE = os.environ.get("CONCOURSE_URL", "http://127.0.0.1:8080").rstrip("/")
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
        flag = ''
        if ratio < 1.0:
            flag = '  !! CAP BELOW OBSERVED WORST'
            problems.append((pipeline, name, total_cap, round(seen_min)))
        elif ratio < 1.3:
            flag = '  !  under 30% headroom'
            problems.append((pipeline, name, total_cap, round(seen_min)))
        if near_cap and not flag:
            flag = f'  !! {len(near_cap)} failed build(s) ran to the cap'
            problems.append((pipeline, name, total_cap, round(max(near_cap) / 60)))
        print(f'{name:<18}{total_cap:<8}{round(seen_min):<11}{count.get(name, 0):<5}{ratio:.1f}x{flag}')
    print()

if problems:
    print('Caps to raise:')
    for pipeline, job, cap, seen in problems:
        print(f'  {pipeline}/{job}: cap {cap}m vs worst successful {seen}m')
    sys.exit(1)
print('every cap clears its observed worst run with margin')
