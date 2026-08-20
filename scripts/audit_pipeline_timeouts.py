"""Every configured task timeout against what the job has actually taken.

PS-7 says the numbers come from measurement, "comfortably above the worst
observed run", not from a target. Fifty of them were set from judgement in one
pass because there was no measured data to hand; there is now. A cap below the
observed worst case does not make a slow job fast, it makes a working job red.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

FLY = os.environ.get("FLY", str(Path.home() / "Documents/Projects/PDSO2/deploy/concourse/bin/fly.exe"))
PIPELINES = {
    'mykronos': 'deploy/concourse/pipelines/mykronos.yml',
    'thehub': 'deploy/concourse/pipelines/thehub.yml',
}
HOOKS = {'preflight', 'report-to-hub', 'notify-slack'}


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
    """job -> (worst successful duration in seconds, sample count)."""
    out = subprocess.run([FLY, '--target', 'mykronos', 'builds', '-p', pipeline, '-c', '400'],
                         capture_output=True, text=True, encoding='utf-8', errors='replace', check=False).stdout
    worst, count = {}, {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or '/' not in parts[1]:
            continue
        job = parts[1].split('/')[1]
        status = parts[2]
        if status != 'succeeded':
            continue
        duration = next((seconds(p) for p in reversed(parts) if seconds(p) is not None), None)
        if duration is None:
            continue
        worst[job] = max(worst.get(job, 0), duration)
        count[job] = count.get(job, 0) + 1
    return worst, count


problems = []
for pipeline, path in PIPELINES.items():
    document = yaml.safe_load(Path(path).read_text(encoding='utf-8'))
    worst, count = observed(pipeline)
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
        seen = worst.get(name)
        if seen is None:
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
        print(f'{name:<18}{total_cap:<8}{round(seen_min):<11}{count.get(name, 0):<5}{ratio:.1f}x{flag}')
    print()

if problems:
    print('Caps to raise:')
    for pipeline, job, cap, seen in problems:
        print(f'  {pipeline}/{job}: cap {cap}m vs worst successful {seen}m')
    sys.exit(1)
print('every cap clears its observed worst run with margin')
