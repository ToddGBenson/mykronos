"""Judging a network-assessment run — spec 32 §4.4.

The scan itself does not run here and never has. It runs on Windows under the
"personal-soc Weekly Network Scan" Scheduled Task, because an nmap sweep from a
container reported all 256 addresses of `192.168.0.0/24` up — Docker Desktop's
NAT answers every probe — while the host's ARP table had 38 entries, and
MAC-keyed inventory needs L2 adjacency a container does not have. A scan from
anywhere else would be confidently, quietly wrong.

What *was* in Concourse is the half Concourse was good at: deciding whether the
run that arrived is worth believing, and saying what changed. That is this
module. It ran there because Concourse was the only scheduler available, not
because it needed a pipeline — it consumes no source, and is triggered by an
artifact appearing rather than by a commit.

**The failure this exists to catch is the Scheduled Task degrading rather than
dying**: still writing `network-status.md` every week, with the checks inside
it no longer running. That is why an `unknown` line is a failure here and not a
warning — a scan that resolved nothing is not a clean scan, and a NAS that is
simply switched off must not read the same as one confirmed closed.

**Transport is deliberately not here.** Every function takes files that are
already in hand. Whether they arrive by the backend pulling from MinIO (which
needs an S3 client the backend does not currently have) or by the host's
existing `publish-netassess-run.ps1` pushing them to an ingestion endpoint is
an open decision, and it is one this module does not need to have made: the
judgement is the same either way, and it is the part that was worth porting.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from datetime import date, datetime

#: `netassess-2026.8.9.zip` — the name the publisher writes. Components are not
#: zero-padded, which is why ordering is by parsed date rather than by string:
#: `sort` puts `2026.8.10` before `2026.8.9` and would compare every week
#: against the same stale baseline. The Concourse job used `sort -V` for the
#: same reason.
_KEY = re.compile(r"^netassess-(\d{4})\.(\d{1,2})\.(\d{1,2})\.zip$")

#: Lines in `network-status.md` that describe real exposure. Matched as
#: substrings against the rendered report, exactly as the shell did — the file
#: is written by the assessment skill and its phrasing is the contract.
EXPOSURE_MARKERS: dict[str, str] = {
    "EXPORTS PRESENT": "NAS is exporting NFS shares",
    "SMBv1 ENABLED": "NAS has SMBv1 enabled",
    "broadcasting": "an open Wi-Fi AP is broadcasting",
}


def run_date(key: str) -> date | None:
    """`netassess-2026.8.9.zip` -> 2026-08-09, or None if it is not a run."""
    match = _KEY.match(key.rsplit("/", 1)[-1])
    if match is None:
        return None
    year, month, day = (int(part) for part in match.groups())
    try:
        return date(year, month, day)
    except ValueError:
        # A key shaped like a run but naming 2026.13.40. Not a run, rather than
        # a crash in something that runs unattended.
        return None


def newest(keys: list[str]) -> str | None:
    """The most recent run among `keys`, by parsed date rather than by name."""
    dated = [(run_date(key), key) for key in keys]
    runs = [(when, key) for when, key in dated if when is not None]
    if not runs:
        return None
    return max(runs)[1]


@dataclass(frozen=True)
class Freshness:
    """Whether the Scheduled Task is still producing runs."""

    newest_key: str | None
    newest_date: date | None
    age_days: int | None
    max_age_days: int
    #: Populated when the cadence has failed. Empty is healthy.
    problem: str | None = None

    @property
    def healthy(self) -> bool:
        return self.problem is None


def freshness(keys: list[str], *, now: date, max_age_days: int = 10) -> Freshness:
    """Has a scan been published recently enough to still mean anything.

    Separate from `verify` because they fail for different reasons and need
    different responses: a stale run is a Scheduled Task that stopped, and a
    bad run is one that ran and resolved nothing.
    """
    key = newest(keys)
    if key is None:
        return Freshness(
            newest_key=None,
            newest_date=None,
            age_days=None,
            max_age_days=max_age_days,
            problem=(
                "No network scan has ever been published. The Windows Scheduled "
                "Task 'personal-soc Weekly Network Scan' has never produced a run, "
                "or the publish step has never succeeded."
            ),
        )

    when = run_date(key)
    assert when is not None  # `newest` only returns parseable keys
    age = (now - when).days
    problem = None
    if age > max_age_days:
        problem = (
            f"No network scan published in {age} days. The Windows Scheduled Task "
            "'personal-soc Weekly Network Scan' has stopped producing runs, or the "
            "publish step is failing."
        )
    return Freshness(
        newest_key=key,
        newest_date=when,
        age_days=age,
        max_age_days=max_age_days,
        problem=problem,
    )


@dataclass(frozen=True)
class Host:
    """One row of `inventory.csv`, keyed the way the file is keyed."""

    mac: str
    address: str
    label: str

    def __str__(self) -> str:
        return f"{self.address} {self.label}".strip()


def hosts(inventory_csv: str) -> dict[str, Host]:
    """Parse `inventory.csv` into hosts by MAC.

    MAC-keyed because that is what the file is keyed by and what survives a
    DHCP lease moving a device to a new address. Uppercased so a case change in
    the writer does not read as every host being replaced at once.

    Columns are read by position — address, MAC, label — because that is what
    the shell did (`cut -d, -f2` and `-f1,3`) and changing the contract while
    porting would be a second change hiding inside the first.
    """
    out: dict[str, Host] = {}
    reader = csv.reader(io.StringIO(inventory_csv))
    for index, row in enumerate(reader):
        if index == 0 or len(row) < 2:
            # Header, or a line too short to identify anything.
            continue
        mac = row[1].strip().strip('"').upper()
        if not mac:
            continue
        out[mac] = Host(
            mac=mac,
            address=row[0].strip().strip('"'),
            label=row[2].strip().strip('"') if len(row) > 2 else "",
        )
    return out


@dataclass(frozen=True)
class HostDiff:
    appeared: list[Host] = field(default_factory=list)
    disappeared: list[Host] = field(default_factory=list)
    #: Why there is no comparison, when there is none. A first run and a run
    #: whose predecessor had no inventory are different facts.
    unavailable: str | None = None

    @property
    def changed(self) -> bool:
        return bool(self.appeared or self.disappeared)


def diff_hosts(previous: str | None, current: str | None) -> HostDiff:
    """What appeared and what went away, between two inventories."""
    if previous is None:
        return HostDiff(unavailable="No earlier run to diff against yet.")
    if current is None:
        return HostDiff(unavailable="This run has no inventory.csv.")

    before, after = hosts(previous), hosts(current)
    return HostDiff(
        appeared=[after[mac] for mac in sorted(set(after) - set(before))],
        disappeared=[before[mac] for mac in sorted(set(before) - set(after))],
    )


@dataclass(frozen=True)
class Verdict:
    """Whether this run is worth believing, and what it found.

    `problems` are reasons to disbelieve the run or to act on it — the
    Concourse task's `note()`, which set `fail=1`. Kept as a list rather than a
    boolean because "the scan did not finish" and "the NAS is exporting NFS"
    are both failures and want different responses.
    """

    problems: list[str] = field(default_factory=list)
    host_count: int = 0
    diff: HostDiff = field(default_factory=HostDiff)

    @property
    def believable(self) -> bool:
        return not self.problems


def verify(
    *,
    inventory_csv: str | None,
    network_status_md: str | None,
    previous_inventory_csv: str | None = None,
) -> Verdict:
    """Decide whether the run that arrived is worth believing (spec 32 §4.4).

    A faithful port of the Concourse task's four checks, in its order:

    1. Is this a real scan — is there an inventory, and does it have rows?
    2. Did every check actually run — an `unknown` line means nmap could not
       answer, so the target was not assessed. Passing on that would let a NAS
       that is simply switched off read the same as one confirmed closed.
    3. Actual exposure — the three markers the report writes.
    4. What changed since the previous run.

    The posture-score comparison the task also ran is deliberately absent: it
    shells out to `Compare-Assessment.ps1` against `findings.json`, which is
    written by a full skill engagement rather than by the weekly scan, and the
    task already skipped it whenever that file was missing — which is every
    weekly run.
    """
    problems: list[str] = []

    if inventory_csv is None:
        problems.append("No inventory.csv — the run enumerated nothing.")
        host_count = 0
    else:
        host_count = len(hosts(inventory_csv))
        if host_count < 1:
            problems.append("inventory.csv is empty — the run enumerated nothing.")

    if network_status_md is None:
        problems.append("No network-status.md — the scan did not finish.")
    else:
        unknown = [
            line.strip()
            for line in network_status_md.splitlines()
            if "unknown" in line.lower()
        ]
        if unknown:
            problems.append(
                "A check reported 'unknown' — it did not run, so it is not a pass: "
                + "; ".join(unknown[:5])
            )
        for marker, meaning in EXPOSURE_MARKERS.items():
            if marker in network_status_md:
                problems.append(meaning)

    return Verdict(
        problems=problems,
        host_count=host_count,
        diff=diff_hosts(previous_inventory_csv, inventory_csv),
    )


def summarise(verdict: Verdict, fresh: Freshness) -> str:
    """One human-readable block, the way the Concourse task's log read.

    Kept here rather than at a call site because both the scheduled job and any
    future ingestion endpoint want the same words, and two renderings of one
    verdict is two things to keep in step.
    """
    lines: list[str] = []
    if fresh.newest_date is not None:
        lines.append(
            f"newest run: {fresh.newest_date.isoformat()} "
            f"({fresh.age_days} days old, limit {fresh.max_age_days})"
        )
    if fresh.problem:
        lines.append(f"  ! {fresh.problem}")

    lines.append(f"inventory rows: {verdict.host_count}")

    if verdict.diff.unavailable:
        lines.append(f"host changes: {verdict.diff.unavailable}")
    elif not verdict.diff.changed:
        lines.append("host changes: none")
    else:
        lines.append("host changes:")
        lines.extend(f"  + new  {host}" for host in verdict.diff.appeared)
        lines.extend(f"  - gone {host}" for host in verdict.diff.disappeared)

    if verdict.problems:
        lines.append("problems:")
        lines.extend(f"  ! {problem}" for problem in verdict.problems)
    else:
        lines.append("problems: none")

    return "\n".join(lines)


def utc_today(now: datetime | None = None) -> date:
    """Today in UTC, injectable so a test is not a function of the clock."""
    return (now or datetime.now()).date()
