"""The weekly LAN scan, and its freshness, as network findings (TheHub #60813).

personal-soc's Windows Scheduled Task scans the LAN (a container cannot: see
`mykronos.netassess`) and publishes a zip to MinIO. Its `netassess-ingest`
lane judged the run and went red on what it found; `netassess-freshness`
went red when no run arrived. Neither uploaded anything, because a finding
had to belong to a repository and the NAS is not one.

Option A (Todd, 2026-10-21): network findings are filed against the scanning
repository, ToddGBenson/personal-soc, and `address` and `port` say which host.
Two tools, one module, because they read the same publisher's output:

``netassess`` reads ``netassess-run.json``, which the lane assembles from the
unpacked run: ``{"run_key", "network_status_md", "inventory_csv",
"nas_probe"}``. ``network_status_md`` is the scan's own summary, one
``- **Check:** verdict`` line per check, and its phrasing is the contract (the
verdict strings come from ``NetAssess.Verdicts.ps1``). ``nas_probe`` is the
scan's ``raw/nas-nfs.txt``: nmap's own output, which is the only place the run
records the NAS's address - the scan guesses it as ``.5`` and the summary just
says "NAS".

* ``NAS NFS exports: EXPORTS PRESENT (...)`` -> ``nas-nfs-exports``, high, on
  the NAS at 2049.
* ``NAS SMB: SMBv1 ENABLED`` -> ``nas-smbv1``, high, on the NAS at 445.
* ``NAS anonymous shares listed: 2 (media, public)`` -> ``nas-anonymous-shares``,
  medium, on the NAS at 445. A bare count (a scan older than TheHub #60852)
  still counts; it just cannot name them.
* ``Open Wi-Fi AP: <SSID> (...) OPEN - broadcasting`` -> ``wifi-open-ap``,
  medium, one per network, on ``wifi:<SSID>`` - an access point is a host
  with no address this scan can see, and its name is what a person changes.
* ``WAN (external) ports visible`` is deliberately not read: the
  ``external-exposure`` lane files those, with the allowlist beside them, and
  a second copy would be two findings for one port.

**`unknown` is its own state, never a pass.** A check whose verdict begins
``unknown`` - or that is missing from the summary - did not run, so the NAS
was not assessed. The run is ``partial_failure``, which reconciliation does not
count as evidence, so a finding from a week the check did run stays open until
a week in which it runs again and does not see it. A NAS that is switched off
must not read the same as one confirmed closed.

``netassess-freshness`` reads ``netassess-freshness.json``: ``{"keys": [...],
"max_age_days": N, "checked_on": "YYYY-MM-DD"}``, the run keys in the bucket.
It produces no findings - a stale scanner is lane health, not a vulnerability
on a host - and a stale or empty bucket is a failed run, saying why, as is
``{"check": "unknown"}``: a bucket that could not be listed. Its own
tool, so reconciliation (which partitions on the tool) never reads its empty
result as the LAN scan finding nothing.
"""

from __future__ import annotations

import json
import re
from datetime import date
from typing import Any

from mykronos import netassess
from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.schemas import FindingSubmission, ScanStatus, Severity

#: `- **NAS SMB:** SMB2/3 only`. The label is everything up to the colon
#: inside the bold; the verdict is the rest of the line.
_LINE = re.compile(r"^\s*[-*]\s*\*\*(?P<label>[^*]+?):\*\*\s*(?P<value>.*?)\s*$")

#: `Nmap scan report for 192.168.0.5` or `... for nas.lan (192.168.0.5)`.
_NMAP_TARGET = re.compile(
    r"Nmap scan report for (?:(?P<name>\S+) \((?P<paren>[0-9A-Fa-f:.]+)\)|(?P<bare>\S+))"
)

NFS = "NAS NFS exports"
SMB = "NAS SMB"
SHARES = "NAS anonymous shares listed"
WIFI = "Open Wi-Fi AP"

#: The checks this adapter files, in the order the scan writes them. A check
#: missing from the summary is a check that did not report, and is unknown.
CHECKS = (NFS, SMB, SHARES, WIFI)

#: Where the NAS is named when nmap's output does not say. A label rather
#: than a guessed address: `.5` is the scan's default, not a fact about
#: this LAN, and a finding keyed on a wrong IP is a finding about a stranger.
NAS_FALLBACK = "nas"


def _document(raw_output: bytes, name: str, result: AdapterResult) -> dict[str, Any] | None:
    try:
        document = json.loads(raw_output.decode("utf-8-sig", errors="replace"))
    except json.JSONDecodeError as exc:
        result.warn(f"{name} is not JSON ({exc}); nothing was read.")
        result.scan_status = ScanStatus.FAILURE
        return None
    if not isinstance(document, dict):
        result.warn(f"{name} is not an object; nothing was read.")
        result.scan_status = ScanStatus.FAILURE
        return None
    return document


def verdicts(network_status_md: str) -> dict[str, str]:
    """`network-status.md`'s lines as {check: verdict}."""
    out: dict[str, str] = {}
    for line in network_status_md.splitlines():
        match = _LINE.match(line)
        if match:
            out[match.group("label").strip()] = match.group("value").strip()
    return out


def nas_address(nas_probe: str | None) -> str | None:
    """The NAS's address, from nmap's own report of what it probed."""
    for match in _NMAP_TARGET.finditer(nas_probe or ""):
        host = match.group("paren") or match.group("bare")
        if host:
            return host.strip()
    return None


def _open_networks(verdict: str) -> list[str]:
    """`Guest (served by the gateway), Cam (80% signal) OPEN - broadcasting;
    neighbouring, not ours: X 20%` -> ["Guest", "Cam"]."""
    ours = verdict.split("OPEN - broadcasting", 1)[0]
    names = []
    for part in re.split(r"\),\s*", ours):
        name = re.sub(r"\s*\([^)]*\)?\s*$", "", part).strip().rstrip(",").strip()
        if name and name not in names:
            names.append(name)
    return names


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    result = AdapterResult()
    document = _document(raw_output, "netassess-run.json", result)
    if document is None:
        return result

    run_key = str(document.get("run_key") or "")
    status_md = document.get("network_status_md")
    inventory = document.get("inventory_csv")

    if not isinstance(status_md, str) or not status_md.strip():
        result.warn(
            f"{run_key or 'This run'} has no network-status.md - the scan did not "
            "finish, so nothing was assessed."
        )
        result.scan_status = ScanStatus.FAILURE
        return result

    if not isinstance(inventory, str) or not netassess.hosts(inventory):
        # Not believable as a scan, but its verdicts are still the verdicts it
        # wrote: kept, and the run marked failed so nothing closes on it.
        result.warn(
            f"{run_key or 'This run'} enumerated no hosts (inventory.csv missing or "
            "empty) - not a believable scan; recorded as failed."
        )
        result.scan_status = ScanStatus.FAILURE

    found = verdicts(status_md)
    nas = nas_address(document.get("nas_probe"))
    unknown: list[str] = []
    nas_needed = False

    def nas_finding(
        rule: str, port: int, severity: Severity, title: str, why: str, verdict: str
    ) -> None:
        nonlocal nas_needed
        nas_needed = True
        result.findings.append(
            FindingSubmission(
                rule_id=rule,
                title=title,
                description=(
                    f"{why}\n\nHost: {nas or 'the NAS (address not recorded by this run)'}"
                    f"\nPort: {port}\nScan verdict: {verdict}\nRun: {run_key or 'unknown'}"
                ),
                severity=severity,
                address=nas or NAS_FALLBACK,
                port=port,
                raw_finding_json={"run_key": run_key, "check": rule, "verdict": verdict},
            )
        )

    for check in CHECKS:
        verdict = found.get(check)
        if verdict is None or verdict.lower().startswith("unknown") or not verdict:
            unknown.append(f"{check}: {verdict or 'not reported'}")
            continue

        if check == NFS and verdict.startswith("EXPORTS PRESENT"):
            nas_finding(
                "nas-nfs-exports",
                2049,
                Severity.HIGH,
                "NAS is exporting NFS shares",
                "NFS exports are mountable by any host the NAS's export rules let in, "
                "with no credential. The weekly scan found exports listed.",
                verdict,
            )
        elif check == SMB and "SMBv1 ENABLED" in verdict:
            nas_finding(
                "nas-smbv1",
                445,
                Severity.HIGH,
                "NAS has SMBv1 enabled",
                "SMBv1 is the protocol EternalBlue and WannaCry used; Microsoft has "
                "deprecated it. The NAS still negotiates it.",
                verdict,
            )
        elif check == SHARES and verdict not in ("0", ""):
            nas_finding(
                "nas-anonymous-shares",
                445,
                Severity.MEDIUM,
                "NAS lists shares without credentials",
                "`net view` listed shares on the NAS without credentials being "
                "supplied to it"
                + (
                    "."
                    if not verdict.isdigit()
                    else ", and this scan version did not record their names."
                ),
                verdict,
            )
        elif check == WIFI and "OPEN - broadcasting" in verdict:
            for name in _open_networks(verdict):
                result.findings.append(
                    FindingSubmission(
                        rule_id="wifi-open-ap",
                        title="An open Wi-Fi access point is broadcasting",
                        description=(
                            "A network with no authentication, served by this "
                            "household's gateway or strong enough to be inside the "
                            f"house.\n\nNetwork: {name}\nScan verdict: {verdict}\n"
                            f"Run: {run_key or 'unknown'}"
                        ),
                        severity=Severity.MEDIUM,
                        address=f"wifi:{name}"[:100],
                        raw_finding_json={"run_key": run_key, "ssid": name, "verdict": verdict},
                    )
                )

    if nas_needed and nas is None:
        result.warn(
            f"The NAS's address is not in this run's nmap output; its findings are "
            f"filed against '{NAS_FALLBACK}' rather than a guessed IP."
        )

    if unknown:
        result.warn(
            "A check did not run, so it is not a pass - this run cannot close what it "
            "did not look at: " + "; ".join(unknown)
        )
        if result.scan_status is ScanStatus.SUCCESS:
            result.scan_status = ScanStatus.PARTIAL_FAILURE

    return result


def normalize_freshness(raw_output: bytes, context: ScanContext) -> AdapterResult:
    result = AdapterResult()
    document = _document(raw_output, "netassess-freshness.json", result)
    if document is None:
        return result

    if str(document.get("check") or "").lower() == "unknown":
        # The bucket could not be listed. Not "no runs" - nobody looked.
        result.warn(
            "Freshness could not be checked "
            f"({document.get('reason') or 'no reason recorded'}). Unknown is not a pass."
        )
        result.scan_status = ScanStatus.FAILURE
        return result

    keys = [str(k) for k in document.get("keys") or [] if str(k).strip()]
    try:
        max_age = int(document.get("max_age_days") or 10)
    except (TypeError, ValueError):
        max_age = 10
    try:
        today = date.fromisoformat(str(document.get("checked_on")))
    except ValueError:
        today = netassess.utc_today()

    fresh = netassess.freshness(keys, now=today, max_age_days=max_age)
    if fresh.problem:
        result.warn(fresh.problem)
        result.scan_status = ScanStatus.FAILURE
    return result
