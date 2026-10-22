"""The WAN edge as Shodan InternetDB sees it, as network findings (TheHub #60813).

personal-soc's `external-exposure` lane runs `Get-ExternalExposure.ps1`, which
resolves the household's public IP and asks InternetDB what it last indexed
there: open ports, CVEs inferred from banners, hostnames. It judged every port
against `exposure-allowlist.yml` and went red on one that is not listed - and
uploaded nothing, because a network finding had no repository to belong to.

Option A (Todd, 2026-10-21): the finding is filed against the repository that
scanned, ToddGBenson/personal-soc, and says which host it is about in
`address` and `port`. Here that host is the public IP.

**Three shapes arrive, and only one of them is a scan result.**

* The script's own `external-exposure.json` - the IP, its ports, and which
  of them are allowlisted. One finding per visible port and per CVE.
* `{"indexed": false}`, written by the lane when the script exited 0 without
  writing a file. That is InternetDB's 404: this IP is not indexed, which is
  the good outcome, and a real observation of an empty edge. Success, no
  findings - so a port that was visible and is no longer closes on the
  ordinary two-scan rule.
* `{"check": "unknown", "reason": ...}`, written when the script exited 2: no
  public IP, the lookup failed, or the allowlist was unreadable. **Not a clean
  scan.** It is a failed run, so reconciliation counts it as no evidence and
  nothing closes on it - a lookup that never happened must not read as an edge
  with nothing on it.

**Severity.** A port not on the allowlist is `medium`, the severity
`network_nmap` gives an administrative port, and for its reason: reachable by
anything that can reach the edge. An allowlisted port is `info` - inventory,
decided by a person, still worth a row so its history is kept. A CVE is
`info`: InternetDB infers it from a banner and gives no score, and this adapter
does not invent one; its CVE id is what threat intelligence keys KEV and EPSS
on.

**The IP is never in a title.** The lane keeps the public IP out of Slack
("Port numbers only"), and ingestion posts titles to Slack for loud findings.
The IP is in `address`, which is where a host belongs, and in the raw record.
"""

from __future__ import annotations

import json
from typing import Any

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.schemas import FindingSubmission, ScanStatus, Severity

_SOURCE = (
    "Seen by Shodan InternetDB, which reflects Shodan's last scan of this IP: "
    "it can be stale, and it is not a live probe."
)


def _as_list(value: Any) -> list[Any]:
    """`ConvertTo-Json` writes a one-element array as a bare value, and an
    empty one as null. Both mean a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _ports(value: Any, result: AdapterResult) -> list[int]:
    ports: list[int] = []
    for item in _as_list(value):
        try:
            port = int(item)
        except (TypeError, ValueError):
            result.skipped += 1
            continue
        if 0 <= port <= 65535 and port not in ports:
            ports.append(port)
        elif not 0 <= port <= 65535:
            result.skipped += 1
    return ports


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    result = AdapterResult()
    try:
        document = json.loads(raw_output.decode("utf-8-sig", errors="replace"))
    except json.JSONDecodeError as exc:
        result.warn(f"external-exposure.json is not JSON ({exc}); the WAN view was not read.")
        result.scan_status = ScanStatus.FAILURE
        return result
    if not isinstance(document, dict):
        result.warn("external-exposure.json is not an object; the WAN view was not read.")
        result.scan_status = ScanStatus.FAILURE
        return result

    if str(document.get("check") or "").lower() == "unknown":
        reason = str(document.get("reason") or "no reason recorded")
        result.warn(
            f"The WAN edge could not be checked ({reason}). Unknown is not a pass: "
            "this run is recorded as failed, and nothing closes on it."
        )
        result.scan_status = ScanStatus.FAILURE
        return result

    if document.get("indexed") is False:
        # InternetDB's 404: a real answer, and the good one.
        return result

    address = str(document.get("ip") or "").strip()
    ports = _ports(document.get("ports"), result)
    # Allowlisted only when the script said so. A port in neither list - an
    # older script, a field ConvertTo-Json dropped - is treated as not
    # allowlisted: the error falls toward a visible port, not a quiet one.
    allowed = set(_ports(document.get("allowlisted_ports"), AdapterResult())) - set(
        _ports(document.get("unexpected_ports"), AdapterResult())
    )
    cves = [str(c).strip() for c in _as_list(document.get("cves")) if str(c).strip()]

    if not address:
        if ports or cves:
            result.warn(
                "external-exposure.json lists ports or CVEs with no IP, so they have "
                "no host to belong to and were not recorded."
            )
            result.scan_status = ScanStatus.PARTIAL_FAILURE
        return result

    context_record = {
        "ip": address,
        "hostnames": _as_list(document.get("hostnames")),
        "tags": _as_list(document.get("tags")),
        "cpes": _as_list(document.get("cpes")),
    }

    for port in ports:
        allowlisted = port in allowed
        if allowlisted:
            severity = Severity.INFO
            title = f"Port {port} is visible from the internet (allowlisted)"
            why = (
                "This port is on exposure-allowlist.yml, so somebody decided it is "
                "meant to be reachable. Recorded as inventory."
            )
        else:
            severity = Severity.MEDIUM
            title = f"Port {port} is visible from the internet and not allowlisted"
            why = (
                "Reachable by anything that can reach the household's public IP, and "
                "not on exposure-allowlist.yml. Close it (port forward, UPnP), or "
                "allowlist it with a reason."
            )
        result.findings.append(
            FindingSubmission(
                rule_id=f"wan-port-{port}",
                title=title,
                description=f"{why}\n\nHost: the WAN edge\nPort: {port}\n\n{_SOURCE}",
                severity=severity,
                address=address,
                port=port,
                raw_finding_json={**context_record, "port": port, "allowlisted": allowlisted},
            )
        )

    for cve in cves:
        result.findings.append(
            FindingSubmission(
                rule_id=cve[:255],
                title=f"{cve} reported on the WAN edge",
                description=(
                    "InternetDB infers this CVE from a service banner on the household's "
                    "public IP. It gives no severity, so none is invented here; threat "
                    f"intelligence ranks it by KEV and EPSS.\n\n{_SOURCE}"
                ),
                severity=Severity.INFO,
                address=address,
                raw_finding_json={**context_record, "cve": cve},
            )
        )

    return result
