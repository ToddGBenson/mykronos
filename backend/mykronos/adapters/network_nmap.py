"""nmap and nuclei output to normalized findings (spec 14 §2, §5).

Two tools, one adapter, because they answer halves of the same question. nmap
says a port is open and what it looks like; nuclei says a specific weakness is
present on it. Both are keyed on address and port, and a finding from either
has to sit beside the other in the same host's history.

**Severity is not invented.** nmap reports no severity at all — an open port is
a fact, not a judgement — so ports map to `info` unless they are on the
administrative list, which is the one place this adapter applies an opinion and
says so. nuclei carries its own severity and it is used as given.

**An open port is a finding, not a vulnerability.** Recording them as `info`
keeps the inventory in the same table as everything else without inflating any
risk score: spec 09's scoring ignores `info`. They exist so that a toxic
combination can pair "3389 answers" with a web finding, which is the entire
reason spec 14 §5 gave findings an asset.
"""

from __future__ import annotations

import json
from typing import Any
from xml.etree import ElementTree

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.schemas import FindingSubmission, ScanStatus, Severity

#: Ports whose exposure is a finding in itself rather than inventory. Narrow
#: on purpose: a list that flags 80 and 443 produces one finding per web
#: server and teaches people that network findings are noise.
_ADMIN_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

#: Cleartext protocols. Separate from the administrative list because the
#: reason differs: these are a finding wherever they answer, not only when
#: they are management surfaces.
_CLEARTEXT: dict[int, str] = {21: "FTP", 23: "Telnet", 80: "HTTP", 143: "IMAP"}

_NUCLEI_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


def _port_severity(port: int) -> tuple[Severity, str]:
    if port in _ADMIN_PORTS:
        return Severity.MEDIUM, (
            f"{_ADMIN_PORTS[port]} is a management or data service. Reachable "
            "from this scanner's vantage point means reachable by anything "
            "else on the same segment."
        )
    if port in _CLEARTEXT:
        return Severity.LOW, (
            f"{_CLEARTEXT[port]} carries credentials and content in cleartext."
        )
    return Severity.INFO, "Open port, recorded as inventory."


def _from_nmap(text: str, result: AdapterResult) -> None:
    try:
        root = ElementTree.fromstring(text)  # noqa: S314 - local scanner output
    except ElementTree.ParseError as exc:
        result.warn(f"Not parseable nmap XML: {exc}")
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        return

    for host in root.iter("host"):
        address_el = host.find("address")
        if address_el is None:
            result.skipped += 1
            continue
        address = str(address_el.get("addr") or "")
        if not address:
            result.skipped += 1
            continue

        hostname_el = host.find("./hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None

        for port_el in host.iter("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                port = int(port_el.get("portid") or "")
            except ValueError:
                result.skipped += 1
                continue

            service_el = port_el.find("service")
            service = (service_el.get("name") if service_el is not None else "") or ""
            product = (service_el.get("product") if service_el is not None else "") or ""
            version = (service_el.get("version") if service_el is not None else "") or ""

            severity, why = _port_severity(port)
            banner = " ".join(part for part in (product, version) if part)
            result.findings.append(
                FindingSubmission(
                    rule_id=f"open-port-{port}",
                    title=(
                        f"{service or 'unknown service'} open on {address}:{port}"
                        + (f" ({banner})" if banner else "")
                    ),
                    description=(
                        f"{why}\n\n"
                        f"Host: {address}"
                        + (f" ({hostname})" if hostname else "")
                        + f"\nPort: {port}/tcp\nService: {service or 'unidentified'}"
                        + (f"\nBanner: {banner}" if banner else "")
                        + "\n\nRecorded by nmap. An open port is an observation, "
                        "not by itself a vulnerability."
                    ),
                    severity=severity,
                    address=address,
                    port=port,
                    raw_finding_json={
                        "address": address,
                        "hostname": hostname,
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version,
                    },
                )
            )


def _from_nuclei(text: str, result: AdapterResult) -> None:
    """nuclei writes JSON Lines, one finding per line."""
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            record: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            result.skipped += 1
            continue

        info = record.get("info") or {}
        template = str(record.get("template-id") or info.get("name") or "").strip()
        if not template:
            result.skipped += 1
            continue

        host = str(record.get("host") or record.get("matched-at") or "")
        address = str(record.get("ip") or "").strip() or _host_of(host)
        if not address:
            result.warn(
                f"nuclei line {number}: no address, so the finding has no "
                "stable identity and was skipped rather than keyed on a URL."
            )
            result.skipped += 1
            continue

        result.findings.append(
            FindingSubmission(
                rule_id=template[:255],
                title=str(info.get("name") or template)[:1000],
                description=(
                    str(info.get("description") or "").strip()
                    + f"\n\nMatched at: {record.get('matched-at') or host}"
                ).strip(),
                severity=_NUCLEI_SEVERITY.get(
                    str(info.get("severity") or "info").lower(), Severity.INFO
                ),
                address=address,
                port=_port_of(host),
                raw_finding_json=record,
            )
        )


def _host_of(target: str) -> str:
    """`https://10.0.0.5:8443/x` -> `10.0.0.5`."""
    without_scheme = target.split("://", 1)[-1]
    hostport = without_scheme.split("/", 1)[0]
    if hostport.startswith("["):  # IPv6 literal
        return hostport.partition("]")[0].lstrip("[")
    return hostport.rsplit(":", 1)[0] if ":" in hostport else hostport


def _port_of(target: str) -> int | None:
    without_scheme = target.split("://", 1)[-1]
    hostport = without_scheme.split("/", 1)[0]
    if hostport.startswith("["):
        _, _, rest = hostport.partition("]")
        candidate = rest.lstrip(":")
    elif hostport.count(":") == 1:
        candidate = hostport.rsplit(":", 1)[1]
    else:
        return None
    try:
        port = int(candidate)
    except ValueError:
        return None
    return port if 0 <= port <= 65535 else None


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    """Parse one scanner report — nmap XML or nuclei JSON Lines (spec 14 §2).

    The format is detected from the content rather than a filename, because
    the uploader hands adapters bytes and the two tools write into the same
    results directory. nmap XML always begins with a declaration or an
    `<nmaprun` element; nuclei writes one JSON object per line.
    """
    result = AdapterResult()
    text = raw_output.decode("utf-8", errors="replace").lstrip()

    if not text:
        result.scan_status = ScanStatus.NO_APPLICABLE_TARGETS
        result.warn("Empty scanner report — nothing was scanned.")
        return result

    if text.startswith("<"):
        _from_nmap(text, result)
    else:
        _from_nuclei(text, result)

    if result.skipped and not result.findings:
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        result.warn(f"{result.skipped} record(s) were unreadable and none were parsed.")
    return result
