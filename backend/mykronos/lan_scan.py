"""Scan the operator's own hosts from the LAN, inside spec 14 §3 (TheHub #60826).

    python -m mykronos.lan_scan \\
        --cidr 192.168.0.14/32 --cidr 192.168.0.20/32 \\
        --authorization-reference "CHG-17: Todd authorised a scan of his own hosts, 2026-10-17" \\
        --ingestion-url http://localhost:8180 --repo ToddGBenson/thehub

**What it does.** Runs `nmap -sV --top-ports 1000` against exactly the ranges
listed, then does two things with the one XML report:

1. uploads it through the existing `network` capability - the same
   `mykronos.upload` path and `adapters/network_nmap.py` adapter any nmap
   report takes, so the open ports land as findings with an asset;
2. posts one `port_published` ControlObservation per open port from the
   `lan` vantage, pointing at the archived XML (`raw_ref`). A listed range in
   which nothing answered is recorded as `unknown`, never left out.

**What it refuses** (spec 14 §3, enforced by `network.resolve` before any
packet): no `--cidr`, no `--authorization-reference`, a malformed range, or a
range outside private space without `--external-scan-acknowledged`. There is
no default range and no discovery: the hosts scanned are the hosts named.
Every run's authorization record (`network.audit_record`) travels in the
observation batch and is written to the audit log with it (§3.5).

**Why on the Windows host and not in a container.** A container behind Docker
Desktop's NAT sees a different L2 segment - an nmap sweep from one reported all
256 addresses of a /24 as up (`publish-netassess-run.ps1`). The vantage this
records is `lan` because it runs from another machine on the LAN.

The token is the repository's ingestion token (`$MYKRONOS_INGESTION_TOKEN`)
granted `network` (`mykronos grant <repo> network`). Behind the perimeter gate,
set `$MYKRONOS_GATE_TOKEN` as well.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import shutil
import socket
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

from mykronos import network
from mykronos.schemas import utcnow
from mykronos.upload import IngestionClient, UploadError, upload

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2

#: The one scan this wrapper runs. Named here so a reviewer reads it once.
NMAP_ARGS = ("-sV", "--top-ports", "1000")

OBSERVATIONS_PATH = "/api/ingest/control-observations"


class GatedClient(IngestionClient):
    """An IngestionClient that also presents the perimeter gate token."""

    def __init__(self, base_url: str, token: str, gate_token: str = "") -> None:
        super().__init__(base_url, token)
        self.gate_token = gate_token

    def _headers(self) -> dict[str, str]:
        headers = super()._headers()
        if self.gate_token:
            headers["X-Hub-Token"] = self.gate_token
        return headers


def build_command(nmap: str, targets: list[str], max_rate: int, output: Path) -> list[str]:
    return [nmap, *NMAP_ARGS, "--max-rate", str(max_rate), "-oX", str(output), *targets]


def _tool_version(root: Any) -> str:
    return str(root.get("version") or "") if root is not None else ""


def observations_from_xml(
    xml_text: str,
    targets: list[str],
    *,
    raw_ref: str,
    collected_at: str,
    self_addresses: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    """One `port_published` pass per open port; `unknown` per silent target.

    A listed range with no open port in the report - nothing up, nothing open,
    or a report that did not parse - is one `unknown` row naming the range.
    nmap's silence is not evidence that nothing is published.

    **A port this host found on itself is `host` vantage, not `lan`.** Windows
    does not filter traffic from a host to its own addresses (`host_controls`
    explains why that makes the local probe worthless), so scanning loopback
    or this machine's own LAN address says what is listening, not what the LAN
    can reach.
    """
    root = None
    try:
        root = SafeElementTree.fromstring(xml_text) if xml_text.strip() else None
    except (ElementTree.ParseError, DefusedXmlException):
        root = None
    version = _tool_version(root)

    def obs(
        subject: str, state: str, detail: str, vantage: str = "lan", **evidence: Any
    ) -> dict[str, Any]:
        return {
            "subject": subject,
            "assertion": "port_published",
            "state": state,
            "vantage": vantage,
            "tool": "nmap",
            "tool_version": version,
            "collected_at": collected_at,
            "raw_ref": raw_ref,
            "detail": detail,
            "evidence": evidence,
        }

    out: list[dict[str, Any]] = []
    open_addresses: set[str] = set()
    if root is not None:
        for host in root.iter("host"):
            address_el = host.find("address")
            address = str(address_el.get("addr") or "") if address_el is not None else ""
            if not address:
                continue
            hostname_el = host.find("./hostnames/hostname")
            hostname = hostname_el.get("name") if hostname_el is not None else None
            for port_el in host.iter("port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = str(port_el.get("portid") or "")
                if not portid.isdigit():
                    continue
                service_el = port_el.find("service")
                service = (service_el.get("name") if service_el is not None else "") or ""
                subject = f"[{address}]:{portid}" if ":" in address else f"{address}:{portid}"
                own = address in self_addresses or _is_loopback(address)
                out.append(
                    obs(
                        subject,
                        "pass",
                        f"{service or 'unidentified service'} open on {address}:{portid} "
                        f"({port_el.get('protocol') or 'tcp'}), "
                        + (
                            "scanned from this host itself - what listens, not what the "
                            "LAN reaches."
                            if own
                            else "seen from the LAN."
                        ),
                        vantage="host" if own else "lan",
                        address=address,
                        port=int(portid),
                        hostname=hostname,
                        service=service,
                    )
                )
                open_addresses.add(address)

    for target in targets:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            continue
        if any(ipaddress.ip_address(a) in net for a in open_addresses):
            continue
        why = (
            "nmap's report did not parse, so nothing was established"
            if root is None
            else "no open port in the report for this range"
        )
        out.append(obs(str(net), "unknown", f"{why}; not evidence that nothing is published."))
    return out


def _is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def local_addresses() -> frozenset[str]:
    """This machine's own addresses, as far as its resolver says."""
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None)
    except OSError:
        return frozenset()
    return frozenset(str(info[4][0]).split("%", 1)[0] for info in infos)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m mykronos.lan_scan",
        description=(
            "nmap -sV --top-ports 1000 against explicitly listed hosts you own, uploaded "
            "as network findings and port_published observations (spec 14 §3)."
        ),
    )
    # Not argparse-required on purpose: a missing range or reference is the
    # authorization refusal (exit 2, with spec 14's reason), not a usage error.
    parser.add_argument("--cidr", action="append", default=[], help="A range to scan. Repeatable.")
    parser.add_argument("--authorization-reference", default="")
    parser.add_argument("--external-scan-acknowledged", action="store_true")
    parser.add_argument("--max-rate", type=int, default=network.NetworkAsset.max_rate_pps)
    parser.add_argument("--ingestion-url", default=os.environ.get("MYKRONOS_URL", ""))
    parser.add_argument("--token", default=os.environ.get("MYKRONOS_INGESTION_TOKEN", ""))
    parser.add_argument("--gate-token", default=os.environ.get("MYKRONOS_GATE_TOKEN", ""))
    parser.add_argument("--repo", required=True, help="owner/repo the token belongs to.")
    parser.add_argument("--asset-id", default="lan")
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--nmap", default="nmap", help="nmap executable.")
    parser.add_argument("--timeout-minutes", type=int, default=60)
    return parser


def main(
    argv: list[str] | None = None,
    *,
    runner: Callable[..., Any] = subprocess.run,
    client: IngestionClient | None = None,
    which: Callable[[str], str | None] = shutil.which,
    self_addresses: Callable[[], frozenset[str]] = local_addresses,
) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _parser().parse_args(argv)

    asset = network.NetworkAsset(
        asset_id=args.asset_id,
        cidr_ranges=tuple(c.strip() for c in args.cidr if c.strip()),
        authorization_reference=args.authorization_reference,
        external_scan_acknowledged=args.external_scan_acknowledged,
        max_rate_pps=args.max_rate,
    )
    try:
        target = network.resolve(asset)
    except network.AuthorizationError as exc:
        logger.error("Refused (spec 14 §3): %s", exc)
        return EXIT_REFUSED
    if not target.networks:
        logger.error("Refused (spec 14 §3): no range to scan. There is no default range.")
        return EXIT_REFUSED

    nmap = which(args.nmap)
    if nmap is None:
        logger.error("nmap was not found (%s). Nothing was scanned.", args.nmap)
        return EXIT_FAILED
    if not args.ingestion_url or not args.token:
        logger.error("--ingestion-url and --token (or $MYKRONOS_INGESTION_TOKEN) are required.")
        return EXIT_FAILED

    targets = [str(net) for net in target.networks]
    actor = f"mykronos.lan_scan@{socket.gethostname()}"
    authorization = network.audit_record(asset, target, actor)
    out_dir = Path(args.output_dir) if args.output_dir else Path(tempfile.mkdtemp(prefix="lan-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    xml_path = out_dir / f"nmap-lan-{stamp}.xml"

    command = build_command(nmap, targets, args.max_rate, xml_path)
    logger.info(
        "Scanning %s (authorization: %s)", ", ".join(targets), asset.authorization_reference
    )
    collected_at = utcnow().isoformat()
    try:
        done = runner(
            command, capture_output=True, text=True, timeout=args.timeout_minutes * 60, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.error("nmap did not finish: %s", exc)
        return EXIT_FAILED
    if getattr(done, "returncode", 1) != 0 or not xml_path.exists():
        logger.error("nmap exited %s: %s", getattr(done, "returncode", "?"),
                     str(getattr(done, "stderr", ""))[:400])
        return EXIT_FAILED

    client = client or GatedClient(args.ingestion_url, args.token, args.gate_token)
    xml_text = xml_path.read_text(encoding="utf-8", errors="replace")
    try:
        outcome = upload(
            argparse.Namespace(
                capability="network",
                tool="nmap",
                tool_version="",
                results_path=str(xml_path),
                ingestion_url=args.ingestion_url,
                token=args.token,
                repo=args.repo,
                commit_sha="lan-scan",
                branch="lan",
                workflow_run_id="",
                job="lan_scan",
                triggered_by="manual",
                pr_number=None,
                workspace="",
                scan_run_id="",
                sbom=[],
                severity_threshold="low",
                blocking="false",
            ),
            client,
        )
        batch = observations_from_xml(
            xml_text,
            targets,
            raw_ref=outcome.raw_output_ref or "",
            collected_at=collected_at,
            self_addresses=self_addresses(),
        )
        accepted = client.post(
            OBSERVATIONS_PATH,
            json_body={
                "collector": actor,
                "observations": batch,
                "run_context": authorization,
            },
        )
    except UploadError as exc:
        logger.error("%s", exc)
        return EXIT_FAILED

    logger.info(
        "Uploaded %s finding(s) (scan run %s) and %s observation(s).",
        outcome.findings_accepted,
        outcome.scan_run_id,
        accepted.get("accepted", len(batch)),
    )
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
