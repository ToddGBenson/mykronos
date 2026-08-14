"""Network scan targets, and the authorization boundary around them (spec 14 §3).

Active network scanning is dual-use. Scanning infrastructure you own is
ordinary practice; the same tool pointed one octet to the left is not. Spec 14
§3 puts the boundary in code rather than in documentation, and this module is
that boundary.

Four rules, each of which is a specific mistake it refuses to let happen:

1. **Explicit ranges only.** No discovery outside declared CIDRs, no "scan
   whatever the host can reach", no default range. An empty configuration
   scans nothing and that is a valid state, not an error — a capability that
   errors when idle gets switched off.
2. **Validated before every run**, not only when saved. Configuration can be
   edited between scheduling and execution, and the check that matters is the
   one nearest the packets.
3. **Non-private ranges need explicit acknowledgement** plus an authorization
   reference. This is a speed bump against the most likely serious mistake: a
   typo'd CIDR aimed at the public internet. `192.168.0.0/16` is a home lab;
   `192.169.0.0/16` is somebody else's.
4. **`authorization_reference` is mandatory** — a ticket, a change record, a
   note naming who authorised this and when. It travels onto every resulting
   finding, because "who said this was allowed" is the first question asked
   afterwards and the hardest to reconstruct later.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

#: Ranges that need no external acknowledgement. RFC1918, RFC4193, loopback,
#: and link-local — the address space that cannot be routed to somebody else
#: by accident.
_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
)


class AuthorizationError(Exception):
    """A scan was requested that the authorization model does not permit."""


@dataclass(frozen=True)
class NetworkAsset:
    """A declared network, and the authority to scan it (spec 14 §5)."""

    asset_id: str
    cidr_ranges: tuple[str, ...] = ()
    authorization_reference: str = ""
    external_scan_acknowledged: bool = False
    enabled: bool = True
    #: Rate ceiling handed to the scanner. Deliberately well below tool
    #: maximums (spec 14 §3.6): a security tool that knocks a device over has
    #: caused an incident, not prevented one.
    max_rate_pps: int = 100


@dataclass
class ResolvedTarget:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list
    )
    #: Ranges outside private space, named so the audit record and the refusal
    #: message can both say which one.
    external: list[str] = field(default_factory=list)

    @property
    def host_count(self) -> int:
        return sum(net.num_addresses for net in self.networks)


def is_private(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return any(
        network.version == private.version and network.subnet_of(private)  # type: ignore[arg-type]
        for private in _PRIVATE_NETS
    )


def resolve(asset: NetworkAsset) -> ResolvedTarget:
    """Validate an asset's ranges and return what may be scanned.

    Raises `AuthorizationError` rather than returning a partial list. A scan
    that silently drops the range somebody meant to authorise, and proceeds
    with the rest, is worse than one that refuses: it produces a clean report
    for a network nobody looked at.
    """
    if not asset.enabled:
        raise AuthorizationError(f"Network asset '{asset.asset_id}' is disabled.")

    target = ResolvedTarget()
    if not asset.cidr_ranges:
        # Not an error. A declared network with no ranges scans nothing, and
        # the caller decides whether that is worth mentioning.
        return target

    if not asset.authorization_reference.strip():
        raise AuthorizationError(
            f"Network asset '{asset.asset_id}' has no authorization_reference. "
            "Spec 14 §3 requires a ticket, change record or note naming who "
            "authorised this scan; it is recorded on every finding the scan "
            "produces."
        )

    for raw in asset.cidr_ranges:
        try:
            network = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError as exc:
            raise AuthorizationError(
                f"'{raw}' is not a valid CIDR range: {exc}. Nothing was scanned."
            ) from exc

        if not is_private(network):
            target.external.append(str(network))
        target.networks.append(network)

    if target.external and not asset.external_scan_acknowledged:
        raise AuthorizationError(
            f"Network asset '{asset.asset_id}' declares ranges outside private "
            f"address space ({', '.join(target.external)}) without "
            "external_scan_acknowledged. These are addresses that may belong "
            "to somebody else — a single mistyped octet is the difference "
            "between a home lab and a stranger's network. Set the flag "
            "deliberately if the range is genuinely yours to scan."
        )

    return target


def audit_record(
    asset: NetworkAsset, target: ResolvedTarget, actor: str
) -> dict[str, object]:
    """What spec 14 §3.5 requires be written for every run."""
    return {
        "actor": actor,
        "asset_id": asset.asset_id,
        "cidr_ranges": [str(net) for net in target.networks],
        "external_ranges": list(target.external),
        "authorization_reference": asset.authorization_reference,
        "max_rate_pps": asset.max_rate_pps,
        "host_count": target.host_count,
    }
