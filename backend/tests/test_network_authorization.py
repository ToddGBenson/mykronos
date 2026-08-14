"""The authorization boundary around network scanning (spec 14 §3).

Active scanning is dual-use, and every test here is a specific mistake the
boundary refuses to let happen rather than a documented expectation.
"""

from __future__ import annotations

import pytest

from mykronos.network import (
    AuthorizationError,
    NetworkAsset,
    audit_record,
    is_private,
    resolve,
)

AUTHORISED = "CHG-1042: home lab, authorised by the owner 2026-08-13"


def asset(**overrides) -> NetworkAsset:
    base = {
        "asset_id": "home-lab",
        "cidr_ranges": ("192.168.0.0/24",),
        "authorization_reference": AUTHORISED,
    }
    base.update(overrides)
    return NetworkAsset(**base)


class TestExplicitRangesOnly:
    def test_a_declared_private_range_resolves(self) -> None:
        target = resolve(asset())

        assert [str(n) for n in target.networks] == ["192.168.0.0/24"]
        assert target.external == []

    def test_no_ranges_scans_nothing_and_is_not_an_error(self) -> None:
        """A capability that errors when idle is a capability people switch
        off. An empty configuration is a valid state."""
        target = resolve(asset(cidr_ranges=()))

        assert target.networks == []
        assert target.host_count == 0

    def test_a_disabled_asset_refuses(self) -> None:
        with pytest.raises(AuthorizationError, match="disabled"):
            resolve(asset(enabled=False))


class TestTheExternalRangeSpeedBump:
    def test_a_public_range_without_acknowledgement_is_refused(self) -> None:
        """The mistake this exists for: 192.168.0.0/16 is a home lab and
        192.169.0.0/16 is somebody else's network, and they differ by one
        character."""
        with pytest.raises(AuthorizationError, match="external_scan_acknowledged"):
            resolve(asset(cidr_ranges=("192.169.0.0/16",)))

    def test_the_refusal_names_the_range(self) -> None:
        """So the operator can see which one they typed wrong rather than
        being told the configuration is invalid."""
        with pytest.raises(AuthorizationError, match=r"8\.8\.8\.0/24"):
            resolve(asset(cidr_ranges=("192.168.1.0/24", "8.8.8.0/24")))

    def test_acknowledgement_permits_it(self) -> None:
        target = resolve(
            asset(cidr_ranges=("203.0.113.0/24",), external_scan_acknowledged=True)
        )

        assert target.external == ["203.0.113.0/24"]

    def test_one_external_range_refuses_the_whole_scan(self) -> None:
        """Not a partial scan of the ranges that passed. Dropping the
        unauthorised range and proceeding would produce a clean report for a
        network nobody looked at, which is worse than refusing."""
        with pytest.raises(AuthorizationError):
            resolve(asset(cidr_ranges=("192.168.1.0/24", "8.8.8.0/24")))

    @pytest.mark.parametrize(
        "cidr",
        ["10.1.0.0/16", "172.16.5.0/24", "192.168.1.0/24", "127.0.0.0/8", "fc00::/64"],
    )
    def test_private_space_needs_no_acknowledgement(self, cidr) -> None:
        assert resolve(asset(cidr_ranges=(cidr,))).external == []

    @pytest.mark.parametrize("cidr", ["8.8.8.0/24", "1.1.1.1/32", "2606:4700::/32"])
    def test_public_space_is_recognised_as_external(self, cidr) -> None:
        import ipaddress

        assert not is_private(ipaddress.ip_network(cidr))


class TestAuthorizationReference:
    def test_it_is_mandatory(self) -> None:
        with pytest.raises(AuthorizationError, match="authorization_reference"):
            resolve(asset(authorization_reference=""))

    def test_whitespace_is_not_a_reference(self) -> None:
        with pytest.raises(AuthorizationError, match="authorization_reference"):
            resolve(asset(authorization_reference="   "))

    def test_it_is_not_required_when_nothing_is_declared(self) -> None:
        """An asset that scans nothing needs no authority to scan nothing."""
        assert resolve(asset(cidr_ranges=(), authorization_reference="")).networks == []


class TestValidation:
    def test_a_malformed_range_scans_nothing(self) -> None:
        with pytest.raises(AuthorizationError, match="not a valid CIDR"):
            resolve(asset(cidr_ranges=("192.168.0.0/33",)))

    def test_the_error_says_nothing_was_scanned(self) -> None:
        with pytest.raises(AuthorizationError, match="Nothing was scanned"):
            resolve(asset(cidr_ranges=("not-a-cidr",)))


class TestAudit:
    def test_the_record_carries_what_an_auditor_asks_for(self) -> None:
        """spec 14 §3.5: operator identity, resolved ranges, and the
        authorization reference."""
        target = resolve(asset())

        record = audit_record(asset(), target, actor="admin")

        assert record["actor"] == "admin"
        assert record["asset_id"] == "home-lab"
        assert record["cidr_ranges"] == ["192.168.0.0/24"]
        assert record["authorization_reference"] == AUTHORISED
        assert record["host_count"] == 256

    def test_external_ranges_are_recorded_separately(self) -> None:
        """So an audit can answer "did we ever scan outside our own space"
        without re-deriving it from CIDR arithmetic."""
        a = asset(cidr_ranges=("203.0.113.0/24",), external_scan_acknowledged=True)

        record = audit_record(a, resolve(a), actor="admin")

        assert record["external_ranges"] == ["203.0.113.0/24"]
