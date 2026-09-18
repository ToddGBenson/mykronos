"""Re-checking the host firewall rule that scopes the deploy registry (#298).

**The failure these tests are about is a check that cannot fail.** The obvious
verification of this control is a request to the port, and run from the host
itself it returns the registry catalog whether the rule is in force, narrowed,
disabled or deleted — Windows Defender Firewall does not filter traffic from a
host to its own addresses. So most of what is pinned here is the difference
between reading the rule and probing the port, and the several ways a report is
allowed to come back not-green.

The evidence in `HOST` is the real shape collected from this estate on
2026-09-17: two addresses on one prefix under two different profiles, and three
Block rules from two provenances, two of which deny the /24 with this host's own
`.14` carved out.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mykronos.cli import main
from mykronos.host_controls import (
    EXPECTED_ASSERTIONS,
    assess,
    parse_evidence,
    parse_remote,
    port_matches,
    verdict,
)

#: `Set-RegistryScope.ps1`'s rule: the whole /24, in the dotted-netmask form
#: Windows actually stores.
WIDE_RULE: dict[str, Any] = {
    "display_name": "Mykronos registry 5000 - deny the LAN",
    "enabled": True,
    "direction": "Inbound",
    "action": "Block",
    "protocol": "TCP",
    "local_ports": ["5000"],
    "remote_addresses": ["192.168.0.0/255.255.255.0"],
    "profiles": ["Any"],
}

#: The older B-054 pair: the same /24 with `.14` — this host — punched out.
NARROW_RULE: dict[str, Any] = {
    "display_name": "Block registry 5000 from the LAN (B-054)",
    "enabled": True,
    "direction": "Inbound",
    "action": "Block",
    "protocol": "TCP",
    "local_ports": ["5000"],
    "remote_addresses": ["192.168.0.1-192.168.0.13", "192.168.0.15-192.168.0.254"],
    "profiles": ["Any"],
}

LAN = [
    {
        "prefix": "192.168.0.0/24",
        "address": "192.168.0.14",
        "interface": "Ethernet 4",
        "profile": "Private",
    },
    {
        "prefix": "192.168.0.0/24",
        "address": "192.168.0.19",
        "interface": "Wi-Fi 2",
        "profile": "Public",
    },
]


def document(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema": "mykronos.host-controls/1",
        "collected_at": "2026-09-17T21:55:54Z",
        "host": "TODDMUSIC",
        "port": 5000,
        "lan_addresses": LAN,
        "firewall_rules": [NARROW_RULE, NARROW_RULE, WIDE_RULE],
        "published_ports": ["mykronos-registry 0.0.0.0:5000->5000/tcp"],
        "registry_auth": {"configured": False, "detail": "no auth: block"},
        "local_probe": {"url": "http://192.168.0.14:5000/v2/_catalog", "status_code": 200},
        "errors": {},
    }
    base.update(overrides)
    return base


def state_of(report: Any, key: str) -> str:
    return next(a.state for a in report.assertions if a.key == key)


def detail_of(report: Any, key: str) -> str:
    return next(a.detail for a in report.assertions if a.key == key)


class TestTheProbeIsNotEvidence:
    """The heart of #298: the easy check has three outcomes and looks like two."""

    def test_a_successful_local_probe_never_counts_as_a_pass(self) -> None:
        """`curl http://192.168.0.14:5000/v2/_catalog` -> 200, from this host.

        That is what an open registry looks like and what a closed one looks
        like. It must not be able to make anything green.
        """
        report = assess(parse_evidence(document()))

        assert state_of(report, "registry.local_probe") == "not_evidence"

    def test_a_document_that_is_only_a_probe_does_not_pass(self) -> None:
        """Nothing failed, and nothing was verified. Those are not the same.

        This is the shape the naive check produces: no assertion is red, so a
        report that only counted failures would call it green.
        """
        report = assess(
            parse_evidence(
                {
                    "port": 5000,
                    "local_probe": {"url": "http://192.168.0.14:5000/", "status_code": 200},
                }
            )
        )

        assert report.failures  # the firewall was never read; that is a failure
        assert not report.ok

    def test_a_probe_alone_with_no_failures_still_does_not_pass(self) -> None:
        """The property in isolation: evidence-free is not ok.

        Constructed directly rather than through the collector, because the
        collector cannot currently emit a document with no unread sections —
        and the rule must hold if one ever can.
        """
        from mykronos.host_controls import Assertion, Report

        report = Report(assertions=[Assertion("registry.local_probe", "not_evidence", "200")])

        assert not report.failures
        assert not report.ok
        assert "NOTHING WAS VERIFIED" in verdict(report)

    def test_a_document_that_measured_nothing_verifies_nothing(self) -> None:
        """`not_measured` is not evidence either [#60015].

        The new state exists so an operator can tell which gaps are closeable,
        NOT so they count as measurements. If `not_measured` were treated as
        evidence, a report in which every single check was unestablished would
        claim to have verified something — the exact "green because it could
        not fail" shape the new state was added to prevent, reintroduced by the
        fix for it.
        """
        from mykronos.host_controls import Assertion, Report

        report = Report(
            assertions=[
                Assertion(key, "not_measured", "nothing to compare against")
                for key in sorted(EXPECTED_ASSERTIONS)
            ]
        )

        assert not report.failures
        assert not report.missing_assertions  # the floor is satisfied
        assert not report.ok
        assert not report.complete
        assert "NOTHING WAS VERIFIED" in verdict(report)


class TestTheRuleIsRead:
    def test_the_estate_as_it_stands_verifies(self) -> None:
        report = assess(parse_evidence(document()), ports_baseline=[
            "mykronos-registry 0.0.0.0:5000->5000/tcp"
        ])

        assert report.ok, verdict(report)
        assert state_of(report, "firewall.scope") == "pass"

    def test_deleting_the_rule_fails(self) -> None:
        report = assess(parse_evidence(document(firewall_rules=[])))

        assert state_of(report, "firewall.rule_present") == "fail"
        assert not report.ok

    def test_disabling_the_rule_fails_and_names_it(self) -> None:
        """Disabled is the way a control is most often lost, and a listing of
        rules shows it looking exactly as it always did."""
        off = dict(WIDE_RULE, enabled=False)
        report = assess(parse_evidence(document(firewall_rules=[off])))

        assert state_of(report, "firewall.rule_present") == "fail"
        assert "Mykronos registry 5000 - deny the LAN" in detail_of(
            report, "firewall.rule_present"
        )

    def test_losing_the_wide_rule_leaves_this_hosts_own_address_uncovered(self) -> None:
        """The failure that is invisible in any listing.

        `Set-RegistryScope.ps1 -Remove` knows about one of the three rules. Run
        it and the operator gets a clean success with two enabled Block rules
        still denying "the LAN" — a /24 with `192.168.0.14` carved out. Only
        arithmetic on the ranges says the host's own address is now reachable
        from the LAN on port 5000.
        """
        report = assess(parse_evidence(document(firewall_rules=[NARROW_RULE, NARROW_RULE])))

        assert state_of(report, "firewall.rule_present") == "pass"  # rules are still there
        assert state_of(report, "firewall.scope") == "fail"
        assert "192.168.0.14" in detail_of(report, "firewall.scope")

    def test_the_gap_report_names_hosts_and_not_the_network_address(self) -> None:
        """`.1-.13, .15-.254` leaves `.0`, `.14` and `.255` outside the denied
        set, and only one of those is a machine somebody could be sitting at.
        Listing all three buries the one that matters."""
        report = assess(parse_evidence(document(firewall_rules=[NARROW_RULE])))
        detail = detail_of(report, "firewall.scope")

        assert "192.168.0.14 is not denied" in detail
        assert "192.168.0.255" not in detail

    def test_a_rule_scoped_to_one_profile_misses_the_other_interface(self) -> None:
        """This host holds 192.168.0.14 on a Private interface and
        192.168.0.19 on a Public one — one prefix, two profiles. A rule that
        only applies under Private covers the first and not the second, and any
        summary that collapsed them would read as covering "the LAN"."""
        private_only = dict(WIDE_RULE, profiles=["Private"])
        report = assess(parse_evidence(document(firewall_rules=[private_only])))

        assert state_of(report, "firewall.scope") == "fail"
        assert "Public" in detail_of(report, "firewall.scope")
        assert "192.168.0.19" in detail_of(report, "firewall.scope")

    def test_the_host_moving_to_a_subnet_the_rule_never_named_fails(self) -> None:
        """A rule denying a subnet this host has left protects nothing while
        looking like it does — `Set-RegistryScope.ps1` says exactly that about
        why it re-scopes rather than skipping."""
        moved = [
            {
                "prefix": "10.0.0.0/24",
                "address": "10.0.0.5",
                "interface": "Ethernet 4",
                "profile": "Private",
            }
        ]
        report = assess(parse_evidence(document(lan_addresses=moved)))

        assert state_of(report, "firewall.scope") == "fail"
        assert "10.0.0" in detail_of(report, "firewall.scope")

    def test_a_rule_on_a_different_port_does_not_count(self) -> None:
        report = assess(
            parse_evidence(document(firewall_rules=[dict(WIDE_RULE, local_ports=["5001"])]))
        )

        assert state_of(report, "firewall.rule_present") == "fail"

    def test_an_udp_only_rule_does_not_count(self) -> None:
        report = assess(
            parse_evidence(document(firewall_rules=[dict(WIDE_RULE, protocol="UDP")]))
        )

        assert state_of(report, "firewall.rule_present") == "fail"

    def test_an_allow_rule_is_not_a_block_rule(self) -> None:
        report = assess(
            parse_evidence(document(firewall_rules=[dict(WIDE_RULE, action="Allow")]))
        )

        assert state_of(report, "firewall.rule_present") == "fail"


class TestUnreadIsNotAPass:
    """A section that could not be read must fail the run, never pass it.

    `netassess` makes the same insistence about an `unknown` line: a NAS that is
    switched off must not read the same as one confirmed closed.
    """

    def test_an_unreadable_firewall_is_unknown_not_a_pass(self) -> None:
        report = assess(
            parse_evidence(document(errors={"firewall_rules": "Access is denied."}))
        )

        assert state_of(report, "firewall.rule_present") == "unknown"
        assert state_of(report, "firewall.scope") == "unknown"
        assert not report.ok

    def test_no_collected_lan_address_is_unknown(self) -> None:
        """Nothing to check the rule against. A rule is only as good as the
        prefix list it denies."""
        report = assess(parse_evidence(document(lan_addresses=[])))

        assert state_of(report, "firewall.scope") == "unknown"
        assert not report.ok

    def test_an_interface_with_no_profile_is_unknown_not_covered(self) -> None:
        """Which rules apply to it cannot be determined, so neither can
        coverage. Assuming they do would be the probe's mistake again."""
        report = assess(
            parse_evidence(
                document(
                    lan_addresses=[
                        {
                            "prefix": "192.168.0.0/24",
                            "address": "192.168.0.14",
                            "interface": "Ethernet 4",
                            "profile": "",
                        }
                    ]
                )
            )
        )

        assert state_of(report, "firewall.scope") == "unknown"

    def test_a_remote_keyword_windows_resolves_later_is_unknown_not_covered(self) -> None:
        """`LocalSubnet` may or may not be the prefix in question, and this
        document does not carry what Windows resolves it against."""
        keyword = dict(WIDE_RULE, remote_addresses=["LocalSubnet"])
        report = assess(parse_evidence(document(firewall_rules=[keyword])))

        assert state_of(report, "firewall.scope") == "unknown"
        assert "LocalSubnet" in detail_of(report, "firewall.scope")

    def test_an_unreadable_registry_config_is_unknown(self) -> None:
        report = assess(
            parse_evidence(
                document(errors={"registry_auth": "a configuration is mounted at /etc/..."})
            )
        )

        assert state_of(report, "registry.auth") == "unknown"
        assert not report.ok


class TestTheControlStoryStaysCurrent:
    def test_no_auth_means_the_firewall_rule_is_still_load_bearing(self) -> None:
        report = assess(parse_evidence(document()))

        assert state_of(report, "registry.auth") == "pass"

    def test_the_registry_gaining_auth_is_reported_rather_than_ignored(self) -> None:
        """An improvement, and the recorded control goes stale: #268 records
        firewall scope as the sole compensating control for a registry with no
        authentication. A silent change is how a register stops being true."""
        report = assess(
            parse_evidence(
                document(registry_auth={"configured": True, "detail": "REGISTRY_AUTH=htpasswd"})
            )
        )

        assert state_of(report, "registry.auth") == "fail"
        assert "out of date" in detail_of(report, "registry.auth")


class TestPublishedPorts:
    def test_no_baseline_can_neither_pass_nor_fail(self) -> None:
        """`not_measured`, not `not_evidence` [#60015].

        The two were one state and the merge lost the actionable half. The
        local probe is `not_evidence` because it can never be evidence however
        often it runs; this has a subject, 22 bindings were observed, and one
        `--record-ports` closes it. A report that says "incomplete" has to be
        able to say which of its checks an operator can do something about.
        """
        report = assess(parse_evidence(document()), ports_baseline=None)

        assert state_of(report, "ports.baseline") == "not_measured"
        assert [a.key for a in report.unmeasured] == ["ports.baseline"]
        assert "compared to nothing" in detail_of(report, "ports.baseline")
        assert "--record-ports" in detail_of(report, "ports.baseline")

    def test_an_unread_ports_section_is_unknown_and_still_fails(self) -> None:
        """`not_measured` must not swallow the case it sits next to.

        "I could not read the published ports" is a failure; "I read them and
        had no baseline" is not. Widening the new state to cover both would
        turn an unreadable host into an incomplete report.
        """
        report = assess(
            parse_evidence(document(errors={"published_ports": "docker not running"})),
            ports_baseline=None,
        )

        assert state_of(report, "ports.baseline") == "unknown"
        assert not report.ok

    def test_a_new_binding_fails(self) -> None:
        report = assess(
            parse_evidence(
                document(
                    published_ports=[
                        "mykronos-registry 0.0.0.0:5000->5000/tcp",
                        "something-new 0.0.0.0:7000->7000/tcp",
                    ]
                )
            ),
            ports_baseline=["mykronos-registry 0.0.0.0:5000->5000/tcp"],
        )

        assert state_of(report, "ports.baseline") == "fail"
        assert "7000" in detail_of(report, "ports.baseline")

    def test_a_binding_going_away_is_not_a_failure(self) -> None:
        report = assess(
            parse_evidence(document(published_ports=[])),
            ports_baseline=["mykronos-registry 0.0.0.0:5000->5000/tcp"],
        )

        assert state_of(report, "ports.baseline") == "pass"


class TestAddressParsing:
    """The three shapes this estate's own rules already use, plus the ones a
    parser that only understood CIDR would silently read as covering nothing."""

    def test_a_dotted_netmask_is_a_network(self) -> None:
        spans, why = parse_remote("192.168.0.0/255.255.255.0")

        assert why is None
        assert spans == [(int.from_bytes(b"\xc0\xa8\x00\x00"), int.from_bytes(b"\xc0\xa8\x00\xff"))]

    def test_a_range_is_a_range(self) -> None:
        spans, why = parse_remote("192.168.0.1-192.168.0.13")

        assert why is None
        assert spans == [(int.from_bytes(b"\xc0\xa8\x00\x01"), int.from_bytes(b"\xc0\xa8\x00\x0d"))]

    def test_any_is_everything(self) -> None:
        assert parse_remote("Any") == ([(0, 2**32 - 1)], None)

    def test_an_ipv6_entry_is_not_an_ipv4_answer_and_is_not_an_error(self) -> None:
        spans, why = parse_remote("fe80::/64")

        assert spans == []
        assert why is None

    def test_nonsense_is_named_rather_than_assumed(self) -> None:
        spans, why = parse_remote("not-an-address")

        assert spans == []
        assert why is not None

    def test_port_ranges_and_any(self) -> None:
        assert port_matches("Any", 5000)
        assert port_matches("5000", 5000)
        assert port_matches("4990-5010", 5000)
        assert not port_matches("5001", 5000)
        assert not port_matches("RPC", 5000)


class TestTheCommand:
    def test_a_healthy_document_with_a_baseline_exits_zero(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        evidence = tmp_path / "host-controls.json"
        evidence.write_text(json.dumps(document()), encoding="utf-8")
        baseline = tmp_path / "ports.json"
        baseline.write_text(
            json.dumps(["mykronos-registry 0.0.0.0:5000->5000/tcp"]), encoding="utf-8"
        )

        assert (
            main(["host-controls", str(evidence), "--ports-baseline", str(baseline)])
            == 0
        )
        out = capsys.readouterr().out
        assert "VERIFIED" in out
        assert "NOT MEASURED" not in out

    def test_the_same_document_without_a_baseline_exits_three(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        """This is the defect in #60015, and it used to exit 0.

        Byte-identical evidence to the test above; the only difference is that
        nothing establishes `ports.baseline`, so 22 bindings are observed and
        compared to nothing. The run said `not_evidence` in a sub-row of a
        table and `VERIFIED` in the exit code, and the exit code is what a
        scheduler reads.

        Reworked rather than deleted: the old assertion (`== 0` with no
        baseline) was the bug written down as a guarantee, so leaving it would
        have meant either a failing suite or an un-fixed control.
        """
        evidence = tmp_path / "host-controls.json"
        evidence.write_text(json.dumps(document()), encoding="utf-8")

        assert main(["host-controls", str(evidence)]) == 3

        out = capsys.readouterr().out
        assert "NOT MEASURED" in out
        assert "ports.baseline" in out

    def test_the_three_outcomes_have_three_numbers(self, tmp_path: Path) -> None:
        """The acceptance criterion itself, as one assertion.

        "A verdict of 'could not measure' is distinguishable from 'passed' in
        the EXIT CODES, not only in the text output." Asserting the three are
        distinct is the property; asserting each individually is not, because
        three tests each passing against the same number would still be green.
        """
        evidence = tmp_path / "host-controls.json"
        baseline = tmp_path / "ports.json"
        baseline.write_text(
            json.dumps(["mykronos-registry 0.0.0.0:5000->5000/tcp"]), encoding="utf-8"
        )

        evidence.write_text(json.dumps(document()), encoding="utf-8")
        passed = main(["host-controls", str(evidence), "--ports-baseline", str(baseline)])
        not_measured = main(["host-controls", str(evidence)])

        evidence.write_text(json.dumps(document(firewall_rules=[])), encoding="utf-8")
        failed = main(["host-controls", str(evidence), "--ports-baseline", str(baseline)])

        assert len({passed, not_measured, failed}) == 3
        assert (passed, failed, not_measured) == (0, 1, 3)

    def test_the_floor_names_exactly_what_assess_produces(self) -> None:
        """The floor and the function have to stay the same list.

        Two ways to rot, both silent. An assertion added to `assess` and not to
        `EXPECTED_ASSERTIONS` is a check the floor does not defend, so deleting
        it later goes unnoticed. A name in `EXPECTED_ASSERTIONS` that `assess`
        never emits makes every report permanently incomplete, and the fix
        somebody reaches for is deleting the floor.
        """
        report = assess(parse_evidence(document()))

        assert {a.key for a in report.assertions} == set(EXPECTED_ASSERTIONS)

    def test_a_missing_check_is_not_a_pass(self) -> None:
        """The floor on what was examined [#60015].

        A report is not allowed to go green by asking fewer questions. Without
        this, deleting an assertion from `assess` turns its subject green
        rather than red — the control keeps reporting and stops reporting the
        thing, which is the failure mode this whole story is about.
        """
        from mykronos.host_controls import Report

        full = assess(parse_evidence(document()), ports_baseline=[
            "mykronos-registry 0.0.0.0:5000->5000/tcp"
        ])
        assert full.ok and full.complete

        pruned = Report(
            assertions=[a for a in full.assertions if a.key != "firewall.scope"]
        )

        assert pruned.missing_assertions == ["firewall.scope"]
        assert not pruned.ok
        assert not pruned.complete
        assert "INCOMPLETE REPORT" in verdict(pruned)
        assert "firewall.scope" in verdict(pruned)

    def test_json_output_carries_both_halves(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        """`ok` alone cannot answer the question the exit code now answers."""
        evidence = tmp_path / "host-controls.json"
        evidence.write_text(json.dumps(document()), encoding="utf-8")

        main(["host-controls", str(evidence), "--json"])
        payload = json.loads(capsys.readouterr().out)

        assert payload["ok"] is True
        assert payload["complete"] is False
        assert payload["unmeasured"] == ["ports.baseline"]
        assert payload["missing_assertions"] == []

    def test_an_unverified_run_is_still_one_not_three(self, tmp_path: Path) -> None:
        """Precedence: a failure outranks an unestablished check.

        Both are true of this document — the rule is gone AND there is no ports
        baseline. It must report the failure, because 3 reads as "nothing is
        wrong, something is missing" and something is very wrong.
        """
        evidence = tmp_path / "host-controls.json"
        evidence.write_text(
            json.dumps(document(firewall_rules=[])), encoding="utf-8"
        )

        assert main(["host-controls", str(evidence)]) == 1

    def test_a_document_with_only_a_probe_exits_non_zero(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        """The command an operator would schedule must go red on the evidence
        the naive check produces."""
        evidence = tmp_path / "host-controls.json"
        evidence.write_text(
            json.dumps({"port": 5000, "local_probe": {"url": "http://x/", "status_code": 200}}),
            encoding="utf-8",
        )

        assert main(["host-controls", str(evidence)]) == 1

    def test_the_narrowed_estate_exits_non_zero(self, tmp_path: Path) -> None:
        evidence = tmp_path / "host-controls.json"
        evidence.write_text(
            json.dumps(document(firewall_rules=[NARROW_RULE])), encoding="utf-8"
        )

        assert main(["host-controls", str(evidence)]) == 1

    def test_recording_a_ports_baseline(self, tmp_path: Path) -> None:
        evidence = tmp_path / "host-controls.json"
        evidence.write_text(json.dumps(document()), encoding="utf-8")
        baseline = tmp_path / "ports.json"

        assert (
            main(
                [
                    "host-controls",
                    str(evidence),
                    "--ports-baseline",
                    str(baseline),
                    "--record-ports",
                ]
            )
            == 0
        )
        assert json.loads(baseline.read_text(encoding="utf-8")) == [
            "mykronos-registry 0.0.0.0:5000->5000/tcp"
        ]
