"""Judging a network-assessment run — spec 32 §4.4.

The failure the whole module exists to catch, and therefore the thing most of
these tests are about: **the Scheduled Task degrading rather than dying.**
Still writing `network-status.md` every week, with the checks inside it no
longer running. A scan that resolved nothing looks exactly like a clean scan
unless something insists on the difference, and a NAS that is switched off must
not read the same as one confirmed closed.
"""

from __future__ import annotations

from datetime import date

from mykronos.netassess import (
    diff_hosts,
    freshness,
    newest,
    run_date,
    summarise,
    verify,
)

INVENTORY = (
    "address,mac,label\n"
    "192.168.0.1,AA:BB:CC:00:00:01,router\n"
    "192.168.0.14,AA:BB:CC:00:00:02,nas\n"
)
CLEAN_STATUS = "# Network status\n\nNFS: no exports\nSMB: SMBv2 only\nWi-Fi: WPA2\n"


class TestRunOrdering:
    def test_a_run_key_parses(self) -> None:
        assert run_date("netassess-2026.8.9.zip") == date(2026, 8, 9)

    def test_a_non_run_key_is_not_a_run(self) -> None:
        assert run_date("runs/README.md") is None
        assert run_date("netassess-latest.zip") is None

    def test_an_impossible_date_is_not_a_run(self) -> None:
        """Shaped like a run, naming a day that does not exist. Not a crash in
        something that runs unattended."""
        assert run_date("netassess-2026.13.40.zip") is None

    def test_ordering_is_by_date_not_by_name(self) -> None:
        """The bug `sort -V` was there to prevent.

        Plain string ordering puts `2026.8.10` before `2026.8.9`, which would
        compare every week against the same stale baseline — and the diff would
        look plausible while being wrong about which run it was against.
        """
        keys = ["netassess-2026.8.9.zip", "netassess-2026.8.10.zip"]

        assert newest(keys) == "netassess-2026.8.10.zip"

    def test_no_runs_is_not_a_run(self) -> None:
        assert newest(["README.md"]) is None


class TestFreshness:
    def test_a_recent_run_is_healthy(self) -> None:
        result = freshness(
            ["netassess-2026.8.25.zip"], now=date(2026, 8, 28), max_age_days=10
        )

        assert result.healthy
        assert result.age_days == 3

    def test_a_stale_run_names_the_scheduled_task(self) -> None:
        """The operator reading this needs to know *what* stopped, not that a
        number exceeded a threshold."""
        result = freshness(
            ["netassess-2026.8.1.zip"], now=date(2026, 8, 28), max_age_days=10
        )

        assert not result.healthy
        assert result.problem is not None
        assert "Weekly Network Scan" in result.problem
        assert "27 days" in result.problem

    def test_never_having_run_is_its_own_answer(self) -> None:
        """Distinct from stale: nothing has ever been published, so there is no
        age to report and nothing to diff against."""
        result = freshness([], now=date(2026, 8, 28))

        assert not result.healthy
        assert result.age_days is None
        assert "never" in (result.problem or "")


class TestVerify:
    def test_a_clean_run_is_believable(self) -> None:
        verdict = verify(inventory_csv=INVENTORY, network_status_md=CLEAN_STATUS)

        assert verdict.believable
        assert verdict.host_count == 2

    def test_an_unknown_line_is_a_failure_not_a_warning(self) -> None:
        """The degradation case. nmap could not answer, so the target was not
        assessed — passing on that lets a NAS that is switched off read the
        same as one confirmed closed."""
        status = "# Network status\n\nNFS: unknown (scan failed)\nSMB: SMBv2 only\n"

        verdict = verify(inventory_csv=INVENTORY, network_status_md=status)

        assert not verdict.believable
        assert any("did not run" in p for p in verdict.problems)

    def test_a_missing_inventory_means_it_enumerated_nothing(self) -> None:
        verdict = verify(inventory_csv=None, network_status_md=CLEAN_STATUS)

        assert not verdict.believable
        assert any("enumerated nothing" in p for p in verdict.problems)

    def test_an_empty_inventory_is_not_a_clean_scan(self) -> None:
        """Header only. The file exists, so a presence check would pass it."""
        verdict = verify(inventory_csv="address,mac,label\n", network_status_md=CLEAN_STATUS)

        assert not verdict.believable
        assert verdict.host_count == 0

    def test_a_missing_status_means_the_scan_did_not_finish(self) -> None:
        verdict = verify(inventory_csv=INVENTORY, network_status_md=None)

        assert not verdict.believable
        assert any("did not finish" in p for p in verdict.problems)

    def test_real_exposure_is_reported(self) -> None:
        status = CLEAN_STATUS + "\nNFS: EXPORTS PRESENT\nSMB: SMBv1 ENABLED\n"

        verdict = verify(inventory_csv=INVENTORY, network_status_md=status)

        assert not verdict.believable
        assert "NAS is exporting NFS shares" in verdict.problems
        assert "NAS has SMBv1 enabled" in verdict.problems

    def test_an_open_ap_is_reported(self) -> None:
        verdict = verify(
            inventory_csv=INVENTORY,
            network_status_md=CLEAN_STATUS + "\nOpen AP broadcasting on channel 6\n",
        )

        assert "an open Wi-Fi AP is broadcasting" in verdict.problems


class TestHostDiff:
    def test_a_new_host_is_reported_with_its_address(self) -> None:
        after = INVENTORY + "192.168.0.99,AA:BB:CC:00:00:03,unknown-laptop\n"

        diff = diff_hosts(INVENTORY, after)

        assert [h.mac for h in diff.appeared] == ["AA:BB:CC:00:00:03"]
        assert "192.168.0.99" in str(diff.appeared[0])
        assert diff.disappeared == []

    def test_a_departed_host_is_reported(self) -> None:
        before = INVENTORY + "192.168.0.99,AA:BB:CC:00:00:03,laptop\n"

        diff = diff_hosts(before, INVENTORY)

        assert [h.mac for h in diff.disappeared] == ["AA:BB:CC:00:00:03"]

    def test_a_host_that_moved_address_is_not_a_change(self) -> None:
        """MAC-keyed, so a DHCP lease moving a device does not read as one host
        vanishing and another appearing. That is the reason the inventory is
        keyed the way it is."""
        moved = INVENTORY.replace("192.168.0.14,", "192.168.0.77,")

        diff = diff_hosts(INVENTORY, moved)

        assert not diff.changed

    def test_case_is_not_a_change(self) -> None:
        """A change in how the writer formats a MAC must not read as every host
        being replaced at once."""
        lowered = INVENTORY.lower()

        diff = diff_hosts(INVENTORY, lowered)

        assert not diff.changed

    def test_a_first_run_says_so(self) -> None:
        diff = diff_hosts(None, INVENTORY)

        assert not diff.changed
        assert diff.unavailable is not None


class TestSummary:
    def test_a_clean_run_reads_clean(self) -> None:
        text = summarise(
            verify(inventory_csv=INVENTORY, network_status_md=CLEAN_STATUS),
            freshness(["netassess-2026.8.25.zip"], now=date(2026, 8, 28)),
        )

        assert "inventory rows: 2" in text
        assert "problems: none" in text

    def test_a_degraded_run_says_what_is_wrong(self) -> None:
        text = summarise(
            verify(
                inventory_csv=INVENTORY,
                network_status_md="NFS: unknown (scan failed)\n",
            ),
            freshness(["netassess-2026.8.1.zip"], now=date(2026, 8, 28)),
        )

        assert "did not run" in text
        assert "Weekly Network Scan" in text
