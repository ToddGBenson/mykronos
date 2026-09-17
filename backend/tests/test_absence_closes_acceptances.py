"""An acceptance stops when the vulnerability does (B-071, issue #407).

`reconcile_absences` read `status = 'open'` and passed `only_if_status="open"`,
so the rule that retires a finding when two consecutive scans no longer see it
applied to open findings alone. An `accepted_risk` finding was therefore
unreachable by it: TheHub carried 12 `critical` acceptances for three perl CVEs
that had been patched twelve successful scans earlier, and nothing short of a
person arriving on the October review date could have ended them.

The judgement in the fix is about *which* dispositions absence may end, and
these tests pin both halves of it. `accepted_risk` is a judgement about the
risk a live vulnerability poses, and absence removes the vulnerability.
`false_positive` and `suppressed` are judgements about the finding itself,
where the scanner going quiet is not news — and where auto-closing would be
worse than useless, because compaction reopens a `fixed` finding on the next
sighting and the human decision would be gone.

The safety premise underneath all of it — that an accepted finding the scanner
still reports carries a *current* `last_seen_scan_run_id` and so is never a
candidate — is pinned by `TestAnAcceptanceStillBeingReported`. Without it this
change would close every acceptance in the estate on its first run.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient

from mykronos.jobs import sweep_acceptances
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.lake.reconcile import reconcile_absences
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan


def scan(
    client: TestClient,
    token: str,
    run_id: str,
    findings: list[dict[str, Any]] | None = None,
    *,
    branch: str = "main",
    capability: str = "sast",
    status: str = "success",
) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    post_scan(
        client,
        headers,
        scan_run_id=run_id,
        capability=capability,
        branch=branch,
        scan_status=status,
    )
    post_findings(
        client, headers, findings or [], scan_run_id=run_id, capability=capability
    )


def only_finding(catalog: Catalog) -> str:
    return str(catalog.query("SELECT finding_id FROM findings")[0][0])


def row(catalog: Catalog) -> tuple[Any, ...]:
    return tuple(
        catalog.query(
            "SELECT status, resolved_at, accepted_until, accepted_reason_code "
            "FROM findings"
        )[0]
    )


def status_of(catalog: Catalog) -> str:
    return str(row(catalog)[0])


def accept(
    client: TestClient,
    admin_auth: dict[str, str],
    finding_id: str,
    **body: Any,
) -> Any:
    payload: dict[str, Any] = {
        "status": "accepted_risk",
        "reason": "no upstream patch",
        "accepted_reason_code": "no_vendor_fix",
        "accepted_until": (utcnow().date() + timedelta(days=30)).isoformat(),
    }
    payload.update(body)
    response = client.patch(
        f"/api/dashboard/findings/{finding_id}/status", json=payload, headers=admin_auth
    )
    assert response.status_code == 200, response.text
    return response


def set_status_directly(catalog: Catalog, finding_id: str, status: str) -> None:
    """For dispositions the endpoint reaches awkwardly, or not at all.

    Writes through the same helper the endpoint uses, so the row is shaped
    exactly as a real one is.
    """
    update_findings(
        catalog,
        locate_findings(catalog, [finding_id]),
        "status = ?",
        [status],
    )


def seed_accepted(
    client: TestClient, catalog: Catalog, admin_auth: dict[str, str], run_compaction: Any
) -> str:
    """One finding, seen once, then accepted by a person."""
    token = issue_token(client, REPO, "sast")
    scan(client, token, "run-1", [finding_payload(title="perl CVE-2026-13221")])
    run_compaction()
    finding_id = only_finding(catalog)
    accept(client, admin_auth, finding_id)
    assert status_of(catalog) == "accepted_risk"
    return finding_id


class TestAbsenceClosesAnAcceptance:
    def test_two_absences_close_an_accepted_finding(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        """The defect in #407, at its smallest. Perl was patched; the register
        went on reporting accepted critical risk for something that was gone."""
        seed_accepted(client, catalog, admin_auth, run_compaction)
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [])
        run_compaction()

        outcome = reconcile_absences(catalog)

        assert len(outcome.fixed) == 1
        assert status_of(catalog) == "fixed"

    def test_the_closure_is_counted_as_an_acceptance_ending(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        """The platform ending a decision somebody made by hand is the one
        number worth auditing separately, so it is reported separately."""
        seed_accepted(client, catalog, admin_auth, run_compaction)
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [])
        run_compaction()

        assert reconcile_absences(catalog).fixed_acceptances == 1

    def test_the_acceptance_is_superseded_not_discarded(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        """The decision is evidence about how this estate reasons. What ends
        is its standing as a live claim about a vulnerability, not the record
        that somebody made it and on what grounds."""
        seed_accepted(client, catalog, admin_auth, run_compaction)
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [])
        run_compaction()

        reconcile_absences(catalog)
        status, resolved_at, accepted_until, reason_code = row(catalog)

        assert str(status) == "fixed"
        assert resolved_at is not None
        assert accepted_until is not None
        assert str(reason_code) == "no_vendor_fix"


class TestAnAcceptanceStillBeingReported:
    """The premise the whole change rests on.

    Ingest reports every finding the scanner still sees whatever its status,
    and compaction refreshes `last_seen_scan_run_id` on the upsert while
    leaving the disposition alone. If that were not so, every acceptance in
    the estate would look absent and this change would close all of them on
    its first run.
    """

    def test_an_acceptance_the_scanner_still_sees_is_not_closed(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        seed_accepted(client, catalog, admin_auth, run_compaction)
        token = issue_token(client, REPO, "sast")
        still_there = [finding_payload(title="perl CVE-2026-13221")]
        scan(client, token, "run-2", still_there)
        scan(client, token, "run-3", still_there)
        run_compaction()

        outcome = reconcile_absences(catalog)

        assert outcome.fixed == []
        assert status_of(catalog) == "accepted_risk"

    def test_being_reported_once_more_resets_the_absence_count(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        """One absence, then a sighting, then one absence is not two
        consecutive absences — for an acceptance exactly as for an open
        finding."""
        seed_accepted(client, catalog, admin_auth, run_compaction)
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [finding_payload(title="perl CVE-2026-13221")])
        run_compaction()
        scan(client, token, "run-4", [])
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert status_of(catalog) == "accepted_risk"


class TestTheRulesTheOpenPathAlreadyHad:
    """Branch-awareness, the two-scan bar and the confirming-status rule are
    not features of `open`; they are features of absence. An acceptance gets
    every one of them."""

    def test_one_absence_does_not_close_an_acceptance(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        seed_accepted(client, catalog, admin_auth, run_compaction)
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-2", [])
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert status_of(catalog) == "accepted_risk"

    def test_another_branch_does_not_close_an_acceptance(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        """B-056 applied to the new path: a finding accepted on `develop` is
        not gone because `main` has been scanned twice."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "dev-1", [finding_payload(title="on develop")], branch="develop")
        run_compaction()
        accept(client, admin_auth, only_finding(catalog))
        scan(client, token, "main-1", [], branch="main")
        scan(client, token, "main-2", [], branch="main")
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert status_of(catalog) == "accepted_risk"

    def test_failed_scans_do_not_close_an_acceptance(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        """A scanner that fell over reported nothing, and nothing is not
        evidence that a risk somebody accepted has gone away."""
        seed_accepted(client, catalog, admin_auth, run_compaction)
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-2", [], status="failure")
        scan(client, token, "run-3", [], status="failure")
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert status_of(catalog) == "accepted_risk"


class TestDispositionsAbsenceMayNotEnd:
    """`false_positive` and `suppressed` are judgements about the *finding*,
    not about the risk, and the scanner going quiet is the scanner agreeing
    with them rather than new information.

    Closing one `fixed` would assert a remediation that never happened and
    feed it to mean-time-to-fix. It would also make the decision impermanent:
    compaction reopens a `fixed` finding the moment a scan sees it again, so
    an auto-closed false positive comes back `open` and the human judgement is
    gone. That reopening is *correct* for an acceptance — the vulnerability
    returned — and wrong here, which is the whole reason the two are split.
    """

    def test_a_false_positive_is_not_closed_by_absence(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-1", [finding_payload(title="not real")])
        run_compaction()
        response = client.patch(
            f"/api/dashboard/findings/{only_finding(catalog)}/status",
            json={"status": "false_positive", "reason": "test fixture, not prod"},
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [])
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert status_of(catalog) == "false_positive"

    def test_a_suppressed_finding_is_not_closed_by_absence(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-1", [finding_payload(title="noisy rule")])
        run_compaction()
        set_status_directly(catalog, only_finding(catalog), "suppressed")
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [])
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert status_of(catalog) == "suppressed"

    def test_a_superseded_record_is_not_closed_by_absence(
        self, client, catalog, run_compaction
    ) -> None:
        """A withdrawn record (spec 05 §5a) is absent by construction — the
        adapter that produced it was corrected. Closing those `fixed` would
        report a mass remediation every time an adapter was fixed."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-1", [finding_payload(title="mis-identified")])
        run_compaction()
        set_status_directly(catalog, only_finding(catalog), "superseded")
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [])
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert status_of(catalog) == "superseded"

    def test_a_stranded_finding_is_not_closed_by_absence(
        self, client, catalog, run_compaction
    ) -> None:
        """B-047: the capability lost the grant that lets it report. Restoring
        the grant returns it to `open` and absence decides then, on evidence."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-1", [finding_payload(title="lane went dark")])
        run_compaction()
        set_status_directly(catalog, only_finding(catalog), "stranded")
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [])
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert status_of(catalog) == "stranded"


class TestComposingWithTheAcceptanceSweep:
    """`sweep_acceptances` re-opens acceptances whose premise ran out. The two
    mechanisms answer different questions — "is the decision still valid?" and
    "is the vulnerability still there?" — and must not undo each other."""

    def test_the_sweep_does_not_revive_an_acceptance_absence_closed(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        """The sweep reads `status = 'accepted_risk'`, so a closed record is
        simply out of its scope — including the expiry branch, which would
        otherwise have put a `fixed` finding back on the queue on the review
        date."""
        seed_accepted(client, catalog, admin_auth, run_compaction)
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [])
        run_compaction()
        reconcile_absences(catalog)
        assert status_of(catalog) == "fixed"

        result = sweep_acceptances(
            catalog, today=utcnow().date() + timedelta(days=365)
        )

        assert result.expired == 0
        assert result.reopened_by_fix == 0
        assert status_of(catalog) == "fixed"

    def test_an_expired_acceptance_still_closes_through_the_open_path(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        """The other order. The sweep re-opens on the review date, and the
        next reconciliation closes it as an ordinary absent open finding —
        so whichever job runs first, the gone vulnerability ends up `fixed`."""
        seed_accepted(client, catalog, admin_auth, run_compaction)
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [])
        run_compaction()

        assert sweep_acceptances(
            catalog, today=utcnow().date() + timedelta(days=365)
        ).expired == 1
        assert status_of(catalog) == "open"

        assert len(reconcile_absences(catalog).fixed) == 1
        assert status_of(catalog) == "fixed"

    def test_reconciliation_is_idempotent_over_a_closed_acceptance(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        """A second pass must find nothing left to do. `fixed` is not in
        `CLOSEABLE_STATUSES`, so a closed acceptance cannot be re-closed and
        re-stamped with a later `resolved_at` on every cycle."""
        seed_accepted(client, catalog, admin_auth, run_compaction)
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [])
        run_compaction()
        assert len(reconcile_absences(catalog).fixed) == 1
        first_resolved_at = row(catalog)[1]

        second = reconcile_absences(catalog)

        assert second.fixed == []
        assert second.fixed_acceptances == 0
        assert row(catalog)[1] == first_resolved_at


class TestTheOpenPathIsUnchanged:
    """Regression guards. Extending the rule must not have altered it."""

    def test_an_absent_open_finding_still_closes(
        self, client, catalog, run_compaction
    ) -> None:
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-1", [finding_payload(title="ordinary")])
        run_compaction()
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [])
        run_compaction()

        outcome = reconcile_absences(catalog)

        assert len(outcome.fixed) == 1
        assert outcome.fixed_acceptances == 0
        assert status_of(catalog) == "fixed"

    def test_a_present_open_finding_still_stays_open(
        self, client, catalog, run_compaction
    ) -> None:
        token = issue_token(client, REPO, "sast")
        present = [finding_payload(title="ordinary")]
        scan(client, token, "run-1", present)
        run_compaction()
        scan(client, token, "run-2", present)
        scan(client, token, "run-3", present)
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert status_of(catalog) == "open"

    def test_an_open_and_an_accepted_finding_close_in_one_pass(
        self, client, catalog, admin_auth, run_compaction
    ) -> None:
        """Both buckets are written, and the partition rewrite of one does not
        drop the other — they share a partition."""
        token = issue_token(client, REPO, "sast")
        scan(
            client,
            token,
            "run-1",
            [
                finding_payload(title="accepted", file_path="a.py"),
                finding_payload(title="ordinary", file_path="b.py"),
            ],
        )
        run_compaction()
        accepted_id = str(
            catalog.query("SELECT finding_id FROM findings WHERE title = 'accepted'")[0][0]
        )
        accept(client, admin_auth, accepted_id)
        scan(client, token, "run-2", [])
        scan(client, token, "run-3", [])
        run_compaction()

        outcome = reconcile_absences(catalog)
        rows = catalog.query("SELECT title, status FROM findings ORDER BY title")

        assert len(outcome.fixed) == 2
        assert outcome.fixed_acceptances == 1
        assert [(str(r[0]), str(r[1])) for r in rows] == [
            ("accepted", "fixed"),
            ("ordinary", "fixed"),
        ]
