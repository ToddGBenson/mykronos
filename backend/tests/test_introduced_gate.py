"""The gate blocks on what a commit introduced, not on the backlog (D-048).

The failure this replaces: Oracle scores the whole open backlog, so once a
repository carries a few hundred findings every commit is refused regardless
of content. A gate that refuses everything is not a gate — it gets switched
off, and then it protects nothing.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from mykronos.dashboard import DashboardQueries
from mykronos.lake.mutate import locate_findings, update_findings
from tests.conftest import (
    REPO,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)
from tests.test_reprocess import _set_raw_ref


@pytest.fixture
def oracle_auth(client: TestClient) -> dict[str, str]:
    """`oracle` has to be granted explicitly - the default fixture token is
    scoped to one capability, and evaluating is a separate grant (D-009)."""
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'oracle')}"}


OLD = "a" * 40
NEW = "b" * 40


def _scan(client, auth, run_compaction, scan_run_id, commit, findings):
    post_scan(client, auth, scan_run_id=scan_run_id, commit_sha=commit)
    post_findings(client, auth, findings, scan_run_id=scan_run_id)
    run_compaction()


class TestIntroducedBy:
    def test_a_finding_from_this_commit_counts(
        self, client, auth, run_compaction, catalog
    ) -> None:
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="R1", severity="critical")],
        )

        introduced = DashboardQueries(catalog).introduced_by(REPO, NEW)

        assert introduced.get("critical") == 1

    def test_a_finding_from_an_earlier_commit_does_not(
        self, client, auth, run_compaction, catalog
    ) -> None:
        """The whole point. Backlog is not the commit's fault, and counting it
        is what made every build red."""
        _scan(
            client,
            auth,
            run_compaction,
            "run-old",
            OLD,
            [finding_payload(rule_id="OLD1", severity="critical")],
        )
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="NEW1", severity="low")],
        )

        introduced = DashboardQueries(catalog).introduced_by(REPO, NEW)

        assert introduced.get("critical") is None
        assert introduced.get("low") == 1

    def test_a_finding_that_persists_is_still_attributed_to_its_first_sighting(
        self, client, auth, run_compaction, catalog
    ) -> None:
        """Reported by both scans, introduced by the first. Otherwise every
        unfixed finding would be re-introduced on every commit and the gate
        would be the backlog gate again by another route."""
        payload = [finding_payload(rule_id="R1", severity="high")]
        _scan(client, auth, run_compaction, "run-old", OLD, payload)
        _scan(client, auth, run_compaction, "run-new", NEW, payload)

        assert DashboardQueries(catalog).introduced_by(REPO, NEW) == {}
        assert DashboardQueries(catalog).introduced_by(REPO, OLD).get("high") == 1

    def test_a_dispositioned_finding_does_not_block_its_own_commit(
        self, client, auth, run_compaction, catalog
    ) -> None:
        """An accepted risk with a reason is a decision, not an obstacle."""
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="R1", severity="critical")],
        )
        ids = [str(r[0]) for r in catalog.query("SELECT finding_id FROM findings")]
        update_findings(
            catalog, locate_findings(catalog, ids), "status = 'accepted_risk'", []
        )

        assert DashboardQueries(catalog).introduced_by(REPO, NEW) == {}

    def test_an_unknown_commit_introduced_nothing(
        self, client, auth, run_compaction, catalog
    ) -> None:
        _scan(
            client,
            auth,
            run_compaction,
            "run-old",
            OLD,
            [finding_payload(rule_id="R1", severity="critical")],
        )

        assert DashboardQueries(catalog).introduced_by(REPO, "c" * 40) == {}


class TestTheGateDecision:
    def test_the_evaluate_response_carries_the_floor(
        self, client, auth, oracle_auth, run_compaction
    ) -> None:
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="R1", severity="critical")],
        )

        body = client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": NEW, "decision_type": "portfolio"},
            headers=oracle_auth,
        ).json()

        assert body["introduced_blocking"] is True
        assert body["introduced"]["critical"] == 1

    def test_a_clean_commit_does_not_block_despite_a_backlog(
        self, client, auth, oracle_auth, run_compaction
    ) -> None:
        """The case that motivated D-048: a large standing backlog and a
        commit that adds nothing serious. The score stays bad; the gate
        passes."""
        _scan(
            client,
            auth,
            run_compaction,
            "run-old",
            OLD,
            [
                finding_payload(rule_id=f"OLD{i}", severity="critical")
                for i in range(5)
            ],
        )
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="NEW1", severity="low")],
        )

        body = client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": NEW, "decision_type": "portfolio"},
            headers=oracle_auth,
        ).json()

        assert body["introduced_blocking"] is False
        assert body["recommendation"] == "no_go", "the backlog is still bad"

    def test_a_new_high_blocks(
        self, client, auth, oracle_auth, run_compaction
    ) -> None:
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="R1", severity="high")],
        )

        body = client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": NEW, "decision_type": "portfolio"},
            headers=oracle_auth,
        ).json()

        assert body["introduced_blocking"] is True

    def test_a_new_medium_does_not(
        self, client, auth, oracle_auth, run_compaction
    ) -> None:
        """The floor is critical and high. Mediums are recorded and triaged;
        blocking on them is how a floor becomes something people lower."""
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="R1", severity="medium")],
        )

        body = client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": NEW, "decision_type": "portfolio"},
            headers=oracle_auth,
        ).json()

        assert body["introduced_blocking"] is False



class TestTheDeployHostHearsTheFloor:
    """#735. deploy.ps1 stopped only on a `no_go` recommendation, but the gate
    job refuses on the introduced floor - and the recommendation describes
    the backlog, so it is almost never `no_go`. 1588e40 was refused by the
    gate and would have shipped with a yellow note."""

    def test_a_commit_that_introduced_a_high_is_blocking_at_deploy_time(
        self, client, auth, oracle_auth, viewer_auth, run_compaction
    ) -> None:
        _scan(
            client, auth, run_compaction, "run-new", NEW,
            [finding_payload(rule_id="R1", severity="high")],
        )
        client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": NEW, "decision_type": "commit_gate"},
            headers=oracle_auth,
        )
        run_compaction()

        body = client.get(
            f"/api/oracle/decisions/by-commit/{NEW[:7]}", headers=viewer_auth
        ).json()

        assert body["found"] is True
        assert body["recommendation"] != "no_go", "the case the old check missed"
        assert body["introduced"] == {"high": 1}
        assert body["introduced_blocking"] is True

    def test_a_clean_commit_is_not(
        self, client, auth, oracle_auth, viewer_auth, run_compaction
    ) -> None:
        _scan(
            client, auth, run_compaction, "run-new", NEW,
            [finding_payload(rule_id="R1", severity="medium")],
        )
        client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": NEW, "decision_type": "commit_gate"},
            headers=oracle_auth,
        )
        run_compaction()

        body = client.get(
            f"/api/oracle/decisions/by-commit/{NEW}", headers=viewer_auth
        ).json()

        assert body["introduced_blocking"] is False
        assert body["introduced"] == {"medium": 1}

# -- #734: newly disclosed is not introduced ---------------------------------

ZAP = "ghcr.io/zaproxy/zaproxy:weekly@sha256:0c31"
SAME_BYTES = "sha256:9e18"
REBUILT = "sha256:77aa"


def _container_scan(
    client, run_compaction, scan_run_id, commit, started_at, image_id, cves
):
    """One containers scan of the ZAP image: its findings, and the archived
    Trivy report whose run properties say which bytes were scanned."""
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'containers')}"}
    post_scan(
        client,
        auth,
        scan_run_id=scan_run_id,
        commit_sha=commit,
        capability="containers",
        tool_name="trivy",
        tool_version="0.58.1",
        started_at=started_at,
    )
    post_findings(
        client,
        auth,
        [
            finding_payload(
                rule_id=cve,
                severity="high",
                title=f"libxtst6 {cve}",
                file_path="zaproxy/zaproxy",
                line_start=1,
                line_end=1,
                symbol=None,
                code_snippet=None,
                package_name="libxtst6",
                package_version="2:1.2.5-1",
                raw_finding_json={"ruleId": cve, "image": ZAP},
            )
            for cve in cves
        ],
        scan_run_id=scan_run_id,
        capability="containers",
    )
    settings = client.app.state.settings
    owner, name = REPO.split("/")
    folder = settings.raw_dir / owner / name / scan_run_id
    folder.mkdir(parents=True, exist_ok=True)
    report = {
        "version": "2.1.0",
        "runs": [{"results": [], "properties": {"imageName": ZAP, "imageID": image_id}}],
    }
    (folder / "trivy-estate-zap.sarif").write_text(json.dumps(report), encoding="utf-8")
    run_compaction()
    _set_raw_ref(
        client.app.state.catalog,
        scan_run_id,
        f"raw/{owner}/{name}/{scan_run_id}/trivy-estate-zap.sarif",
    )


class TestNewlyDisclosedIsNotIntroduced:
    def test_a_new_cve_in_unchanged_bytes_is_disclosed_not_introduced(
        self, client, run_compaction, catalog
    ) -> None:
        """The refusal of 1588e40: the ZAP image had the same imageID in the
        scan before, so the new high came from the vulnerability database,
        not from the commit."""
        _container_scan(
            client, run_compaction, "ctr-old", OLD, "2026-09-29T01:18:00", SAME_BYTES,
            ["CVE-OLD"],
        )
        _container_scan(
            client, run_compaction, "ctr-new", NEW, "2026-09-29T15:34:00", SAME_BYTES,
            ["CVE-OLD", "CVE-NEW"],
        )

        queries = DashboardQueries(catalog)
        assert queries.introduced_by(REPO, NEW) == {}
        assert queries.introduced_rows(REPO, NEW) == []
        assert queries.disclosed_by(REPO, NEW) == {"high": 1}

    def test_a_rebuilt_image_still_introduces(
        self, client, run_compaction, catalog
    ) -> None:
        """Different bytes: the commit may well have changed the image, and
        a new high in it is the commit's to answer for."""
        _container_scan(
            client, run_compaction, "ctr-old", OLD, "2026-09-29T01:18:00", SAME_BYTES,
            ["CVE-OLD"],
        )
        _container_scan(
            client, run_compaction, "ctr-new", NEW, "2026-09-29T15:34:00", REBUILT,
            ["CVE-OLD", "CVE-NEW"],
        )

        queries = DashboardQueries(catalog)
        assert queries.introduced_by(REPO, NEW) == {"high": 1}
        assert queries.disclosed_by(REPO, NEW) == {}

    def test_with_no_earlier_scan_everything_is_introduced(
        self, client, run_compaction, catalog
    ) -> None:
        """No evidence the image existed before, so no excuse."""
        _container_scan(
            client, run_compaction, "ctr-new", NEW, "2026-09-29T15:34:00", SAME_BYTES,
            ["CVE-NEW"],
        )

        assert DashboardQueries(catalog).introduced_by(REPO, NEW) == {"high": 1}

    def test_a_missing_archive_counts_as_introduced(
        self, client, run_compaction, catalog
    ) -> None:
        """The comparison needs both reports. Losing one must not open the
        gate - missing evidence answers "introduced"."""
        _container_scan(
            client, run_compaction, "ctr-old", OLD, "2026-09-29T01:18:00", SAME_BYTES,
            ["CVE-OLD"],
        )
        _container_scan(
            client, run_compaction, "ctr-new", NEW, "2026-09-29T15:34:00", SAME_BYTES,
            ["CVE-OLD", "CVE-NEW"],
        )
        owner, name = REPO.split("/")
        (
            client.app.state.settings.raw_dir / owner / name / "ctr-old"
            / "trivy-estate-zap.sarif"
        ).unlink()

        assert DashboardQueries(catalog).introduced_by(REPO, NEW) == {"high": 1}

    def test_the_gate_reports_it_and_does_not_block_on_it(
        self, client, oracle_auth, run_compaction
    ) -> None:
        _container_scan(
            client, run_compaction, "ctr-old", OLD, "2026-09-29T01:18:00", SAME_BYTES,
            ["CVE-OLD"],
        )
        _container_scan(
            client, run_compaction, "ctr-new", NEW, "2026-09-29T15:34:00", SAME_BYTES,
            ["CVE-OLD", "CVE-NEW"],
        )

        body = client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": NEW, "decision_type": "portfolio"},
            headers=oracle_auth,
        ).json()

        assert body["introduced_blocking"] is False
        assert body["introduced"] == {}
        assert body["disclosed"] == {"high": 1}
