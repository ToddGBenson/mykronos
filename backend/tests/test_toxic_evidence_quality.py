"""Toxic combinations must not escalate low-quality evidence (TheHub #60965).

Two critical combinations were reported that the evidence did not support:

- `vulnerable-image-and-live-service` fired on a missing
  Cross-Origin-Resource-Policy header. ZAP titles carry the route
  ("... at GET /api/version"), so the old title pattern matched `version` in
  the route rather than anything the service disclosed about itself.
- `live-unauth-and-committed-credential` fired on a secrets finding that was a
  false positive.

So the disclosure half of that rule is now a configured list of ZAP alerts
that do disclose what the service runs, a member dispositioned
`false_positive` or `accepted_risk` no longer counts toward any combination,
and every combination says which finding satisfied which half, and why.
"""

from __future__ import annotations

from typing import Any

import pytest

from mykronos import toxic
from mykronos.config import get_settings
from mykronos.oracle import OracleEngine, load_policy
from mykronos.patchwork import correlate
from tests.conftest import REPO, finding_payload, post_findings, post_scan


def finding(
    finding_id: str,
    rule_id: str,
    capability: str,
    *,
    title: str = "",
    severity: str = "high",
    status: str | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "title": title or rule_id,
        "file_path": "",
        "capability": capability,
        "severity": severity,
    }
    if status is not None:
        row["status"] = status
    return row


CVE = finding("c1", "CVE-2024-4812", "containers", severity="high")
#: The finding that produced the live critical: a missing CORP header on a
#: route whose path happens to contain "version".
CORP = finding(
    "d1",
    "ZAP-90004-CWE-693",
    "dast",
    title="Insufficient Site Isolation Against Spectre Vulnerability at GET /api/version",
    severity="low",
)
VULNERABLE_IMAGE = next(
    r for r in correlate.BUILT_IN_RULES if r.rule_id == "vulnerable-image-and-live-service"
)
LIVE_CREDENTIAL = next(
    r for r in correlate.BUILT_IN_RULES if r.rule_id == "live-unauth-and-committed-credential"
)


class TestDisclosureClassDast:
    def test_a_corp_header_finding_produces_no_combination(self) -> None:
        assert correlate.detect([CVE, CORP]) == []

    def test_a_route_naming_auth_or_version_does_not_qualify(self) -> None:
        """The route is where ZAP saw the alert, not what the alert says."""
        for title in (
            "Missing Anti-clickjacking Header at GET /api/version",
            "Content Security Policy (CSP) Header Not Set at GET /auth/login",
            "X-Content-Type-Options Header Missing at GET /exposed/banner",
        ):
            dast = finding("d1", "ZAP-10021-CWE-693", "dast", title=title, severity="low")
            assert correlate.detect([CVE, dast], rules=(VULNERABLE_IMAGE,)) == [], title

    def test_the_list_is_configured_and_names_the_story_examples(self) -> None:
        assert {"10036", "10037", "90022"} <= set(correlate.DISCLOSURE_CLASS_DAST_RULES)
        assert VULNERABLE_IMAGE.requires[1].rule_ids == correlate.DISCLOSURE_CLASS_DAST_RULES

    @pytest.mark.parametrize(
        ("rule_id", "title"),
        [
            ("ZAP-10036-CWE-497", 'Server Leaks Version Information via "Server" '
             "HTTP Response Header Field at GET /"),
            ("ZAP-10037-CWE-497", 'Server Leaks Information via "X-Powered-By" '
             "HTTP Response Header Field(s) at GET /"),
            ("ZAP-90022-CWE-550", "Application Error Disclosure at GET /"),
        ],
    )
    def test_a_disclosure_class_alert_pairs_with_a_high_cve(
        self, rule_id: str, title: str
    ) -> None:
        dast = finding("d1", rule_id, "dast", title=title, severity="low")

        combos = correlate.detect([CVE, dast])

        assert [c.rule_id for c in combos] == ["vulnerable-image-and-live-service"]

    def test_the_alert_number_must_match_exactly(self) -> None:
        """`ZAP-100370` is not `ZAP-10037`: a prefix match would let any alert
        whose number starts with a listed one through."""
        for rule_id in ("ZAP-100370", "ZAP-910036", "10037", "CVE-10037"):
            dast = finding("d1", rule_id, "dast", title="X-Powered-By", severity="low")
            assert correlate.detect([CVE, dast], rules=(VULNERABLE_IMAGE,)) == [], rule_id

    def test_a_listed_number_from_another_capability_does_not_qualify(self) -> None:
        sast = finding("s1", "ZAP-10037", "sast", severity="low")
        assert correlate.detect([CVE, sast], rules=(VULNERABLE_IMAGE,)) == []


class TestDispositionedMembersStopCounting:
    @pytest.mark.parametrize("status", ["false_positive", "accepted_risk"])
    def test_a_dispositioned_credential_does_not_make_a_combination(self, status: str) -> None:
        """The second live critical: a gitleaks false positive."""
        dast = finding("d1", "ZAP-10202", "dast", title="Missing auth token", severity="medium")
        secret = finding(
            "s1", "generic-api-key", "secrets", severity="high", status=status
        )

        assert correlate.detect([dast, secret], rules=(LIVE_CREDENTIAL,)) == []

    @pytest.mark.parametrize("status", ["false_positive", "accepted_risk"])
    def test_another_open_member_can_still_complete_it(self, status: str) -> None:
        dast = finding("d1", "ZAP-10202", "dast", title="Missing auth token", severity="medium")
        dismissed = finding("s1", "generic-api-key", "secrets", status=status)
        live = finding("s2", "generic-api-key", "secrets", status="open")

        combos = correlate.detect([dast, dismissed, live], rules=(LIVE_CREDENTIAL,))

        assert [c.finding_ids for c in combos] == [frozenset({"d1", "s2"})]

    def test_a_finding_without_a_status_still_counts(self) -> None:
        """Patchwork's candidate pool is open findings and carries no status
        column; absence is not a disposition."""
        dast = finding("d1", "ZAP-10037", "dast", severity="low")
        assert len(correlate.detect([CVE, dast])) == 1


class TestEvidenceNamesWhyEachMemberQualifies:
    def test_each_member_carries_its_reason(self) -> None:
        dast = finding(
            "d1", "ZAP-10037-CWE-497", "dast",
            title='Server Leaks Information via "X-Powered-By" at GET /', severity="low",
        )

        combo = correlate.detect([CVE, dast])[0]
        why = dict(combo.qualifications)

        assert set(why) == {"c1", "d1"}
        assert "10037" in why["d1"] and "disclosure" in why["d1"]
        assert "CVE-" in why["c1"] and "high" in why["c1"]

    def test_the_rationale_lists_the_members(self) -> None:
        dast = finding("d1", "ZAP-10037", "dast", severity="low")

        combo = correlate.detect([CVE, dast])[0]

        assert "`CVE-2024-4812`" in combo.rationale
        assert "`ZAP-10037`" in combo.rationale


def _seed(client, auth, run_compaction, findings) -> None:
    post_scan(client, auth, scan_run_id="run-1")
    post_findings(client, auth, findings, scan_run_id="run-1")
    run_compaction()


def _pair() -> list[dict[str, Any]]:
    return [
        finding_payload(
            rule_id="CWE-89", title="SQL injection via string concatenation",
            severity="medium", file_path="orders/query.py", symbol="get_order",
            code_snippet="q()",
        ),
        finding_payload(
            rule_id="CWE-306", title="Missing authentication for critical function",
            severity="medium", file_path="orders/query.py", symbol="admin",
            code_snippet="a()",
        ),
    ]


class TestTheSharedAnswer:
    def test_members_name_why_they_qualify_everywhere(
        self, client, auth, admin_auth, run_compaction, catalog
    ) -> None:
        _seed(client, auth, run_compaction, _pair())

        combos = toxic.detect(catalog, repo=REPO)
        api = client.get("/api/dashboard/toxic-combinations", headers=admin_auth).json()
        decision = OracleEngine(catalog, load_policy(get_settings().oracle_policy_path)).evaluate(
            REPO
        )

        assert all(m["qualifies"] for m in combos[0].members)
        assert all(m["qualifies"] for m in api["combinations"][0]["members"])
        snap = decision.inputs_snapshot["toxic_combinations"]["combinations"][0]
        assert set(snap["qualifies"]) == set(snap["finding_ids"])
        assert all(snap["qualifies"].values())

    def test_a_false_positive_member_closes_the_combination(
        self, client, auth, admin_auth, run_compaction, catalog
    ) -> None:
        _seed(client, auth, run_compaction, _pair())
        assert len(toxic.detect(catalog, repo=REPO)) == 1
        injectable = catalog.query("SELECT finding_id FROM findings WHERE rule_id = 'CWE-89'")[0][0]

        response = client.patch(
            f"/api/dashboard/findings/{injectable}/status",
            json={"status": "false_positive", "reason": "Parameterised two lines later."},
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        run_compaction()

        assert toxic.detect(catalog, repo=REPO) == []


def _error_disclosure(fid: str, raw: Any) -> dict[str, Any]:
    row = finding(
        fid, "ZAP-90022-CWE-550", "dast",
        title="Application Error Disclosure at GET /api/orders", severity="low",
    )
    row["raw_finding_json"] = raw
    return row


class TestErrorDisclosureNeedsEvidence:
    """ZAP 90022 fires on any error page (TheHub #61014).

    "Application Error Disclosure" is raised for a generic 500 body as readily
    as for a stack trace, so the alert number alone does not show that the
    service disclosed what it runs. A 90022 counts as the disclosure half only
    when its evidence shows a stack trace, a framework or a version string;
    evidence that cannot be read counts (fail closed)."""

    @pytest.mark.parametrize(
        "evidence",
        [
            "An internal error occurred",
            "HTTP/1.1 500 Internal Server Error",
            "<p>Something went wrong. Please try again later.</p>",
        ],
    )
    def test_a_generic_error_body_does_not_qualify(self, evidence: str) -> None:
        dast = _error_disclosure("d1", {"instance": {"uri": "/", "evidence": evidence}})

        assert correlate.detect([CVE, dast], rules=(VULNERABLE_IMAGE,)) == [], evidence

    @pytest.mark.parametrize(
        ("raw", "shown"),
        [
            (
                {"instance": {"evidence": 'Traceback (most recent call last):\n  File '
                              '"/app/orders.py", line 41, in get_order'}},
                "Traceback",
            ),
            (
                {"instance": {"evidence": "at com.acme.Orders.get(Orders.java:41)"}},
                "Orders.java:41",
            ),
            ({"instance": {"evidence": "Werkzeug Debugger"}}, "Werkzeug"),
            ({"instance": {"evidence": "nginx/1.18.0"}}, "nginx/1.18.0"),
            (
                {"instance": {"evidence": "500"}, "otherinfo": "<p>Django version 3.2.4</p>"},
                "Django",
            ),
        ],
    )
    def test_a_stack_trace_framework_or_version_qualifies(
        self, raw: dict[str, Any], shown: str
    ) -> None:
        dast = _error_disclosure("d1", raw)

        combos = correlate.detect([CVE, dast], rules=(VULNERABLE_IMAGE,))

        assert [c.finding_ids for c in combos] == [frozenset({"c1", "d1"})]
        why = dict(combos[0].qualifications)["d1"]
        assert shown in why and "evidence" in why

    @pytest.mark.parametrize("raw", [None, "{not json", {}, {"instance": {"evidence": ""}}])
    def test_unreadable_evidence_qualifies(self, raw: Any) -> None:
        """Fail closed: evidence nobody can read is not evidence of absence."""
        dast = _error_disclosure("d1", raw)

        combos = correlate.detect([CVE, dast], rules=(VULNERABLE_IMAGE,))

        assert len(combos) == 1
        assert "unreadable" in dict(combos[0].qualifications)["d1"]

    def test_other_listed_alerts_need_no_evidence(self) -> None:
        """10037 is a header naming the stack: the alert itself is the evidence."""
        dast = finding("d1", "ZAP-10037-CWE-497", "dast", severity="low")
        dast["raw_finding_json"] = {"instance": {"evidence": "An internal error occurred"}}

        assert len(correlate.detect([CVE, dast], rules=(VULNERABLE_IMAGE,))) == 1


class TestErrorDisclosureThroughTheLake:
    """The risk decision reads its pool from the lake, which carries the raw
    record; the pool must read the 90022 evidence or every one would count."""

    @staticmethod
    def _seed(client, run_compaction, evidence: str) -> None:
        import uuid

        from tests.conftest import dependency_finding, issue_token

        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas', 'dast')}"}
        for capability, payload in (
            ("atlas", dependency_finding(severity="high")),
            (
                "dast",
                finding_payload(
                    rule_id="ZAP-90022-CWE-550",
                    title="Application Error Disclosure at GET /api/orders",
                    severity="low", file_path=None, line_start=None, line_end=None,
                    symbol=None, code_snippet=None,
                    raw_finding_json={
                        "pluginid": "90022",
                        "instance": {"uri": "/api/orders", "method": "GET",
                                     "evidence": evidence},
                    },
                ),
            ),
        ):
            run = str(uuid.uuid4())
            post_scan(client, auth, scan_run_id=run, capability=capability)
            response = post_findings(
                client, auth, [payload], scan_run_id=run, capability=capability
            )
            assert response.status_code in (200, 201), response.text
        run_compaction()

    def test_a_generic_500_forms_no_combination(
        self, client, admin_auth, run_compaction, catalog
    ) -> None:
        self._seed(client, run_compaction, "An internal error occurred")

        assert toxic.detect(catalog, repo=REPO) == []
        api = client.get("/api/dashboard/toxic-combinations", headers=admin_auth).json()
        assert api["combinations"] == []
        from mykronos.dashboard import DashboardQueries

        page = DashboardQueries(catalog).open_findings(REPO)
        assert page["toxic_combinations"] == []

    def test_a_stack_trace_forms_it(self, client, admin_auth, run_compaction, catalog) -> None:
        self._seed(
            client, run_compaction,
            'Traceback (most recent call last):\n  File "/app/orders.py", line 41',
        )

        combos = toxic.detect(catalog, repo=REPO)

        assert [c.rule_id for c in combos] == ["vulnerable-image-and-live-service"]
        assert any("Traceback" in m["qualifies"] for m in combos[0].members)
