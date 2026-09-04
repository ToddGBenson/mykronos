"""Remediation taken from the scan rather than invented here (B-026).

The test that matters is `test_a_package_with_no_published_fix_says_so`. The
standing text said a container CVE was fixed by rebuilding on a current base
image. Trivy reported no fixed version for 231 of 234 open container findings,
and a freshly pulled `python:3.13-slim` was verified to ship byte-identical
package versions to the deployed one. The advice was confidently wrong, and
only reading the scan could say so.
"""

from __future__ import annotations

from mykronos import guidance
from mykronos.auth import TokenRegistry
from tests.conftest import REPO, finding_payload, post_findings, post_scan


def _ingest(client, auth, findings: list[dict], capability: str = "sast") -> None:
    """The shared token only grants `sast`; every other capability has to be
    granted before it may write (D-009)."""
    with client.app.state.db.session() as session:
        TokenRegistry(session).grant(REPO, capability)
    assert post_scan(
        client, auth, scan_run_id="run-1", capability=capability
    ).status_code < 400
    response = post_findings(client, auth, findings, scan_run_id="run-1", capability=capability)
    assert response.status_code < 400, response.text


class TestItReadsTheScanner:
    def test_zap_solution_is_used_verbatim(self, client, auth, catalog, run_compaction) -> None:
        """ZAP writes the best remediation text in the estate and it was being
        discarded. Nothing here paraphrases it."""
        _ingest(
            client,
            auth,
            [
                finding_payload(
                    rule_id="ZAP-10021",
                    title="X-Content-Type-Options Header Missing at GET /retro",
                    raw_finding_json={
                        "solution": "<p>Ensure that the web server sets "
                        "X-Content-Type-Options to 'nosniff'.</p>"
                    },
                )
            ],
            capability="dast",
        )
        run_compaction()

        rule = guidance.by_rule(catalog)[0].rules[0]

        assert "nosniff" in rule.fix
        assert "<p>" not in rule.fix, "HTML belongs in the alert, not a table cell"
        assert rule.source == "scanner"

    def test_a_package_with_a_published_fix_names_the_version(
        self, client, auth, catalog, run_compaction
    ) -> None:
        _ingest(
            client,
            auth,
            [
                finding_payload(
                    rule_id="CVE-2026-1",
                    title="setuptools: path traversal",
                    raw_finding_json={
                        "message": {
                            "text": "Package: setuptools Installed Version: 70.3.0 "
                            "Vulnerability CVE-2026-1 Severity: HIGH "
                            "Fixed Version: 78.1.1 Link: [x](y)"
                        }
                    },
                )
            ],
            capability="containers",
        )
        run_compaction()

        rule = guidance.by_rule(catalog)[0].rules[0]

        assert "78.1.1" in rule.fix
        assert rule.effort == "upgrade"
        assert rule.actionable is True

    def test_a_package_with_no_published_fix_says_so(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """The correction this module exists for.

        Trivy leaves `Fixed Version` empty when no patch has been published.
        Telling somebody to rebuild the base image then sends them to do a day
        of work that cannot close a single finding — verified by pulling a
        fresh `python:3.13-slim` and finding byte-identical package versions.
        """
        _ingest(
            client,
            auth,
            [
                finding_payload(
                    rule_id="CVE-2026-2",
                    title="glibc: buffer overflow",
                    raw_finding_json={
                        "message": {
                            "text": "Package: libc6 Installed Version: 2.41-12+deb13u3 "
                            "Vulnerability CVE-2026-2 Severity: MEDIUM "
                            "Fixed Version: Link: [x](y)"
                        }
                    },
                )
            ],
            capability="containers",
        )
        run_compaction()

        summary = guidance.by_rule(catalog)[0]
        rule = summary.rules[0]

        assert rule.effort == "no_fix"
        assert rule.actionable is False
        assert "rebuild closes nothing" in rule.fix
        assert "no_vendor_fix" in rule.fix, "the route that does apply must be named"
        assert summary.unactionable == 1


class TestGroupingAndOrder:
    def test_one_rule_across_many_urls_is_one_row(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """Forty alerts across forty URLs are one policy line. Listing them as
        forty rows is how a five-minute change looks like a sprint."""
        _ingest(
            client,
            auth,
            [
                finding_payload(
                    rule_id="ZAP-10038",
                    title=f"Content Security Policy Header Not Set at GET /page-{n}",
                    file_path=f"/page-{n}",
                    raw_finding_json={"solution": "Set the header."},
                )
                for n in range(4)
            ],
            capability="dast",
        )
        run_compaction()

        rules = guidance.by_rule(catalog)[0].rules

        assert len(rules) == 1, "the URL is not part of the problem"
        assert rules[0].count == 4
        assert "at GET" not in rules[0].title

    def test_cheapest_first_within_a_capability(self) -> None:
        """`config` is a few lines closing many; `no_fix` cannot be worked at
        all. Sorting on count would bury the cheapest thing on the page."""
        assert guidance.EFFORT.index("config") < guidance.EFFORT.index("judgement")
        assert guidance.EFFORT.index("judgement") < guidance.EFFORT.index("no_fix")

    def test_a_header_alert_is_config_and_a_content_one_is_not(self) -> None:
        """ZAP titles a CSP alert without the word "header" — 57 findings and
        one policy line, which a naive match called a judgement and buried.
        But a suspicious comment is a decision about a line of source, whatever
        its title looks like."""
        solution = {"solution": "Set the header."}

        assert guidance._dast(solution, "CSP: style-src unsafe-inline")[2] == "config"
        assert guidance._dast(solution, "Insufficient Site Isolation")[2] == "config"
        assert guidance._dast(solution, "X-Content-Type-Options Header Missing")[2] == "config"
        assert (
            guidance._dast(solution, "Information Disclosure - Suspicious Comments")[2]
            == "judgement"
        )

    def test_entities_are_unescaped_twice(self) -> None:
        """Trivy double-encodes, so one pass leaves `-&gt;` on the page."""
        assert "&" not in guidance._clean("EUC_JISX0213 -&amp;gt; UCS4")

    def test_an_empty_lake_is_not_an_error(self, catalog) -> None:
        assert guidance.by_rule(catalog) == []


class TestHonesty:
    def test_standing_advice_is_labelled_as_ours(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """Gitleaks reports the match, not a remedy. The remedy is ours, and
        the page says so — "the tool told us" and "we think" do not deserve
        equal trust."""
        _ingest(
            client,
            auth,
            [
                finding_payload(
                    rule_id="generic-api-key",
                    title="Exposed secret",
                    raw_finding_json={"File": "pipelines/thehub.yml"},
                )
            ],
            capability="secrets",
        )
        run_compaction()

        rule = guidance.by_rule(catalog)[0].rules[0]

        assert rule.source == "standing"
        assert rule.effort == "rotate"
        # Order matters and the text has to carry it: removing without
        # rotating leaves a disclosed credential disclosed.
        assert "Rotate" in rule.fix
        assert rule.fix.index("Rotate") < rule.fix.index("remove")

    def test_unparseable_raw_json_falls_back_rather_than_raising(self) -> None:
        """A scanner that writes something unexpected must cost one row's
        guidance, not the page."""
        fix, source, effort = guidance._for("dast", {}, "Anything")

        assert fix and source == "standing" and effort == "judgement"

    def test_scoping_to_one_repository(self, client, auth, catalog, run_compaction) -> None:
        _ingest(client, auth, [finding_payload()])
        run_compaction()

        assert guidance.by_rule(catalog), "the estate-wide view has rows"
        assert guidance.by_rule(catalog, asset_id="ToddGBenson/nothing-here") == []


class TestGroupingByFix:
    """One level above grouping by rule: several rules, one change.

    `ZAP-10038` ("CSP Header Not Set") and `ZAP-10055` ("CSP: style-src
    unsafe-inline") are separate plugins with separate ids, and both are
    answered by one Content-Security-Policy value. Presented as two rows,
    somebody does the work twice or does half of it.
    """

    def test_two_rules_naming_one_header_are_one_fix(
        self, client, auth, catalog, run_compaction
    ) -> None:
        _ingest(
            client,
            auth,
            [
                finding_payload(
                    rule_id="ZAP-10038",
                    title="Content Security Policy Header Not Set at GET /a",
                    file_path="/a",
                    raw_finding_json={
                        "solution": "Ensure that your web server is configured "
                        "to set the Content-Security-Policy header."
                    },
                ),
                finding_payload(
                    rule_id="ZAP-10055",
                    title="CSP: style-src unsafe-inline at GET /b",
                    file_path="/b",
                    raw_finding_json={
                        "solution": "Ensure that your web server is properly "
                        "configured to set the Content-Security-Policy header."
                    },
                ),
            ],
            capability="dast",
        )
        run_compaction()

        groups = guidance.fix_groups(catalog)

        assert len(groups) == 1, "two rules, one header, one change"
        assert groups[0].collapses_rules is True
        assert sorted(groups[0].rules) == ["ZAP-10038", "ZAP-10055"]
        assert groups[0].findings == 2

    def test_the_operative_header_wins_over_the_one_merely_mentioned(self) -> None:
        """ZAP's solution for a missing `X-Content-Type-Options` also mentions
        `Content-Type`. Taking the first — or the first alphabetically — files
        the finding under a fix that does not exist."""
        solution = (
            "Ensure that the application/web server sets the Content-Type "
            "header appropriately, and that it sets the X-Content-Type-Options "
            "header to 'nosniff' for all web pages."
        )

        assert (
            guidance._header_named_by(solution, "X-Content-Type-Options Header Missing")
            == "X-Content-Type-Options"
        )

    def test_two_advisories_on_one_package_are_one_upgrade(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """Fixed in 78.1.1 and 83.0.0 is one upgrade, to 83.0.0. Two groups
        would ask for the work twice, and the first would not have closed the
        second."""
        _ingest(
            client,
            auth,
            [
                finding_payload(
                    rule_id=f"CVE-2026-100{n}",
                    title="setuptools: something",
                    package_name="setuptools",
                    raw_finding_json={
                        "message": {
                            "text": "Package: setuptools Installed Version: 70.3.0 "
                            f"Fixed Version: {version} Link: [x](y)"
                        }
                    },
                )
                for n, version in enumerate(("78.1.1", "83.0.0"))
            ],
            capability="containers",
        )
        run_compaction()

        groups = guidance.fix_groups(catalog)

        assert len(groups) == 1
        assert groups[0].action == "Upgrade setuptools to 83.0.0"
        assert groups[0].collapses_rules is True

    def test_the_highest_version_is_numeric_not_lexical(self) -> None:
        """`"9.0" > "10.0"` as strings, and offering 9.0 would leave the
        advisory that needed 10.0 open."""
        assert guidance._highest({"9.0", "10.0"}) == "10.0"
        assert guidance._highest({"1.2.10", "1.2.9"}) == "1.2.10"

    def test_a_class_with_no_shared_fix_is_not_collapsed(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """Two SAST rules are two judgements. Grouping them would be a
        collapse that reads as progress and is not one."""
        _ingest(
            client,
            auth,
            [
                finding_payload(rule_id="rule-a", title="A", file_path="a.py"),
                finding_payload(rule_id="rule-b", title="B", file_path="b.py"),
            ],
        )
        run_compaction()

        groups = guidance.fix_groups(catalog)

        assert len(groups) == 2
        assert all(not g.collapses_rules for g in groups)

    def test_every_group_ends_with_closure(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """A change nobody scans again closes nothing, however correct it is.
        That is the defect D-098 exists to report, so the guide says it."""
        _ingest(
            client,
            auth,
            [
                finding_payload(
                    rule_id="ZAP-10063",
                    title="Permissions Policy Header Not Set at GET /a",
                    raw_finding_json={
                        "solution": "Configure the Permissions-Policy header."
                    },
                )
            ],
            capability="dast",
        )
        run_compaction()

        steps = guidance.fix_groups(catalog)[0].steps

        assert steps, "a config fix has a guide"
        assert "consecutive successful scans" in steps[-1]
