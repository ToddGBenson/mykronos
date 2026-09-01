"""Vulnerable packages, and whether anything can be done about them (B-027).

The tab reported a trust score and advisory counts and never named a package.
The test that matters most here is `test_a_package_with_no_published_fix...`:
on this estate 218 of 221 TheHub advisories have nothing to upgrade to, and a
view that does not say so sends somebody to bump versions that do not exist.
"""

from __future__ import annotations

from mykronos import supply_chain
from mykronos.auth import TokenRegistry
from tests.conftest import REPO, finding_payload, post_findings, post_scan


def _ingest(client, auth, findings: list[dict], capability: str = "containers") -> None:
    with client.app.state.db.session() as session:
        TokenRegistry(session).grant(REPO, capability)
    post_scan(client, auth, scan_run_id="run-1", capability=capability)
    response = post_findings(client, auth, findings, scan_run_id="run-1", capability=capability)
    assert response.status_code < 400, response.text


def _advisory(package: str, version: str, cve: str, severity: str, fixed: str = "") -> dict:
    """A Trivy-shaped container advisory, including the flat message block the
    fixed version has to be parsed back out of."""
    return finding_payload(
        rule_id=cve,
        title=f"{package}: something bad",
        severity=severity,
        package_name=package,
        package_version=version,
        raw_finding_json={
            "message": {
                "text": (
                    f"Package: {package} Installed Version: {version} "
                    f"Vulnerability {cve} Severity: {severity.upper()} "
                    f"Fixed Version: {fixed} Link: [x](y)"
                )
            }
        },
    )


class TestNamingThePackages:
    def test_advisories_group_into_one_package(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """Twenty-three advisories against libc6 are one question about one
        package. Listing them separately is how a single decision looks like
        twenty-three pieces of work."""
        _ingest(
            client,
            auth,
            [
                _advisory("libc6", "2.41-12", "CVE-2026-1001", "medium"),
                _advisory("libc6", "2.41-12", "CVE-2026-1002", "high"),
                _advisory("curl", "8.14.1", "CVE-2026-1003", "low"),
            ],
        )
        run_compaction()

        analysis = supply_chain.vulnerable_packages(catalog, REPO)

        assert analysis.total == 2, "two packages, not three advisories"
        assert analysis.advisories == 3
        libc = next(p for p in analysis.packages if p.package_name == "libc6")
        assert libc.advisories == 2
        assert libc.worst_severity == "high", "the worst of the two, not the last seen"

    def test_a_package_with_a_published_fix_names_the_version(
        self, client, auth, catalog, run_compaction
    ) -> None:
        _ingest(
            client,
            auth,
            [_advisory("setuptools", "70.3.0", "CVE-2026-1004", "high", "78.1.1")],
        )
        run_compaction()

        package = supply_chain.vulnerable_packages(catalog, REPO).packages[0]

        assert package.fixed_version == "78.1.1"
        assert package.fixable is True

    def test_a_package_with_no_published_fix_says_so(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """Trivy writes `Fixed Version:` with nothing after it, so a naive
        regex captures the next token — which is `Link:`. Reporting that as a
        version people could upgrade to would be worse than reporting nothing.
        """
        _ingest(client, auth, [_advisory("libc6", "2.41-12", "CVE-2026-1005", "medium")])
        run_compaction()

        analysis = supply_chain.vulnerable_packages(catalog, REPO)

        assert analysis.packages[0].fixed_version == ""
        assert analysis.packages[0].fixable is False
        assert analysis.fixable == 0
        assert analysis.unfixable_advisories == 1


class TestOrdering:
    def test_fixable_sorts_above_a_bigger_unfixable_pile(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """Sorting on advisory count alone would bury the one package somebody
        can act on beneath eighteen they cannot."""
        _ingest(
            client,
            auth,
            [_advisory("libc6", "2.41-12", f"CVE-2026-20{n}0", "high") for n in range(5)]
            + [_advisory("setuptools", "70.3.0", "CVE-2026-3001", "medium", "78.1.1")],
        )
        run_compaction()

        order = [p.package_name for p in supply_chain.vulnerable_packages(catalog, REPO).packages]

        assert order[0] == "setuptools", "one fixable beats five that are not"

    def test_known_exploited_outranks_everything(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """KEV is a fact, not a prediction, and it outranks both severity and
        whether a fix exists."""
        _ingest(
            client,
            auth,
            [
                _advisory("setuptools", "70.3.0", "CVE-2026-1004", "high", "78.1.1"),
                _advisory("openssl", "3.0.1", "CVE-2026-1007", "medium"),
            ],
        )
        run_compaction()

        analysis = supply_chain.vulnerable_packages(
            catalog, REPO, kev_cves={"CVE-2026-1007"}
        )

        assert analysis.packages[0].package_name == "openssl"
        assert analysis.packages[0].kev_count == 1
        assert analysis.kev_packages == 1


class TestHonesty:
    def test_directness_is_three_valued(self, client, auth, catalog, run_compaction) -> None:
        """No SBOM here, so nothing knows whether these are direct. `None` is
        the answer; `False` would be a claim the platform cannot make."""
        _ingest(client, auth, [_advisory("libc6", "2.41-12", "CVE-2026-1005", "medium")])
        run_compaction()

        assert supply_chain.vulnerable_packages(catalog, REPO).packages[0].direct is None

    def test_unparseable_raw_json_costs_one_field_not_the_row(
        self, client, auth, catalog, run_compaction
    ) -> None:
        _ingest(
            client,
            auth,
            [
                finding_payload(
                    rule_id="CVE-2026-1008",
                    title="mystery: something",
                    package_name="mystery",
                    package_version="1.0",
                    raw_finding_json={"unexpected": "shape"},
                )
            ],
        )
        run_compaction()

        analysis = supply_chain.vulnerable_packages(catalog, REPO)

        assert analysis.total == 1, "the row survives"
        assert analysis.packages[0].fixed_version == ""

    def test_findings_without_a_package_are_not_invented(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """A SAST finding names a file, not a package. It has no place here."""
        _ingest(client, auth, [finding_payload()], capability="sast")
        run_compaction()

        assert supply_chain.vulnerable_packages(catalog, REPO).packages == []

    def test_an_empty_lake_is_not_an_error(self, catalog) -> None:
        assert supply_chain.vulnerable_packages(catalog, REPO).total == 0
