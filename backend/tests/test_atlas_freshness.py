"""The staleness term stops being permanently zero — spec 22 §2.

`stale_dependencies` has been in the schema, in the trust formula, and
labelled "Unmaintained packages" on the frontend since spec 07 shipped, and
nothing has ever incremented it. Every assertion here is about the difference
between "checked, nothing stale" and "never checked", because conflating them
is how the term stayed invisible for so long.

No network. `staleness` takes its one outbound call as a parameter.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from mykronos import atlas, atlas_counts, atlas_freshness
from mykronos.schemas import EcosystemEvidence

NOW = datetime(2026, 8, 19, tzinfo=UTC)
ANCIENT = (NOW - timedelta(days=1200)).isoformat()
RECENT = (NOW - timedelta(days=30)).isoformat()


def sbom(*names, ecosystem="npm"):
    return {
        "components": [
            {"name": n, "version": "1.0.0", "purl": f"pkg:{ecosystem}/{n}@1.0.0"}
            for n in names
        ]
    }


def npm_registry(dates: dict[str, str]):
    """A fetch that answers for the packages in `dates` and nothing else."""

    def fetch(url: str):
        name = url.rsplit("/", 1)[-1]
        if name not in dates:
            return None
        return {"time": {"created": ANCIENT, "1.0.0": dates[name]}}

    return fetch


class TestStaleness:
    def test_an_abandoned_package_is_stale(self) -> None:
        result = atlas_freshness.staleness(
            sbom("abandoned"), now=NOW, fetch=npm_registry({"abandoned": ANCIENT})
        )

        assert result == {"npm": {"stale": 1, "known": 1}}

    def test_a_maintained_package_is_known_and_not_stale(self) -> None:
        """The distinction the whole term rests on: `known` counts it, `stale`
        does not. Without `known` moving, a fresh tree is indistinguishable
        from an unchecked one."""
        result = atlas_freshness.staleness(
            sbom("alive"), now=NOW, fetch=npm_registry({"alive": RECENT})
        )

        assert result == {"npm": {"stale": 0, "known": 1}}

    def test_a_failed_lookup_counts_in_neither(self) -> None:
        """spec 22 §6. A private package, a delisted one, a timeout — folding
        it in either direction would be a claim about a package nobody
        managed to ask about."""
        result = atlas_freshness.staleness(
            sbom("private-thing"), now=NOW, fetch=lambda url: None
        )

        assert result == {}

    def test_one_failure_does_not_cost_the_others(self) -> None:
        result = atlas_freshness.staleness(
            sbom("gone", "abandoned", "alive"),
            now=NOW,
            fetch=npm_registry({"abandoned": ANCIENT, "alive": RECENT}),
        )

        assert result == {"npm": {"stale": 1, "known": 2}}

    def test_an_unsupported_ecosystem_is_absent(self) -> None:
        """No cheap registry API, so no guess. Absent from the result means
        `maintenance_data_available_for` stays null for it, which spec 07 §8
        already knows how to handle."""
        assert (
            atlas_freshness.staleness(
                sbom("some-crate", ecosystem="cargo"), now=NOW, fetch=lambda url: None
            )
            == {}
        )

    def test_the_threshold_is_the_policy_call_it_looks_like(self) -> None:
        """Plenty of small, correct libraries have not shipped since 2019 and
        are not a supply-chain risk for it. Where the line sits is a
        judgement, so it is configurable."""
        one_year_old = (NOW - timedelta(days=400)).isoformat()

        lenient = atlas_freshness.staleness(
            sbom("mature"),
            now=NOW,
            threshold_days=730,
            fetch=npm_registry({"mature": one_year_old}),
        )
        strict = atlas_freshness.staleness(
            sbom("mature"),
            now=NOW,
            threshold_days=180,
            fetch=npm_registry({"mature": one_year_old}),
        )

        assert lenient["npm"]["stale"] == 0
        assert strict["npm"]["stale"] == 1

    def test_each_package_is_asked_about_once(self) -> None:
        """A monorepo resolves the same package in several workspaces and the
        registry answer is identical. Asking per component would multiply the
        request count by the workspace count for no new information."""
        calls: list[str] = []

        def counting(url: str):
            calls.append(url)
            return {"time": {"1.0.0": RECENT}}

        duplicated = {"components": sbom("lodash")["components"] * 5}
        atlas_freshness.staleness(duplicated, now=NOW, fetch=counting)

        assert len(calls) == 1


class TestParsingRegistryAnswers:
    def test_npm_takes_the_newest_stamp(self) -> None:
        fetch = lambda url: {"time": {"created": ANCIENT, "1.0.0": ANCIENT, "2.0.0": RECENT}}  # noqa: E731

        assert atlas_freshness.npm_last_publish("x", fetch) == datetime.fromisoformat(RECENT)

    def test_npm_ignores_created(self) -> None:
        """A package's birth is not evidence of current care, and it is the
        one stamp a long-abandoned package is guaranteed to have — counting
        it would make nothing ever look stale."""
        fetch = lambda url: {"time": {"created": RECENT, "1.0.0": ANCIENT}}  # noqa: E731

        assert atlas_freshness.npm_last_publish("x", fetch) == datetime.fromisoformat(ANCIENT)

    def test_pypi_takes_the_newest_upload_across_releases(self) -> None:
        """Not the newest version. The two differ whenever a maintainer
        backports to an older line, and a backport is maintenance."""
        fetch = lambda url: {  # noqa: E731
            "releases": {
                "2.0.0": [{"upload_time_iso_8601": ANCIENT}],
                "1.9.1": [{"upload_time_iso_8601": RECENT}],
            }
        }

        assert atlas_freshness.pypi_last_publish("x", fetch) == datetime.fromisoformat(RECENT)

    def test_a_malformed_answer_is_no_answer(self) -> None:
        assert atlas_freshness.npm_last_publish("x", lambda url: {"time": "nonsense"}) is None
        assert atlas_freshness.pypi_last_publish("x", lambda url: {}) is None

    def test_an_unparseable_timestamp_does_not_raise(self) -> None:
        fetch = lambda url: {"time": {"1.0.0": "yesterday-ish"}}  # noqa: E731

        assert atlas_freshness.npm_last_publish("x", fetch) is None


class TestItReachesTheScore:
    REPORT = {
        "results": [
            {
                "packages": [
                    {"package": {"ecosystem": "npm", "name": "abandoned", "version": "1.0.0"}}
                ]
            }
        ]
    }

    def test_the_counts_row_carries_the_denominator(self) -> None:
        rows = atlas_counts.summarise(
            self.REPORT, None, {"npm": {"stale": 1, "known": 4}}
        )

        assert rows[0]["stale_dependencies"] == 1
        assert rows[0]["maintenance_data_available_for"] == 4

    def test_without_the_lookup_the_denominator_stays_null(self) -> None:
        """Null, not `dependency_count`. spec 07 §8 falls back for scoring,
        but the row must record that nobody checked."""
        rows = atlas_counts.summarise(self.REPORT)

        assert rows[0]["maintenance_data_available_for"] is None
        assert rows[0]["stale_dependencies"] == 0

    def test_a_real_staleness_term_appears_in_the_trust_score(self) -> None:
        """The acceptance criterion. Before spec 22 this term could not be
        made to fire from real data at all."""
        result = atlas.score(
            [
                EcosystemEvidence(
                    ecosystem="npm",
                    dependency_count=4,
                    stale_dependencies=1,
                    maintenance_data_available_for=4,
                )
            ]
        )

        terms = {term["key"]: term for term in result.terms}
        assert terms["stale_dependencies"]["count"] == 1
        assert result.trust_score < 100

    def test_a_checked_and_clean_tree_scores_the_same_as_before(self) -> None:
        """Running the lookup must not cost points by itself — only finding
        something does."""
        checked = atlas.score(
            [
                EcosystemEvidence(
                    ecosystem="npm",
                    dependency_count=4,
                    stale_dependencies=0,
                    maintenance_data_available_for=4,
                )
            ]
        )

        assert checked.trust_score == 100
