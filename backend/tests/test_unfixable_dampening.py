"""Findings nobody can fix count for less — D-077.

TheHub carried sixteen critical Perl CVEs with `fixed_version: null`. Debian
had shipped no patch, so no rebuild, bump or fixer closed any of them — and
they contributed 177 points, pinning the repository at 100/100. The gate read
the same whether the team fixed everything they could or nothing at all, which
is the state in which a gate has stopped carrying information.

The dangerous half is the guard, not the discount. A SAST finding has no
`fixed_version` and never will: absence there means the field does not apply,
not that upstream has shipped nothing. Reading it the other way would quieten
every injection finding in the fleet, so most of this file is about that.
"""

from __future__ import annotations

import pytest

from mykronos.oracle.engine import OracleEngine
from mykronos.oracle.policy import load_policy
from tests.conftest import (
    REPO,
    dependency_finding,
    finding_payload,
    post_findings,
    post_scan,
)
from tests.test_onboarding import onboard


@pytest.fixture
def engine(client, catalog):
    return OracleEngine(catalog, client.app.state.oracle_policy)


def cve(rule_id, package, *, fixed, severity="critical"):
    payload = dependency_finding(rule_id=rule_id, package_name=package, severity=severity)
    payload["package_version"] = "1.0.0"
    payload["raw_finding_json"] = {"fixed_version": fixed} if fixed else {}
    return payload


def seed(client, admin_auth, auth, run_compaction, findings, run="unfix"):
    onboard(client, admin_auth)
    post_scan(client, auth, scan_run_id=run)
    response = post_findings(client, auth, findings, scan_run_id=run)
    assert response.status_code < 300, response.text
    run_compaction()


def band(decision, severity="critical"):
    return next(
        (t for t in decision.inputs_snapshot["terms"] if t["key"] == f"findings.{severity}"),
        None,
    )


class TestTheGuardThatMatters:
    def test_a_sast_finding_is_never_dampened(
        self, client, admin_auth, auth, run_compaction, engine
    ) -> None:
        """The bug this could most easily have been. A SQL-injection finding
        carries no `fixed_version` because the field does not apply — it is
        entirely fixable, by the person reading it."""
        seed(
            client,
            admin_auth,
            auth,
            run_compaction,
            [finding_payload(rule_id="CWE-89", severity="critical")],
        )

        term = band(engine.evaluate(REPO))

        assert term["inputs"]["no_upstream_fix"] == 0

    def test_a_finding_with_a_fix_available_is_not_dampened(
        self, client, admin_auth, auth, run_compaction, engine
    ) -> None:
        """Somebody can act on this today. It should score in full."""
        seed(
            client,
            admin_auth,
            auth,
            run_compaction,
            [cve("CVE-2026-1", "urllib3", fixed="2.2.2")],
        )

        term = band(engine.evaluate(REPO))

        assert term["inputs"]["no_upstream_fix"] == 0


class TestTheDiscount:
    def test_an_unfixable_finding_is_counted_as_such(
        self, client, admin_auth, auth, run_compaction, engine
    ) -> None:
        seed(
            client,
            admin_auth,
            auth,
            run_compaction,
            [cve("CVE-2026-13221", "perl", fixed=None)],
        )

        term = band(engine.evaluate(REPO))

        assert term["inputs"]["no_upstream_fix"] == 1

    def test_it_scores_less_than_a_fixable_one(
        self, client, admin_auth, auth, run_compaction, catalog, engine
    ) -> None:
        seed(
            client,
            admin_auth,
            auth,
            run_compaction,
            [cve("CVE-2026-1", "urllib3", fixed="2.2.2")],
        )
        fixable = band(engine.evaluate(REPO))["contribution"]

        # Same finding, same severity, no upstream fix.
        post_scan(client, auth, scan_run_id="second")
        post_findings(
            client, auth, [cve("CVE-2026-1", "urllib3", fixed=None)], scan_run_id="second"
        )
        run_compaction()

        assert band(engine.evaluate(REPO))["contribution"] < fixable

    def test_it_still_scores_something(
        self, client, admin_auth, auth, run_compaction, engine
    ) -> None:
        """Dampened, never excluded. An unpatched critical in production is
        real risk and pretending otherwise would be worse than scoring it in
        full."""
        seed(
            client,
            admin_auth,
            auth,
            run_compaction,
            [cve("CVE-2026-13221", "perl", fixed=None)],
        )

        assert band(engine.evaluate(REPO))["contribution"] > 0

    def test_the_detail_says_why_the_number_is_lower(
        self, client, admin_auth, auth, run_compaction, engine
    ) -> None:
        """spec 01 §6: an admin has to be able to reproduce the arithmetic.
        A discount with no stated reason is the kind of number people stop
        believing."""
        seed(
            client,
            admin_auth,
            auth,
            run_compaction,
            [cve("CVE-2026-13221", "perl", fixed=None)],
        )

        term = band(engine.evaluate(REPO))

        assert "no upstream fix" in term["detail"]
        assert "no upstream fix" in term["label"]


class TestItCannotDiscountTwice:
    def test_the_categories_cap_each_other(
        self, client, admin_auth, auth, run_compaction, engine
    ) -> None:
        """A finding that is unfixable *and* has a fix in flight is a
        contradiction, but the arithmetic must not produce a negative
        effective count if the data ever says both."""
        seed(
            client,
            admin_auth,
            auth,
            run_compaction,
            [cve(f"CVE-2026-{i}", f"pkg{i}", fixed=None) for i in range(3)],
        )

        term = band(engine.evaluate(REPO))

        assert term["inputs"]["effective_count"] >= 0
        assert term["inputs"]["no_upstream_fix"] <= term["inputs"]["count"]


class TestThePolicy:
    def test_the_shipped_policy_dampens(self) -> None:
        from mykronos.config import get_settings

        policy = load_policy(get_settings().oracle_policy_path)

        assert 0 < policy.unfixable.factor < 1

    def test_a_policy_without_the_block_still_loads_and_changes_nothing(
        self, tmp_path
    ) -> None:
        """A deployment on the older file keeps its scores exactly."""
        import yaml

        from mykronos.config import get_settings

        document = yaml.safe_load(
            get_settings().oracle_policy_path.read_text(encoding="utf-8")
        )
        del document["modifiers"]["unfixable_dampening"]
        path = tmp_path / "old.yaml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")

        assert load_policy(path).unfixable.factor == 0

    def test_a_zero_factor_leaves_the_label_alone(
        self, client, admin_auth, auth, run_compaction, catalog
    ) -> None:
        """With the discount off, the term must read exactly as it did before
        this existed — no dangling "0 with no upstream fix"."""
        import dataclasses

        from mykronos.config import get_settings

        policy = load_policy(get_settings().oracle_policy_path)
        off = dataclasses.replace(
            policy, unfixable=dataclasses.replace(policy.unfixable, factor=0.0)
        )
        seed(
            client,
            admin_auth,
            auth,
            run_compaction,
            [cve("CVE-2026-13221", "perl", fixed=None)],
        )

        term = band(OracleEngine(catalog, off).evaluate(REPO))

        assert "no upstream fix" not in term["label"]
