"""Proposing a risk profile from evidence (B-041).

The rule the whole module turns on: an absent field stays absent. A builder
that guessed "internal, low criticality" whenever it could not tell would be
worse than the empty profile it replaces — an empty profile is visibly empty,
and a guessed one looks like an answer.
"""

from __future__ import annotations

from typing import Any

from mykronos import risk_profile_builder as builder

REPO = "acme/api"


class _Catalog:
    """Answers the three questions `propose` asks, and nothing else."""

    def __init__(self, *, dast: int = 0, network: int = 0, secrets: list[str] | None = None):
        self._dast = dast
        self._network = network
        self._secrets = secrets or []

    def all_files(self, table: str) -> list[str]:
        return ["x"]

    def query(self, sql: str, params: list[Any] | None = None) -> list[tuple[Any, ...]]:
        if "capability = 'dast'" in sql:
            return [(self._dast,)]
        if "'cloud', 'network'" in sql:
            return [(self._network,)]
        if "capability = 'secrets'" in sql:
            return [(rule,) for rule in self._secrets]
        return []


def _field(proposal, name: str):
    return next(p for p in proposal.proposals if p.field == name)


class TestInternetFacing:
    def test_dast_alone_does_not_prove_it(self) -> None:
        """The inference this module exists to refuse.

        "DAST has run 35 times, therefore internet-facing" is exactly the
        confident nonsense that discredits a feature: this platform's own DAST
        lane runs inside CI against an ephemeral compose stack.
        """
        out = builder.propose(_Catalog(dast=35), REPO)

        internet = _field(out, "internet_facing")
        assert internet.value is None
        assert internet.confidence == "unknown"
        assert "ephemeral" in internet.evidence
        assert internet.what_would_settle_it

    def test_a_declared_surface_settles_it(self) -> None:
        """Somebody's statement about the system outranks any inference."""
        out = builder.propose(_Catalog(dast=35), REPO, declared_surfaces=2)

        internet = _field(out, "internet_facing")
        assert internet.value is True
        assert internet.confidence == "observed"

    def test_an_answering_port_settles_it(self) -> None:
        out = builder.propose(_Catalog(network=3), REPO)

        internet = _field(out, "internet_facing")
        assert internet.value is True
        assert internet.confidence == "observed"


class TestTheFieldsItRefuses:
    def test_leaked_credentials_do_not_classify_the_data(self) -> None:
        """A narrow true statement — this codebase handles these credential
        kinds — is not an answer to what data the system stores, and
        conflating them would be a guess wearing a citation."""
        out = builder.propose(_Catalog(secrets=["anthropic-api-key"]), REPO)

        data = _field(out, "data_classification")
        assert data.value is None
        assert "anthropic-api-key" in data.evidence
        assert "says nothing about what data" in data.evidence

    def test_business_criticality_is_never_inferred(self) -> None:
        """Scan volume measures how much is watched, not how much depends on
        it, and no amount of finding data changes that."""
        out = builder.propose(_Catalog(dast=100, network=50), REPO)

        criticality = _field(out, "business_criticality")
        assert criticality.value is None
        assert criticality.what_would_settle_it

    def test_every_unknown_says_what_would_settle_it(self) -> None:
        """The most useful output: the empty form becomes a list of evidence
        to go and get."""
        out = builder.propose(_Catalog(), REPO)

        for proposal in out.proposals:
            if proposal.confidence == "unknown":
                assert proposal.what_would_settle_it, proposal.field


class TestOwner:
    def test_codeowners_is_observed(self) -> None:
        out = builder.propose(
            _Catalog(), REPO, owner="@acme/platform", owner_source="codeowners"
        )

        owner = _field(out, "owner")
        assert owner.value == "@acme/platform"
        assert owner.confidence == "observed"

    def test_the_account_is_only_inferred(self) -> None:
        """Weaker and true, and labelled as such — the same standard the
        ownership ladder itself is held to."""
        out = builder.propose(_Catalog(), REPO, owner="acme", owner_source="repo_owner")

        owner = _field(out, "owner")
        assert owner.confidence == "inferred"
        assert owner.what_would_settle_it
