"""Assets, entry points and trust boundaries (B-029).

`RepoControl`'s own docstring says a threat model is made of four things and
that this platform had one. It has had mitigations since spec 28 §3. These are
the other three, and they follow the same rule: declared, never verified, and
the wording never blurs the two.
"""

from __future__ import annotations

import pytest

from mykronos import surfaces
from mykronos.db import Database


@pytest.fixture
def db(tmp_path):
    database = Database(f"sqlite:///{(tmp_path / 'surfaces.db').as_posix()}")
    database.create_all()
    yield database
    database.close()


REPO = "example-org/payments-api"


class TestDeclaring:
    def test_an_asset_keeps_its_sensitivity(self, db: Database) -> None:
        with db.session() as session:
            surface = surfaces.declare(
                session,
                REPO,
                kind="asset",
                name="Cardholder database",
                exposure="internal",
                sensitivity="financial",
            )
            assert surface.sensitivity == "financial"

    def test_an_entry_point_does_not(self, db: Database) -> None:
        """Sensitivity is a property of something that holds something. Asking
        how sensitive a *way in* is produces an answer nobody can act on, so it
        is dropped rather than stored as a guess."""
        with db.session() as session:
            surface = surfaces.declare(
                session,
                REPO,
                kind="entry_point",
                name="POST /webhooks/stripe",
                exposure="internet",
                sensitivity="financial",
            )
            assert surface.sensitivity == "unknown"

    def test_the_vocabularies_are_enforced(self, db: Database) -> None:
        """A register where one person writes `internet` and another writes
        `public-facing` cannot be queried, and an inventory nobody can query is
        a wiki page with a database bill."""
        with db.session() as session:
            with pytest.raises(surfaces.SurfaceError, match="not an exposure"):
                surfaces.declare(
                    session, REPO, kind="asset", name="x", exposure="public-facing"
                )
            with pytest.raises(surfaces.SurfaceError, match="not part of a threat model"):
                surfaces.declare(session, REPO, kind="mitigation", name="x")

    def test_an_unnamed_surface_is_refused(self, db: Database) -> None:
        with (
            db.session() as session,
            pytest.raises(surfaces.SurfaceError, match="needs a name"),
        ):
            surfaces.declare(session, REPO, kind="asset", name="   ")

    def test_unknown_is_the_default(self, db: Database) -> None:
        """A platform that guessed `internal` would be understating risk by
        default, and the wrong direction to be wrong in is the one that reads
        as reassurance."""
        with db.session() as session:
            surface = surfaces.declare(session, REPO, kind="asset", name="Something")
            assert surface.exposure == "unknown"
            assert surface.sensitivity == "unknown"


class TestReading:
    def _seed(self, session) -> None:
        surfaces.declare(
            session, REPO, kind="asset", name="Cardholder DB", sensitivity="financial"
        )
        surfaces.declare(
            session, REPO, kind="entry_point", name="Public API", exposure="internet"
        )
        surfaces.declare(
            session, REPO, kind="trust_boundary", name="API to payment processor"
        )

    def test_split_by_part(self, db: Database) -> None:
        with db.session() as session:
            self._seed(session)
            summary = surfaces.for_repo(session, REPO)

        assert summary.total == 3
        assert [s.name for s in summary.assets] == ["Cardholder DB"]
        assert [s.name for s in summary.entry_points] == ["Public API"]
        assert summary.internet_facing == 1

    def test_completeness_is_all_three(self, db: Database) -> None:
        """Entry points without assets describe how somebody gets in and never
        what they reach, which is half a sentence."""
        with db.session() as session:
            surfaces.declare(session, REPO, kind="entry_point", name="Public API")
            assert surfaces.for_repo(session, REPO).complete is False
            self._seed(session)
            assert surfaces.for_repo(session, REPO).complete is True

    def test_unknowns_are_counted(self, db: Database) -> None:
        """The number that says how much of this is a model rather than an
        inventory."""
        with db.session() as session:
            self._seed(session)
            summary = surfaces.for_repo(session, REPO)

        # The asset has unknown exposure, the trust boundary has unknown
        # exposure, and nothing has an unknown sensitivity except the asset's
        # is set — so: two unknown exposures.
        assert summary.unknowns == 2

    def test_unknown_exposure_sorts_with_the_risky_end(self, db: Database) -> None:
        """Reading order puts `unknown` last, where it renders as the mildest
        thing on the page. It is not mild: an unclassified entry point is an
        open question about whether the internet can reach it."""
        with db.session() as session:
            surfaces.declare(session, REPO, kind="entry_point", name="B local", exposure="local")
            surfaces.declare(session, REPO, kind="entry_point", name="A unknown")
            surfaces.declare(
                session, REPO, kind="entry_point", name="C internet", exposure="internet"
            )
            order = [s.name for s in surfaces.for_repo(session, REPO).entry_points]

        assert order == ["C internet", "A unknown", "B local"]

    def test_another_repository_is_not_visible(self, db: Database) -> None:
        with db.session() as session:
            self._seed(session)
            assert surfaces.for_repo(session, "example-org/other").total == 0


class TestWithdrawing:
    def test_a_declaration_can_be_corrected(self, db: Database) -> None:
        with db.session() as session:
            surface = surfaces.declare(session, REPO, kind="asset", name="Wrong")
            assert surfaces.remove(session, REPO, surface.id) is True
            assert surfaces.for_repo(session, REPO).total == 0

    def test_an_id_from_another_repository_cannot_reach_across(self, db: Database) -> None:
        with db.session() as session:
            surface = surfaces.declare(session, REPO, kind="asset", name="Theirs")
            assert surfaces.remove(session, "example-org/other", surface.id) is False
            assert surfaces.for_repo(session, REPO).total == 1
