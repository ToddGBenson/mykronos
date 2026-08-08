"""The Knowledge Store — spec 11 §3, §5, §6, §8.

The confidence model is the part worth testing hardest: it is the only place
in the platform where the passage of time changes an answer, and every one of
its behaviours is a judgement that could reasonably have gone the other way.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from mykronos.knowledge.store import (
    CONFIDENCE_FLOOR,
    KnowledgeStore,
    entry_id,
)
from mykronos.schemas import utcnow

REPO = "example-org/payments-api"
LATER = utcnow()


@pytest.fixture
def store(tmp_path) -> KnowledgeStore:
    return KnowledgeStore(tmp_path / "knowledge", tier="personal")


def dismissal(store: KnowledgeStore, rule="CKV_AWS_123", reason="generated code", **kw):
    return store.add_entry(
        source_type="finding_dismissal",
        subject=rule,
        source_ref=kw.pop("finding_id", "f-1"),
        text=f"{rule} in {REPO} was dismissed as a false positive — {reason}",
        repo_full_name=REPO,
        reason=reason,
        **kw,
    )


class TestIdentity:
    def test_the_same_pattern_is_one_entry(self, store) -> None:
        """A store that logged every click would have plenty of rows and no
        knowledge in it."""
        dismissal(store, finding_id="f-1")
        dismissal(store, finding_id="f-2")

        assert len(store.list_entries()) == 1

    def test_reconfirmation_counts(self, store) -> None:
        dismissal(store)
        result = dismissal(store)

        assert result.reconfirmed is True
        assert result.entry.observations == 2

    def test_a_different_rule_is_a_different_entry(self, store) -> None:
        dismissal(store, rule="CKV_AWS_123")
        dismissal(store, rule="CKV_AWS_456")

        assert len(store.list_entries()) == 2

    def test_the_same_rule_in_another_repo_is_a_different_entry(self, store) -> None:
        """spec 11 §11: entries stay repo-scoped, so one team's conclusion
        cannot silently become another's."""
        assert entry_id("personal", "a/b", "finding_dismissal", "R1") != entry_id(
            "personal", "a/c", "finding_dismissal", "R1"
        )

    def test_the_latest_source_is_kept(self, store) -> None:
        dismissal(store, finding_id="f-1")
        result = dismissal(store, finding_id="f-2")

        assert result.entry.source_ref == "f-2"


class TestReasons:
    def test_a_reason_is_kept(self, store) -> None:
        result = dismissal(store, reason="the whole directory is generated")

        assert result.entry.reasons == ["the whole directory is generated"]

    def test_a_bare_dismissal_starts_lower(self, store) -> None:
        """Recorded, and deliberately made useless: spec 11 §4."""
        with_reason = dismissal(store, rule="A", reason="vendored")
        without = dismissal(store, rule="B", reason="")

        assert without.entry.confidence < with_reason.entry.confidence
        assert without.entry.has_reason is False

    def test_a_bare_reconfirmation_does_not_raise_confidence(self, store) -> None:
        """It is evidence the pattern recurs and no evidence at all about why."""
        first = dismissal(store, reason="vendored")
        second = dismissal(store, reason="")

        assert second.entry.confidence == pytest.approx(first.entry.confidence)
        assert second.entry.observations == 2

    def test_contradictory_reasons_are_both_kept(self, store) -> None:
        """spec 11 §11: the system does not auto-resolve contradictions, and a
        single overwritten string would hide that there is one."""
        dismissal(store, reason="this is generated code")
        result = dismissal(store, reason="actually this one is a real bug")

        assert len(result.entry.reasons) == 2
        assert "real bug" in result.entry.reasons[0]

    def test_the_same_reason_twice_is_not_duplicated(self, store) -> None:
        dismissal(store, reason="vendored")
        result = dismissal(store, reason="vendored")

        assert result.entry.reasons == ["vendored"]


class TestConfidence:
    def test_it_rises_with_reasoned_reconfirmation(self, store) -> None:
        scores = []
        for _ in range(4):
            scores.append(dismissal(store).entry.confidence)

        assert scores == sorted(scores), "confidence must be monotonic"

    def test_it_never_reaches_certainty_from_clicks(self, store) -> None:
        for _ in range(50):
            result = dismissal(store)

        assert result.entry.confidence < 1.0

    def test_it_decays_over_time(self, store) -> None:
        entry = dismissal(store).entry
        now = entry.last_confirmed_at

        assert store.decayed_confidence(entry, now) == pytest.approx(entry.confidence)
        assert store.decayed_confidence(
            entry, now + timedelta(days=180)
        ) == pytest.approx(entry.confidence / 2, rel=0.01)

    def test_decay_is_reproducible(self, store) -> None:
        """spec 11 §10 makes this an acceptance criterion — it is what lets a
        retro report be re-derived rather than trusted."""
        entry = dismissal(store).entry
        stamp = entry.last_confirmed_at + timedelta(days=97)

        assert store.decayed_confidence(entry, stamp) == store.decayed_confidence(
            entry, stamp
        )

    def test_it_has_a_floor(self, store) -> None:
        entry = dismissal(store).entry

        decayed = store.decayed_confidence(
            entry, entry.last_confirmed_at + timedelta(days=36_500)
        )

        assert decayed == CONFIDENCE_FLOOR

    def test_reconfirmation_boosts_from_the_decayed_value(self, store) -> None:
        """Rebuilding from the stored figure would let an entry nobody has
        reconfirmed in two years jump straight back to where it was, which
        would make decay decorative."""
        first = dismissal(store).entry
        stale = first.last_confirmed_at + timedelta(days=720)

        revived = store.add_entry(
            source_type="finding_dismissal",
            subject="CKV_AWS_123",
            source_ref="f-9",
            text="again",
            repo_full_name=REPO,
            reason="still generated",
            now=stale,
        ).entry

        assert revived.confidence < first.confidence
        assert revived.confidence > store.decayed_confidence(first, stale)

    def test_decayed_entries_leave_active_but_stay_on_disk(self, store) -> None:
        """"We knew this and stopped believing it" is a different fact from
        "we never knew it", and only one of them is recoverable."""
        entry = dismissal(store).entry
        much_later = entry.last_confirmed_at + timedelta(days=3_650)

        assert store.active_entries(as_of=much_later) == []
        assert len(store.list_entries()) == 1


class TestRetrieval:
    def test_it_finds_a_similar_entry(self, store) -> None:
        store.add_entry(
            source_type="retro_note",
            subject="terraform",
            source_ref="r-1",
            text="Checkov flags the terraform module registry mirror constantly",
            repo_full_name=REPO,
            reason="noted in retro",
        )

        hits = store.retrieve_similar("terraform module registry")

        assert hits
        assert hits[0].mode == "lexical"

    def test_it_reports_the_mode_that_found_them(self, store) -> None:
        """So a caller is never told "nothing similar" when what happened is
        "nothing lexically similar" (spec 11 §8)."""
        dismissal(store, reason="vendored dependency directory")

        hits = store.retrieve_similar("vendored dependency")

        assert all(hit.mode == "lexical" for hit in hits)

    def test_an_empty_store_returns_nothing_rather_than_raising(self, store) -> None:
        assert store.retrieve_similar("anything") == []

    def test_a_corrupt_store_degrades_gracefully(self, store) -> None:
        """spec 11 §10. A triage step that dies because a JSON file is corrupt
        is a worse outcome than one that proceeds without the context."""
        dismissal(store)
        store.path.write_text("{not json at all\n", encoding="utf-8")

        assert store.retrieve_similar("anything") == []
        assert store.list_entries() == []

    def test_one_bad_line_does_not_lose_the_others(self, store) -> None:
        dismissal(store, rule="A")
        dismissal(store, rule="B")
        with store.path.open("a", encoding="utf-8") as handle:
            handle.write("{ broken\n")

        assert len(store.list_entries()) == 2

    def test_results_are_deterministic(self, store) -> None:
        for rule in ("A", "B", "C"):
            dismissal(store, rule=rule, reason="generated code directory")

        assert [h.entry.entry_id for h in store.retrieve_similar("generated code")] == [
            h.entry.entry_id for h in store.retrieve_similar("generated code")
        ]

    def test_another_repos_personal_entry_is_not_retrieved(self, store) -> None:
        dismissal(store, reason="only true here")

        assert store.retrieve_similar("only true here", repo_full_name="other/repo") == []
        assert store.retrieve_similar("only true here", repo_full_name=REPO)

    def test_a_semantic_backend_is_used_when_configured(self, tmp_path) -> None:
        def embed(text: str) -> list[float]:
            return [float(text.count(ch)) for ch in "abcdefg"]

        store = KnowledgeStore(tmp_path / "k", tier="personal", embed_fn=embed)
        dismissal(store, reason="a badged cafe")
        store.rebuild_index()

        hits = store.retrieve_similar("badged cafe")

        assert hits and hits[0].mode == "semantic"

    def test_a_broken_embedder_falls_back_to_lexical(self, tmp_path) -> None:
        """The gateway being down should cost precision, not the feature."""

        def explode(text: str) -> list[float]:
            raise RuntimeError("gateway down")

        store = KnowledgeStore(tmp_path / "k", tier="personal", embed_fn=explode)
        dismissal(store, reason="vendored dependency directory")

        hits = store.retrieve_similar("vendored dependency")

        assert hits and hits[0].mode == "lexical"

    def test_rebuild_index_is_a_no_op_without_an_embedder(self, store) -> None:
        dismissal(store)

        assert store.rebuild_index() == 0


class TestPurge:
    def test_entries_for_offboarded_repos_are_removed(self, store) -> None:
        """An entry about a repo we no longer hold data for cannot be
        reconfirmed or audited, and would outlive the deletion request that
        removed everything else (spec 02 §6)."""
        dismissal(store)

        result = store.purge_expired(known_repos={"someone/else"})

        assert result.count == 1
        assert store.list_entries() == []

    def test_known_repos_are_kept(self, store) -> None:
        dismissal(store)

        assert store.purge_expired(known_repos={REPO}).count == 0

    def test_org_entries_survive(self, tmp_path) -> None:
        """They are not about a repository, so no repository going away can
        expire them."""
        org = KnowledgeStore(tmp_path / "k", tier="org")
        org.add_entry(
            source_type="retro_note",
            subject="policy",
            source_ref="r-1",
            text="CKV_AWS_123 is noise everywhere we have looked",
            reason="four teams agreed",
        )

        assert org.purge_expired(known_repos=set()).count == 0

    def test_decay_never_deletes(self, store) -> None:
        entry = dismissal(store).entry
        ancient = entry.last_confirmed_at + timedelta(days=10_000)

        store.purge_expired(known_repos={REPO})

        assert len(store.list_entries()) == 1
        assert store.decayed_confidence(entry, ancient) == CONFIDENCE_FLOOR


class TestDurability:
    def test_entries_survive_a_reopen(self, tmp_path) -> None:
        first = KnowledgeStore(tmp_path / "k", tier="personal")
        dismissal(first, reason="vendored")

        second = KnowledgeStore(tmp_path / "k", tier="personal")

        assert len(second.list_entries()) == 1
        assert second.list_entries()[0].reasons == ["vendored"]

    def test_tiers_are_separate_files(self, tmp_path) -> None:
        personal = KnowledgeStore(tmp_path / "k", tier="personal")
        team = KnowledgeStore(tmp_path / "k", tier="team")
        dismissal(personal)

        assert team.list_entries() == []

    def test_an_unknown_tier_is_refused(self, tmp_path) -> None:
        with pytest.raises(ValueError, match="Unknown tier"):
            KnowledgeStore(tmp_path / "k", tier="global")

    def test_an_unknown_source_type_is_refused(self, store) -> None:
        with pytest.raises(ValueError, match="Unknown source_type"):
            store.add_entry(
                source_type="vibes", subject="x", source_ref="y", text="z"
            )

    def test_sensitivity_defaults_to_restricted(self, store) -> None:
        """A dismissal reason is free text about somebody's own codebase.
        Assuming it is safe to promote across an organisation is the wrong
        default, and the cost of being wrong is asymmetric."""
        assert dismissal(store).entry.sensitivity == "restricted"
