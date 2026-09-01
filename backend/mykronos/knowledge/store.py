"""The Knowledge Store — what humans concluded, kept (spec 11).

Everything else in Mykronos records what a *tool* observed. This records what a
*person* decided about it: that a rule is noise in this repo, that a `no_go`
was acceptable this once, that an auto-fix was wrong. Those are the only inputs
the platform has that it cannot generate for itself, and spec 11's premise is
that they are worth more than any additional scanner.

Three properties the design serves:

**A learning is a pattern, not an event.** The same rule dismissed on a second
finding is the same learning, seen again — so entries are keyed by what recurs
and reconfirmation *updates* rather than appends. A store that logged every
click would have plenty of rows and no knowledge in it.

**Reasons are the point.** A bare dismissal is recorded and deliberately made
useless: it cannot raise confidence and it cannot support dampening. Spec 11 §4
puts it well — reasons are what make learnings actionable rather than
statistics.

**Nothing here is authoritative on its own.** Confidence decays, promotion
needs a human, and the store never edits the policy. It proposes.

Physically colocated with the data lake, logically separate (spec 11 §8): this
is text somebody wrote, with retention and promotion rules that have nothing to
do with Parquet compaction.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

TIERS = ("personal", "team", "org")
SOURCE_TYPES = (
    "finding_dismissal",
    "decision_override",
    "remediation_outcome",
    "retro_note",
    #: A person disagreed with the classifier (B-020). Deliberately its own
    #: type rather than a dismissal: it teaches about the classifier, not the
    #: rule, and dampening reads `finding_dismissal` only. Recording a "this
    #: is real" as a dismissal would quieten the rule that correctly fired.
    "classification_rejected",
)
SENSITIVITIES = ("public", "restricted")

#: spec 11 §5. Below this an entry is out of active retrieval and ineligible
#: for promotion, but it is never deleted for it.
CONFIDENCE_FLOOR = 0.05

#: How many distinct human reasons to keep per entry. Two people dismissing the
#: same rule for different stated reasons is the spec 11 §11 contradiction
#: case; collapsing them to one string would hide it.
MAX_REASONS = 20


def entry_id(tier: str, repo_full_name: str | None, source_type: str, subject: str) -> str:
    """Derived, not random (spec 11 §3).

    Reconfirmation is an update — the same pattern seen again, resetting decay.
    A random id would append a second row instead and the confidence model
    would silently never work.
    """
    material = "\x00".join([tier, repo_full_name or "", source_type, subject])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass
class KnowledgeEntry:
    """spec 11 §3."""

    entry_id: str
    tier: str
    repo_full_name: str | None
    source_type: str
    subject: str
    source_ref: str
    text: str
    confidence: float
    sensitivity: str
    created_at: datetime
    last_confirmed_at: datetime
    observations: int = 1
    reasons: list[str] = field(default_factory=list)

    @property
    def has_reason(self) -> bool:
        """Whether a human ever said why.

        The gate on everything that matters: confidence growth, promotion
        eligibility, and Oracle dampening all require this.
        """
        return bool(self.reasons)

    def to_json(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "tier": self.tier,
            "repo_full_name": self.repo_full_name,
            "source_type": self.source_type,
            "subject": self.subject,
            "source_ref": self.source_ref,
            "text": self.text,
            "confidence": round(self.confidence, 4),
            "sensitivity": self.sensitivity,
            "created_at": self.created_at.isoformat(),
            "last_confirmed_at": self.last_confirmed_at.isoformat(),
            "observations": self.observations,
            "reasons": self.reasons,
        }

    @classmethod
    def from_json(cls, row: dict[str, Any]) -> KnowledgeEntry:
        return cls(
            entry_id=str(row["entry_id"]),
            tier=str(row["tier"]),
            repo_full_name=row.get("repo_full_name"),
            source_type=str(row["source_type"]),
            subject=str(row.get("subject", "")),
            source_ref=str(row.get("source_ref", "")),
            text=str(row.get("text", "")),
            confidence=float(row.get("confidence", 0.5)),
            sensitivity=str(row.get("sensitivity", "restricted")),
            created_at=datetime.fromisoformat(row["created_at"]),
            last_confirmed_at=datetime.fromisoformat(row["last_confirmed_at"]),
            observations=int(row.get("observations", 1)),
            reasons=list(row.get("reasons") or []),
        )


@dataclass
class AddResult:
    entry: KnowledgeEntry
    created: bool
    reconfirmed: bool


@dataclass
class Retrieved:
    entry: KnowledgeEntry
    score: float
    #: `lexical` or `semantic`. Carried so a caller can tell a genuinely empty
    #: result from the limits of the configured backend (spec 11 §8).
    mode: str


@dataclass
class PurgeResult:
    removed: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.removed)


# --------------------------------------------------------------------------
# Retrieval
# --------------------------------------------------------------------------

_WORD = re.compile(r"[a-z0-9_]+")

#: Words that appear in nearly every entry because of how the text is
#: generated. Left in the text (it reads properly) but ignored when scoring,
#: or every entry would look similar to every other.
_STOPWORDS = frozenset([
    "a", "an", "and", "as", "at", "be", "by", "for", "from", "in", "into", "is", "it", "of",
    "on", "or", "that", "the", "this", "to", "was", "with", "rule", "repo", "reason",
    "dismissed", "false", "positive", "finding"
])


def _tokens(text: str) -> list[str]:
    return [word for word in _WORD.findall(text.lower()) if word not in _STOPWORDS]


def lexical_score(query_tokens: list[str], entry_tokens: list[str]) -> float:
    """Overlap coefficient over content words, in [0, 1].

    Not TF-IDF, and deliberately not: the corpus here is hundreds of short,
    highly templated sentences, where inverse document frequency mostly
    measures how the text was generated rather than what it says. Overlap on
    content words after stripping the template vocabulary is both more honest
    about what it does and easier to explain when somebody asks why an entry
    was retrieved.
    """
    if not query_tokens or not entry_tokens:
        return 0.0
    query, entry = set(query_tokens), set(entry_tokens)
    return len(query & entry) / min(len(query), len(entry))


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b))
    return dot / norm if norm else 0.0


# --------------------------------------------------------------------------
# The store
# --------------------------------------------------------------------------


class KnowledgeStore:
    """One JSONL file per tier, plus a sidecar vector index (spec 11 §8, §9).

    Read-modify-write on a whole file rather than append-only, because
    reconfirmation edits rows. At the scale this operates on — hundreds to low
    thousands of entries per tier, written on human actions rather than by
    scanners — a full rewrite costs microseconds and buys the ability to update
    an entry in place, which is the entire confidence model. If a deployment
    ever outgrows that, the fix is a real database, not an append log with
    tombstones.
    """

    def __init__(
        self,
        store_dir: Path,
        tier: str = "personal",
        embed_fn: Callable[[str], list[float]] | None = None,
        *,
        half_life_days: int = 180,
    ) -> None:
        if tier not in TIERS:
            raise ValueError(f"Unknown tier {tier!r}. Expected one of {TIERS}.")
        self.store_dir = Path(store_dir)
        self.tier = tier
        self.embed_fn = embed_fn
        self.half_life_days = half_life_days

    @property
    def path(self) -> Path:
        return self.store_dir / f"{self.tier}.jsonl"

    @property
    def index_path(self) -> Path:
        return self.store_dir / f"{self.tier}.index.json"

    # -- reading --------------------------------------------------------

    def list_entries(self, filter_tags: dict[str, Any] | None = None) -> list[KnowledgeEntry]:
        """Every entry, optionally filtered by exact field match.

        A malformed line is skipped with a warning rather than raising. This
        file is the record of what people concluded; one corrupt row must not
        make the other four hundred unreadable.
        """
        if not self.path.exists():
            return []

        entries: list[KnowledgeEntry] = []
        with self.path.open(encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(KnowledgeEntry.from_json(json.loads(line)))
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    logger.warning(
                        "Skipping unreadable knowledge entry at %s:%s: %s",
                        self.path,
                        number,
                        exc,
                    )

        if filter_tags:
            entries = [
                entry
                for entry in entries
                if all(getattr(entry, key, None) == value for key, value in filter_tags.items())
            ]
        return entries

    def find(self, entry_id_value: str) -> KnowledgeEntry | None:
        return next(
            (e for e in self.list_entries() if e.entry_id == entry_id_value), None
        )

    # -- writing --------------------------------------------------------

    def add_entry(
        self,
        *,
        source_type: str,
        subject: str,
        source_ref: str,
        text: str,
        repo_full_name: str | None = None,
        reason: str = "",
        sensitivity: str = "restricted",
        confidence: float = 0.5,
        now: datetime | None = None,
    ) -> AddResult:
        """Record a learning, or reconfirm one already held (spec 11 §4, §5).

        `sensitivity` defaults to `restricted` on purpose. A dismissal reason
        is free text somebody typed about their own codebase; assuming it is
        safe to promote across an organisation is the wrong default, and the
        cost of being wrong is asymmetric.
        """
        if source_type not in SOURCE_TYPES:
            raise ValueError(f"Unknown source_type {source_type!r}.")
        if sensitivity not in SENSITIVITIES:
            raise ValueError(f"Unknown sensitivity {sensitivity!r}.")

        stamp = now or utcnow()
        key = entry_id(self.tier, repo_full_name, source_type, subject)
        entries = self.list_entries()
        existing = next((e for e in entries if e.entry_id == key), None)

        if existing is None:
            entry = KnowledgeEntry(
                entry_id=key,
                tier=self.tier,
                repo_full_name=repo_full_name,
                source_type=source_type,
                subject=subject,
                source_ref=source_ref,
                text=text,
                # A reasoned first observation starts above an unreasoned one,
                # but neither starts high: one person's opinion once is a
                # hypothesis, not a finding.
                confidence=confidence if reason.strip() else min(confidence, 0.25),
                sensitivity=sensitivity,
                created_at=stamp,
                last_confirmed_at=stamp,
                observations=1,
                reasons=[reason.strip()] if reason.strip() else [],
            )
            entries.append(entry)
            self._write(entries)
            return AddResult(entry=entry, created=True, reconfirmed=False)

        updated = self._reconfirm(
            existing, source_ref=source_ref, text=text, reason=reason, now=stamp
        )
        entries = [updated if e.entry_id == key else e for e in entries]
        self._write(entries)
        return AddResult(entry=updated, created=False, reconfirmed=True)

    def _reconfirm(
        self,
        entry: KnowledgeEntry,
        *,
        source_ref: str,
        text: str,
        reason: str,
        now: datetime,
    ) -> KnowledgeEntry:
        """The same pattern, handled the same way again (spec 11 §5).

        Confidence is boosted from its *decayed* value, not its stored one.
        Rebuilding from the stored figure would let an entry nobody has
        reconfirmed in two years jump straight back to where it was, which
        would make decay decorative.

        An unreasoned reconfirmation resets the decay clock but does not raise
        confidence. It is evidence the pattern recurs and no evidence at all
        about why.
        """
        current = self.decayed_confidence(entry, now)
        cleaned = reason.strip()

        if cleaned:
            # Diminishing returns: the third dismissal tells you much less than
            # the second, and nothing should reach certainty from clicks alone.
            boosted = min(1.0, current + (1.0 - current) * 0.4)
            reasons = [cleaned, *[r for r in entry.reasons if r != cleaned]][:MAX_REASONS]
        else:
            boosted = current
            reasons = entry.reasons

        return replace(
            entry,
            source_ref=source_ref,
            text=text,
            confidence=boosted,
            last_confirmed_at=now,
            observations=entry.observations + 1,
            reasons=reasons,
        )

    def _write(self, entries: Iterable[KnowledgeEntry]) -> None:
        """Rewrite the file atomically.

        Half a knowledge store is worse than none: the missing half is
        invisible, and the confidence figures on what survives would be
        computed against a corpus that no longer exists.
        """
        self.store_dir.mkdir(parents=True, exist_ok=True)
        pending = self.path.with_suffix(".jsonl.tmp")
        with pending.open("w", encoding="utf-8", newline="\n") as handle:
            for entry in entries:
                handle.write(json.dumps(entry.to_json(), ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(pending, self.path)

    # -- confidence -----------------------------------------------------

    def decayed_confidence(self, entry: KnowledgeEntry, as_of: datetime | None = None) -> float:
        """Exponential decay from `last_confirmed_at` (spec 11 §5).

        A pure function of stored fields and the timestamp you pass, so any
        past value is reproducible — spec 11 §10 makes that an acceptance
        criterion, and it is what lets a retro report be re-derived rather
        than trusted.
        """
        stamp = as_of or utcnow()
        elapsed = (stamp - entry.last_confirmed_at).total_seconds() / 86_400
        if elapsed <= 0:
            return min(1.0, entry.confidence)
        decayed = float(entry.confidence) * float(0.5 ** (elapsed / self.half_life_days))
        return max(CONFIDENCE_FLOOR, min(1.0, decayed))

    def active_entries(
        self, *, min_confidence: float = 0.2, as_of: datetime | None = None
    ) -> list[tuple[KnowledgeEntry, float]]:
        """Entries still believed, with their current confidence.

        Decayed entries are excluded here and kept on disk (spec 11 §5): "we
        knew this and stopped believing it" is a different fact from "we never
        knew it", and only one of them is recoverable.
        """
        stamp = as_of or utcnow()
        scored = [(e, self.decayed_confidence(e, stamp)) for e in self.list_entries()]
        return [pair for pair in scored if pair[1] >= min_confidence]

    # -- retrieval ------------------------------------------------------

    def retrieve_similar(
        self, query: str, k: int = 5, *, repo_full_name: str | None = None
    ) -> list[Retrieved]:
        """Top-k similar entries. Returns `[]` rather than raising, always.

        spec 11 §6 makes graceful degradation a requirement rather than a
        courtesy: a retrieval failure must never block the process that asked.
        A triage step that dies because a JSON file is corrupt is a worse
        outcome than one that proceeds without the extra context.
        """
        try:
            entries = self.list_entries()
            if repo_full_name is not None:
                entries = [
                    e
                    for e in entries
                    # Org and team entries apply everywhere; personal ones only
                    # to their own repo.
                    if e.repo_full_name in (None, repo_full_name)
                ]
            if not entries:
                return []

            if self.embed_fn is not None:
                results = self._semantic(query, entries)
                if results:
                    return results[:k]

            query_tokens = _tokens(query)
            scored = [
                Retrieved(
                    entry=entry,
                    score=lexical_score(query_tokens, _tokens(entry.text)),
                    mode="lexical",
                )
                for entry in entries
            ]
            hits = [hit for hit in scored if hit.score > 0]
            # Tie-break on entry_id so the same query twice returns the same
            # order — a retrieval that reshuffles is impossible to debug.
            hits.sort(key=lambda hit: (-hit.score, hit.entry.entry_id))
            return hits[:k]
        except Exception as exc:  # noqa: BLE001 — see docstring
            logger.warning("Knowledge retrieval failed, continuing without it: %s", exc)
            return []

    def _semantic(self, query: str, entries: list[KnowledgeEntry]) -> list[Retrieved]:
        if self.embed_fn is None:
            return []
        try:
            vectors = self._load_index()
            query_vector = self.embed_fn(query)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Embedding backend unavailable, falling back to lexical: %s", exc)
            return []

        hits = []
        for entry in entries:
            vector = vectors.get(entry.entry_id)
            if not vector:
                continue
            hits.append(
                Retrieved(entry=entry, score=cosine(query_vector, vector), mode="semantic")
            )
        hits = [hit for hit in hits if hit.score > 0]
        hits.sort(key=lambda hit: (-hit.score, hit.entry.entry_id))
        return hits

    def _load_index(self) -> dict[str, list[float]]:
        if not self.index_path.exists():
            return {}
        with self.index_path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        return {str(k): list(v) for k, v in data.items()}

    def rebuild_index(self) -> int:
        """Recompute embeddings for every entry (spec 11 §9).

        A no-op returning 0 when no `embed_fn` is configured, rather than an
        error: the default retriever is lexical and needs no index, so calling
        this on a default deployment should be harmless.
        """
        if self.embed_fn is None:
            return 0

        vectors: dict[str, list[float]] = {}
        for entry in self.list_entries():
            try:
                vectors[entry.entry_id] = list(self.embed_fn(entry.text))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not embed entry %s: %s", entry.entry_id, exc)

        self.store_dir.mkdir(parents=True, exist_ok=True)
        pending = self.index_path.with_suffix(".json.tmp")
        pending.write_text(json.dumps(vectors), encoding="utf-8")
        os.replace(pending, self.index_path)
        return len(vectors)

    # -- retention ------------------------------------------------------

    def purge_expired(self, known_repos: set[str]) -> PurgeResult:
        """Remove entries whose subject no longer exists (spec 11 §5).

        Not a confidence purge — decay never deletes. This removes entries
        about repositories Mykronos no longer holds data for, because an entry
        about an offboarded repo cannot be reconfirmed, cannot be audited
        against anything, and would otherwise outlive the deletion request
        that removed everything else (spec 02 §6).

        Org-tier entries with no repo are never touched: they are not about a
        repository, so no repository going away can expire them.
        """
        entries = self.list_entries()
        keep, removed = [], []
        for entry in entries:
            if entry.repo_full_name is None or entry.repo_full_name in known_repos:
                keep.append(entry)
            else:
                removed.append(entry.entry_id)

        if removed:
            self._write(keep)
            logger.info(
                "Knowledge store %s: purged %s entr(ies) for offboarded repos",
                self.tier,
                len(removed),
            )
        return PurgeResult(removed=removed)


def half_life_check(half_life_days: int, elapsed_days: int) -> float:
    """The decay multiplier, exposed for tests and for the retro report.

    Kept as a free function so the arithmetic can be stated in a report
    without instantiating a store.
    """
    return float(0.5 ** (elapsed_days / half_life_days))


def default_store_dir(datalake_dir: Path) -> Path:
    """Colocated with the lake, in its own directory (spec 11 §8)."""
    return Path(datalake_dir) / "knowledge"


def since(days: int, *, now: datetime | None = None) -> datetime:
    return (now or utcnow()) - timedelta(days=days)
