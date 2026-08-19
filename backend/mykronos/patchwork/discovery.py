"""Candidate toxic combinations, for a person to review (spec 19 §2.2).

The nine rules in `correlate.py` are hand-written and always will be —
`BUILT_IN_RULES` staying declarative and human-reviewed is spec 08 §5's whole
point, and nothing here changes it. What is missing is a way to *notice* a
pattern worth writing a rule for, which today depends on somebody happening to
see the same pairing twice.

So this finds candidates and stops. It writes nothing to `correlate.py`, it
proposes no rule text, and its output is a section of the retro report a
person reads. The same shape spec 11's `find_cross_project_candidates` already
uses for false-positive promotion: the machine surfaces, the human decides.

A co-occurrence count, not a statistical model. With a portfolio of tens of
repositories, a chi-squared test over sparse capability pairs would produce
confident-looking numbers from almost no data — the count is honest about
being a count.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from mykronos.lake.catalog import Catalog
from mykronos.patchwork import correlate

#: Below this a pairing is a coincidence. Two capabilities finding something
#: in the same file once is the normal texture of a codebase; the same pairing
#: in several repositories is the thing worth a rule.
DEFAULT_MIN_REPOS = 2
DEFAULT_MIN_FILES = 3


@dataclass
class CandidateCombination:
    capabilities: tuple[str, str]
    files: int
    repos: int
    examples: list[dict[str, Any]] = field(default_factory=list)

    @property
    def key(self) -> str:
        return "+".join(self.capabilities)


def _covered_pairs() -> set[frozenset[str]]:
    """Capability pairs an existing rule already names.

    Read from `BUILT_IN_RULES` rather than hardcoded, so a rule somebody adds
    tomorrow stops this suggesting the pairing it covers. A discovery report
    that keeps proposing what already exists is one people stop reading.
    """
    covered: set[frozenset[str]] = set()
    for rule in correlate.BUILT_IN_RULES:
        named = {
            capability
            for requirement in rule.requires
            for capability in requirement.capabilities
        }
        for first in named:
            for second in named:
                if first != second:
                    covered.add(frozenset({first, second}))
    return covered


def find_candidates(
    catalog: Catalog,
    *,
    min_repos: int = DEFAULT_MIN_REPOS,
    min_files: int = DEFAULT_MIN_FILES,
    limit: int = 10,
) -> list[CandidateCombination]:
    """Capability pairs that keep landing in the same file, uncovered by a rule.

    Scoped to open findings with a real `file_path`: a pairing in a file
    somebody already fixed is not a pattern to write a rule about, and the
    empty path that dependency findings carry would collapse every one of them
    into a single enormous phantom co-occurrence.
    """
    rows = catalog.query(
        """
        SELECT asset_id, file_path, capability, rule_id, title
        FROM findings
        WHERE status = 'open'
          AND file_path IS NOT NULL AND trim(file_path) <> ''
          AND capability IS NOT NULL
        """
    )

    by_file: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    for asset_id, file_path, capability, rule_id, title in rows:
        # One example per capability per file. A file with forty SAST findings
        # would otherwise dominate every example list with the same rule.
        by_file[(str(asset_id), str(file_path))].setdefault(
            str(capability),
            {"capability": str(capability), "rule_id": str(rule_id), "title": str(title)},
        )

    covered = _covered_pairs()
    files: dict[frozenset[str], int] = defaultdict(int)
    repos: dict[frozenset[str], set[str]] = defaultdict(set)
    examples: dict[frozenset[str], list[dict[str, Any]]] = defaultdict(list)

    for (asset_id, file_path), found in by_file.items():
        capabilities = sorted(found)
        for index, first in enumerate(capabilities):
            for second in capabilities[index + 1 :]:
                pair = frozenset({first, second})
                if pair in covered:
                    continue
                files[pair] += 1
                repos[pair].add(asset_id)
                if len(examples[pair]) < 3:
                    examples[pair].append(
                        {
                            "repo_full_name": asset_id,
                            "file_path": file_path,
                            "findings": [found[first], found[second]],
                        }
                    )

    candidates = [
        CandidateCombination(
            capabilities=tuple(sorted(pair)),  # type: ignore[arg-type]
            files=count,
            repos=len(repos[pair]),
            examples=examples[pair],
        )
        for pair, count in files.items()
        if count >= min_files and len(repos[pair]) >= min_repos
    ]
    candidates.sort(key=lambda c: (-c.files, -c.repos, c.key))
    return candidates[:limit]
