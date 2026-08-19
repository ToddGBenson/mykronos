"""Last-publish dates for resolved dependencies (spec 22 §2).

`stale_dependencies` has been in the schema, in the trust formula, and on the
frontend labelled "Unmaintained packages" since spec 07 shipped. Nothing has
ever incremented it — osv-scanner has no last-release signal — so the term has
contributed exactly zero to every trust score this platform has computed.

This is the cheapest thing that makes it real: the npm and PyPI registries
both answer "when did this package last publish" unauthenticated, in one
request, and both are already used to far heavier traffic than a dependency
tree's worth of HEAD-ish reads.

Opt-in, never default-on, following the rule spec 07 §7 already holds Atlas to
and the shape Aegis's `ai_classifier_url` established: the platform does not
make outbound calls to third parties because a scan happened to run.

    python -m mykronos.atlas_freshness sbom.json --threshold-days 730

Prints `{"<ecosystem>": {"stale": n, "known": n}}` on stdout.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from mykronos.atlas_sbom import _components, _ecosystem_of

#: Two years. Long enough that what trips it is an abandoned package rather
#: than a merely finished one — plenty of small, correct libraries have not
#: needed a release since 2019 and are not a supply-chain risk for it. The
#: threshold is configurable precisely because that judgement is a policy
#: call, not a fact.
DEFAULT_THRESHOLD_DAYS = 730

_TIMEOUT_SECONDS = 10


def _get_json(url: str) -> dict[str, Any] | None:
    """One registry read, or None. Never raises.

    spec 22 §6: one package's lookup failing — a timeout, a delisted package,
    a private name that is not on the public registry at all — must not fail
    the scan or contaminate the other packages' answers. It costs that one
    package's row in the denominator, which is exactly what
    `maintenance_data_available_for` exists to express.
    """
    try:
        request = urllib.request.Request(
            url, headers={"Accept": "application/json", "User-Agent": "mykronos-atlas"}
        )
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            payload = json.load(response)
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _parse(stamp: str) -> datetime | None:
    """An ISO-8601 timestamp from either registry, as an aware datetime."""
    text = stamp.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def npm_last_publish(name: str, fetch: Callable[[str], dict[str, Any] | None]) -> datetime | None:
    """When npm last saw a release of this package.

    The newest stamp in `time`, not `time[latest]`. `modified` moves for
    events that publish nothing — a deprecation, an unpublish — and those are
    maintenance too; the question here is whether anybody is still tending
    the package, not whether they shipped features. `created` is excluded
    because a package's birth is not evidence of current care, and it is the
    only stamp a long-abandoned package is guaranteed to have.
    """
    payload = fetch(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
    if not payload:
        return None
    times = payload.get("time")
    if not isinstance(times, dict):
        return None
    candidates = [
        _parse(str(value))
        for key, value in times.items()
        if key not in {"created", "unpublished"} and isinstance(value, str)
    ]
    real = [stamp for stamp in candidates if stamp]
    return max(real) if real else None


def pypi_last_publish(name: str, fetch: Callable[[str], dict[str, Any] | None]) -> datetime | None:
    """When PyPI last saw a release of this package.

    The newest upload across every release, not the newest *version* — the
    two differ whenever a maintainer backports to an older line, and a
    backport is maintenance.
    """
    payload = fetch(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    if not payload:
        return None
    newest: datetime | None = None
    for files in (payload.get("releases") or {}).values():
        if not isinstance(files, list):
            continue
        for entry in files:
            if not isinstance(entry, dict):
                continue
            stamp = _parse(str(entry.get("upload_time_iso_8601") or ""))
            if stamp and (newest is None or stamp > newest):
                newest = stamp
    return newest


_LOOKUPS: dict[str, Callable[[str, Callable[[str], dict[str, Any] | None]], datetime | None]] = {
    "npm": npm_last_publish,
    "pypi": pypi_last_publish,
}


def staleness(
    sbom: dict[str, Any],
    *,
    threshold_days: int = DEFAULT_THRESHOLD_DAYS,
    now: datetime | None = None,
    fetch: Callable[[str], dict[str, Any] | None] = _get_json,
) -> dict[str, dict[str, int]]:
    """Per-ecosystem `{"stale": n, "known": n}` (spec 22 §2.2).

    `known` is the denominator the trust formula needs: packages whose
    maintenance recency was actually established. A package whose lookup
    failed appears in neither number — not stale, not fresh, not counted.
    Folding it in either direction would be a claim about a package nobody
    managed to ask about.

    `fetch` is injected so the registry reads are the one thing a caller can
    replace. Nothing else here touches the network.
    """
    cutoff = (now or datetime.now(UTC)) - timedelta(days=threshold_days)
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"stale": 0, "known": 0})
    # One lookup per distinct name, not per component. A monorepo resolves the
    # same package in several workspaces and the registry answer is identical.
    asked: dict[tuple[str, str], datetime | None] = {}

    for component in _components(sbom):
        ecosystem = _ecosystem_of(component)
        lookup = _LOOKUPS.get(ecosystem)
        name = str(component.get("name") or "")
        if lookup is None or not name:
            continue
        key = (ecosystem, name)
        if key not in asked:
            asked[key] = lookup(name, fetch)
        published = asked[key]
        if published is None:
            continue
        counts[ecosystem]["known"] += 1
        if published < cutoff:
            counts[ecosystem]["stale"] += 1

    return dict(sorted(counts.items()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mykronos-atlas-freshness", description=__doc__
    )
    parser.add_argument("sbom")
    parser.add_argument("--threshold-days", type=int, default=DEFAULT_THRESHOLD_DAYS)
    args = parser.parse_args(argv)

    try:
        with open(args.sbom, encoding="utf-8") as handle:
            sbom = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read {args.sbom}: {exc}", file=sys.stderr)
        json.dump({}, sys.stdout)
        return 0

    json.dump(
        staleness(sbom, threshold_days=args.threshold_days), sys.stdout, ensure_ascii=False
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
