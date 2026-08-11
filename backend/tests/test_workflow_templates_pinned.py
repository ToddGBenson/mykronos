"""Every action reference the installer emits must be immutable.

A tag is a mutable pointer. Whoever controls it controls what executes inside every
onboarded repository -- with that repo's checkout on disk and its ingestion token in the
environment. `uses: some/action@v4` is a standing invitation for that actor to change what
runs, silently, in every install at once.

This is a test rather than a review habit because the pins have already been lost once. A
downstream repo pinned its three installed workflows by hand; the next template resync
reverted all ten refs to tags, because nothing upstream asserted otherwise. A fix that lives
only downstream is a fix with an expiry date.

Two failure modes are covered:

  1. A template gains an unpinned `uses:`.
  2. The shared composite action's default ref goes back to a tag.

Both look completely normal in review. Neither is visible without executing something.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "workflow-templates"

# `uses:` values that are Jinja variables rather than literal refs. These are resolved at
# render time and are asserted separately, against the config default.
TEMPLATED_REFS = {"<< upload_action_ref >>"}

USES = re.compile(r"^\s*uses:\s*(?P<ref>\S.*?)\s*(?:#.*)?$", re.MULTILINE)
SHA_PINNED = re.compile(r"^[\w.-]+(?:/[\w.-]+)+@[0-9a-f]{40}$")


def _templates() -> list[Path]:
    files = sorted(TEMPLATE_DIR.glob("*.yml.j2"))
    assert files, f"no templates found under {TEMPLATE_DIR} -- a test that scans nothing passes"
    return files


@pytest.mark.parametrize("template", _templates(), ids=lambda p: p.name)
def test_every_action_reference_is_sha_pinned(template: Path) -> None:
    offenders = []
    for match in USES.finditer(template.read_text(encoding="utf-8")):
        ref = match.group("ref")
        if ref in TEMPLATED_REFS or ref.startswith("./"):
            continue
        if not SHA_PINNED.match(ref):
            offenders.append(ref)

    assert not offenders, (
        f"{template.name} references actions by mutable ref: {offenders}. "
        "Pin to the full commit SHA with a trailing `# vX.Y.Z` comment.\n"
        "Resolve with: gh api repos/<owner>/<repo>/commits/<tag> --jq .sha\n"
        "Do NOT read the SHA off the tag object -- an annotated tag's object SHA is the "
        "tag, not the commit, and pinning it yields a valid-looking ref that never resolves."
    )


def test_shared_upload_action_default_is_a_commit_not_a_tag() -> None:
    """The one action every onboarded repo runs is the one worth pinning hardest."""
    from mykronos.config import Settings

    ref = Settings.model_fields["upload_action_ref"].default
    if callable(ref):  # default_factory
        ref = ref()

    assert "@" in ref, f"upload_action_ref has no ref at all: {ref!r}"
    _, _, rev = ref.rpartition("@")

    assert re.fullmatch(r"[0-9a-f]{40}", rev), (
        f"upload_action_ref is pinned to {rev!r}, which is not a 40-character commit SHA. "
        "Every onboarded repo executes this action with its own checkout and ingestion "
        "token; a tag can be repointed by whoever controls it.\n"
        "NOTE: v1 is an ANNOTATED tag. Dereference it to the commit "
        "(`gh api repos/ToddGBenson/mykronos/commits/v1 --jq .sha`) rather than using the "
        "tag-object SHA."
    )


def test_rendered_ref_and_installed_package_ref_agree() -> None:
    """`mykronos_ref` is derived from `upload_action_ref`; a SHA must survive that split.

    The template installs the Python package from `mykronos_ref` so the package and the
    action come from the same commit. If pinning broke that derivation, the action and the
    package it installs would drift apart -- which is the bug this derivation was added to
    fix in the first place.
    """
    from mykronos.config import Settings

    ref = Settings.model_fields["upload_action_ref"].default
    if callable(ref):
        ref = ref()

    derived = ref.rpartition("@")[2] or "main"
    assert re.fullmatch(r"[0-9a-f]{40}", derived), (
        f"derived mykronos_ref is {derived!r}, not a commit SHA -- the action would run at "
        "one revision and install its package from another."
    )
