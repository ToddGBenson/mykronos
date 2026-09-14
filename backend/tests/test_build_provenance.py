"""The running container has to be able to say which commit it is (#361).

THE DEFECT. On 2026-09-13 the backend serving this platform was an image built
eight days earlier. Twenty-six merged PRs were not running -- including one
that had been blocking `promote` for a day -- and every indicator the platform
publishes was green throughout: `repos_with_stale_scans: 0`,
`overdue_findings: 0`. Both measure how recently a repository was *scanned*.
Nothing measured what was *deployed*, and nothing could have, because the
artifact had no way to name itself:

  - the image tag carries the full commit SHA, but a container cannot read the
    tag it was started from;
  - `mykronos.__version__` is `0.1.0` in every build ever made;
  - the pipeline's `build` job appears to fix that -- it renames its wheel to
    carry `+<short-sha>` -- but a wheel records its version in METADATA, not in
    its filename, and `backend/Dockerfile` compiles a *separate* wheel of its
    own. The stamped artifact never reaches the image.

So three mechanisms looked like they answered "what is running?" and none did.
The gap was found because the operator asked, not because anything measured it.

WHAT THESE TESTS PIN:

  1. a build-arg SHA reaches `/healthz`               <- the mechanism works
  2. no SHA reports unknown, and reports it as a null <- absence is a state
  3. `__version__` is never used as a substitute      <- the trap above
  4. the probe stays unauthenticated                  <- see the class docstring
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from mykronos import __version__
from mykronos.config import Settings
from mykronos.main import create_app

SHA = "63714b61df3743b16ff72b4d1dc7f2c2011b4aed"


def _build(settings: Settings, sha: str) -> dict:
    """A client over an app configured exactly as an image would be."""
    configured = settings.model_copy(update={"build_sha": sha})
    with TestClient(create_app(configured)) as client:
        response = client.get("/healthz")
    assert response.status_code == 200
    return response.json()["build"]


class TestTheImageCanNameItself:
    def test_a_baked_sha_is_reported(self, settings: Settings) -> None:
        """The whole mechanism in one assertion: what the Dockerfile's
        `ARG MYKRONOS_BUILD_SHA` receives is what a caller outside the
        container reads back."""
        build = _build(settings, SHA)

        assert build["sha"] == SHA
        assert build["source"] == "image"

    def test_it_is_reported_verbatim(self, settings: Settings) -> None:
        """Not shortened, not normalised. The tag is the full 40 characters
        and the comparison against `main` is an equality test -- an
        abbreviation here would turn that into a prefix match, which is a
        different and weaker claim."""
        assert _build(settings, SHA)["sha"] == SHA
        assert len(_build(settings, SHA)["sha"]) == 40


class TestAbsenceIsAStateRatherThanAGuess:
    def test_no_sha_reports_unknown(self, settings: Settings) -> None:
        """A local `docker build` genuinely does not know the commit.

        `source` exists so that case cannot be misread as an answer. This is
        the same distinction the portfolio already draws between "never
        scanned" and "stale", and between a `risk_score` of None and one of 0.
        """
        build = _build(settings, "")

        assert build["sha"] is None
        assert build["source"] == "unknown"

    def test_whitespace_is_not_a_sha(self, settings: Settings) -> None:
        """A build-arg that arrives as `""` through a shell can reach the
        environment as a space. An unknown build that claims to be known is
        strictly worse than one that admits it."""
        build = _build(settings, "   ")

        assert build["sha"] is None
        assert build["source"] == "unknown"

    def test_the_version_is_never_the_fallback(self, settings: Settings) -> None:
        """The trap this file's docstring describes.

        `__version__` is `0.1.0` in every image ever built, including the
        eight-day-old one. Falling back to it would restore exactly the
        failure this endpoint exists to prevent: a confident, wrong, and
        entirely stable answer about what is deployed.
        """
        build = _build(settings, "")

        assert build["sha"] != __version__
        assert __version__ not in str(build["sha"])


class TestItIsReadableFromOutside:
    def test_the_probe_needs_no_credential(self, client: TestClient) -> None:
        """Whatever asks "is the fix running yet?" asks from outside the
        container, of the process actually serving traffic. A commit SHA names
        a public commit in a public repository; TheHub has served its own from
        `/health` throughout, and that is what made TheHub's deployment state
        checkable on 2026-09-13 when mykronos's was not."""
        response = client.get("/healthz")

        assert response.status_code == 200
        assert "build" in response.json()

    def test_it_still_reveals_nothing_else(self, client: TestClient) -> None:
        """The endpoint's existing contract. `build` is additive -- it must
        not become the reason an unauthenticated caller learns about the
        lake, the repositories, or the findings."""
        body = client.get("/healthz").json()

        assert set(body) == {"status", "version", "build"}
        assert set(body["build"]) == {"sha", "source"}
