"""Bump a Dockerfile's base image to a newer tag, pinned by digest (TheHub #60746).

The deterministic fixer `bump-base-image` (registered in `fixers.FIXERS`). A
finding that points at a Dockerfile's `FROM` line, for an image on the
registry the lanes publish to, gets one edit: the reference on that line moves
to the newest tag the registry holds *in the same series*, written as
`<image>:<new tag>@sha256:<digest>`. Everything else on the line (`--platform`,
`AS <stage>`, comments) is kept byte for byte.

**Same series only.** What counts as newer is mechanical, never a choice:

- `<prefix>-p<YYYYMMDD>` (image-refresh's patched shape): the same prefix at a
  later date, exactly as `image_date.newer_date` reads it.
- `<major>.<minor>.<patch><suffix>`: the same major, minor and suffix at a
  higher patch. `3.12.4-slim` may become `3.12.7-slim`; never `3.13.0-slim`
  and never `3.12.7-alpine`, which are different platforms.

Anything else (`latest`, `3.12`, a bare major) names a moving target or a
decision about the platform, and is refused with that reason.

**The digest is resolved, then verified, or there is no pull request.** The
manifest is fetched by the new tag and its bytes hashed; the registry's
`Docker-Content-Digest` must equal that hash. A registry that cannot be
reached, answers without the header, or answers with bytes that do not hash to
it produces a refusal and no pull request. A tag alone is not pinned: a tag
can be pushed again, and a digest is the only name for the exact bytes the
reviewer is approving.

`propose` is pure: the tag listing and the verified digest are arguments.
`RegistryDigests` is the one network read, anonymous and read-only.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote, urljoin

import httpx2

from mykronos.patchwork.fixers import ProposedFix
from mykronos.patchwork.image_date import PUBLIC_REGISTRIES, _split_host, newer_date, parse_image

logger = logging.getLogger(__name__)

FIXER_NAME = "bump-base-image"

#: File names a Dockerfile goes by.
_DOCKERFILE = re.compile(
    r"(?:^|/)(?:Dockerfile(?:\.[^/]+)?|[^/]+\.[Dd]ockerfile|Containerfile(?:\.[^/]+)?)$"
)
#: One `FROM` instruction: leading flags kept, the reference, then the rest.
_FROM = re.compile(r"^(?P<lead>\s*FROM\s+(?:--\S+\s+)*)(?P<ref>[^\s#]+)(?P<rest>.*)$", re.I)
_SEMVER = re.compile(
    r"^(?P<v>v?)(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?P<suffix>[-+._A-Za-z0-9]*)$"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

#: What the manifest read accepts: every format a tag can point at. The
#: registry returns the manifest as stored, so its bytes hash to the digest.
MANIFEST_TYPES = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


@dataclass(frozen=True)
class BaseImage:
    """The image a `FROM` line names, and where."""

    path: str
    line: int  # 1-based
    host: str
    repository: str
    tag: str
    digest: str | None

    @property
    def reference(self) -> str:
        return f"{self.host}/{self.repository}:{self.tag}"


def is_dockerfile(path: str) -> bool:
    return bool(_DOCKERFILE.search(path))


def _parse_reference(reference: str) -> tuple[str, str, str, str | None] | None:
    """(host, repository, tag, digest), or None for a reference that is not ours."""
    ref, _, digest = reference.partition("@")
    host, rest = _split_host(ref)
    if host is None or host.lower() in PUBLIC_REGISTRIES:
        return None
    repository, sep, tag = rest.rpartition(":")
    if not sep or not repository or "/" in tag or not tag:
        return None
    return host, repository, tag, digest or None


def from_line(finding: Mapping[str, Any], content: str) -> BaseImage | str | None:
    """The base image this finding points at.

    None when the finding is not about a Dockerfile's `FROM` line (the fixer
    does not apply); a string when it is, but names an image this fixer must
    not move; otherwise the image.
    """
    path = str(finding.get("file_path") or "")
    line_number = finding.get("line_start")
    if not path or not is_dockerfile(path) or not isinstance(line_number, int):
        return None
    lines = content.splitlines()
    if line_number < 1 or line_number > len(lines):
        return None
    match = _FROM.match(lines[line_number - 1])
    if not match:
        return None
    parsed = _parse_reference(match.group("ref"))
    if parsed is None:
        return (
            f"`{match.group('ref')}` at {path}:{line_number} is not on the registry "
            "the lanes publish to (no registry host, or a public one), so its "
            "tags and digests there are not evidence about this image."
        )
    host, repository, tag, digest = parsed
    return BaseImage(path, line_number, host, repository, tag, digest)


def newer_tag(tag: str, tags: Iterable[str]) -> str | None:
    """The newest tag in `tag`'s series strictly after it, or None."""
    listed = list(tags)
    patched = parse_image(f"registry.invalid/x:{tag}")
    if patched is not None:
        date = newer_date(patched, listed)
        return f"{patched.prefix}-p{date}" if date else None
    current = _SEMVER.match(tag)
    if not current:
        return None
    best: tuple[int, str] | None = None
    for candidate in listed:
        found = _SEMVER.match(candidate)
        if not found:
            continue
        if any(found.group(k) != current.group(k) for k in ("v", "major", "minor", "suffix")):
            continue
        patch = int(found.group("patch"))
        if patch > int(current.group("patch")) and (best is None or patch > best[0]):
            best = (patch, candidate)
    return best[1] if best else None


def rewrite(content: str, image: BaseImage, new_tag: str, digest: str) -> str:
    """`content` with only `image`'s `FROM` reference changed."""
    lines = content.splitlines(keepends=True)
    line = lines[image.line - 1]
    body = line.rstrip("\r\n")
    ending = line[len(body) :]
    match = _FROM.match(body)
    assert match is not None
    host_and_repo = match.group("ref").partition("@")[0].rpartition(":")[0]
    new_ref = f"{host_and_repo}:{new_tag}@{digest}"
    lines[image.line - 1] = f"{match.group('lead')}{new_ref}{match.group('rest')}{ending}"
    return "".join(lines)


def propose(
    image: BaseImage,
    content: str,
    *,
    tags: Iterable[str] | None,
    digest: str | None,
    new_tag: str | None = None,
) -> ProposedFix | str:
    """The pull request's change, or why there is none.

    `tags` is the registry's listing (None if it could not be read). `digest`
    is the verified digest of `new_tag` (None if it could not be resolved or
    did not verify); `new_tag` defaults to `newer_tag(image.tag, tags)`.
    """
    if tags is None:
        return f"Could not list the registry's tags for {image.repository}; no pull request."
    target = new_tag or newer_tag(image.tag, tags)
    if target is None:
        if not _SEMVER.match(image.tag) and parse_image(f"registry.invalid/x:{image.tag}") is None:
            return (
                f"`{image.tag}` has no patch component, so it names a moving target "
                "or a platform choice; choosing what to move it to is not mechanical."
            )
        return (
            f"The registry holds no tag in {image.repository}:{image.tag}'s series "
            "newer than it."
        )
    if digest is None or not _DIGEST.match(digest):
        return (
            f"The digest of {image.repository}:{target} could not be resolved and "
            "verified against the registry, so there is nothing safe to pin; no pull "
            "request."
        )
    rewritten = rewrite(content, image, target, digest)
    return ProposedFix(
        files={image.path: rewritten},
        summary=f"Move the base image `{image.repository}` to {target}, pinned by digest",
        review_notes=[
            f"`{image.path}:{image.line}` moves from `{image.repository}:{image.tag}` to "
            f"`{image.repository}:{target}@{digest}`: the same series, a newer release. "
            "Nothing else in the file changed.",
            f"The digest was read from the registry and verified: the manifest bytes "
            f"served for `{target}` hash to `{digest}`. The build now pulls exactly those "
            "bytes even if the tag is pushed again.",
            "Rebuild and run the test suite. A newer base can still change a package "
            "the image depends on.",
            "A digest pin does not move by itself. The next bump is another pull "
            "request like this one.",
        ],
    )


class DigestSource(Protocol):
    async def digest(self, repository: str, tag: str) -> str | None:
        """The verified `sha256:` digest of `repository:tag`, or None."""
        ...


class RegistryDigests:
    """`GET /v2/<repository>/manifests/<tag>`, verified against its own bytes.

    The same registry and the same anonymous, read-only access as
    `image_date.RegistryTags`. None on anything short of a verified digest.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.transport = transport

    @classmethod
    def from_settings(cls, settings: Any) -> RegistryDigests | None:
        url = str(getattr(settings, "patchwork_image_registry", "") or "").strip()
        return cls(url) if url else None

    async def digest(self, repository: str, tag: str) -> str | None:
        url = urljoin(
            self.base_url,
            f"v2/{quote(repository, safe='/')}/manifests/{quote(tag, safe='')}",
        )
        try:
            async with httpx2.AsyncClient(
                timeout=self.timeout, transport=self.transport, follow_redirects=False
            ) as client:
                response = await client.get(url, headers={"Accept": MANIFEST_TYPES})
                response.raise_for_status()
        except httpx2.HTTPError as exc:
            logger.warning("Could not read the manifest of %s:%s: %s", repository, tag, exc)
            return None
        claimed = str(response.headers.get("docker-content-digest") or "").strip()
        computed = "sha256:" + hashlib.sha256(response.content).hexdigest()
        if not _DIGEST.match(claimed) or claimed != computed:
            logger.warning(
                "Refusing the digest of %s:%s: the registry said %r, the bytes hash to %s",
                repository,
                tag,
                claimed,
                computed,
            )
            return None
        return claimed
