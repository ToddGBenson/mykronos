"""Compare the origins an app loads against the CSP it serves (mykronos#290).

A Content-Security-Policy is a whitelist of every external origin an
application is allowed to reach, and nothing in this estate declares that
list. Shipping one to TheHub broke two features latently — `cdn.teller.io`
(bank connect) and `api.datamuse.com` (rhyme lookup) — and neither review nor
a smoke test caught either, because both fail only when a user exercises the
feature. The page loads, the console is clean, and nothing reports it.

The two halves already exist here and were joined by nobody: the repository,
cloned by every scan, and the served policy, which the DAST lane reads on
every run. This module is the join, and it reports in **both** directions:

* **used-but-not-permitted** — the app loads an origin the policy omits. A
  latent functional break. This is the direction that bites.
* **permitted-but-unused** — the policy names an origin nothing loads. Not a
  break; a permission nobody is watching grow.

Three disciplines this module holds to, because each of them is a way a check
like this quietly asserts more than it measured:

1. **A hit is not a use.** `https://host/...` in a string is a link target as
   often as it is a fetch, and CSP governs one and not the other. TheHub has
   25 references to `www.google.com` (anchors, ungoverned) and 2 to
   `api.datamuse.com` (a `fetch`, governed, and blocked); a grep reports them
   identically. Every reference here carries the *pattern that classified it*,
   and a reference no pattern claims is recorded as `unclassified` rather than
   silently dropped or silently counted.

2. **A wildcarded directive cannot be evaluated.** A directive whose effective
   source list contains a scheme-source (`https:`) or `*` permits every origin,
   which makes the named origins beside it decorative: no omission is possible
   under it and no named source there can be called unused. TheHub's `img-src`
   ends in a bare `https:` after ten named origins (that is #329, deliberate
   and documented at b71d04c7). This says so once, instead of reporting ten
   tidy findings that would be equally true of any hostname in the world.

3. **Name the environment, and name what was read.** Two backends here carry
   different policies and nothing records which one a claim came from — copying
   the narrower one is what caused the Teller break in the first place. So
   `--environment` is required, not defaulted, and the scanned paths travel
   with the result too: "unused" means "unreferenced under the paths I read",
   and that qualifier is part of the claim.

**Asymmetric confidence, stated once here and repeated in the output.** An
omission is positive evidence — a specific line does a specific governed load
and the policy has no source for it. An unused allowance is an argument from
absence over a regex sweep of source text: a URL assembled at runtime, loaded
by a third-party stylesheet, or pulled from configuration is invisible to
this. Omissions are actionable; unused allowances are a prompt to go look.

This is the measurement, not a fix. It changes no policy, and it is not yet
wired into a pipeline lane — it emits SARIF, which the existing capabilities
ingest, and a human report. Wiring needs a per-environment policy URL decided
by an operator, and inventing one here would be the same defect this module
exists to catch.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

# --------------------------------------------------------------------------
# Directives
# --------------------------------------------------------------------------

#: The fallback chain the browser walks for each directive we classify into.
#: A policy that omits `frame-src` does not permit nothing there — it falls
#: back to `child-src` and then `default-src`, and a comparison that ignored
#: that would report every framed origin as missing on a policy that permits
#: them all. `form-action` deliberately has no `default-src` entry: it does
#: not fall back, per CSP Level 3 §6.1.
FALLBACK: dict[str, tuple[str, ...]] = {
    "script-src": ("script-src", "default-src"),
    "style-src": ("style-src", "default-src"),
    "img-src": ("img-src", "default-src"),
    "font-src": ("font-src", "default-src"),
    "connect-src": ("connect-src", "default-src"),
    "frame-src": ("frame-src", "child-src", "default-src"),
    "worker-src": ("worker-src", "child-src", "script-src", "default-src"),
    "media-src": ("media-src", "default-src"),
    "object-src": ("object-src", "default-src"),
    "form-action": ("form-action",),
}

#: Source expressions that permit *any* host, which is what makes every named
#: origin in the same directive unfalsifiable. `data:` and `blob:` are not
#: here on purpose: they widen the scheme, not the host set, so a policy with
#: `img-src 'self' data:` can still be meaningfully compared.
HOST_WILDCARDS = frozenset({"*", "*:*", "http:", "https:", "https://*", "http://*"})

#: The two of those that permit any host on *any* scheme. The rest are
#: scheme-bound: `https:` widens the host set to everything and still blocks
#: `http://`, so it cannot be matched by membership alone. Getting this wrong
#: is how a wildcard swallows the one origin the policy really did block.
_ANY_SCHEME_WILDCARDS = frozenset({"*", "*:*"})

#: Source expressions that are not origins at all and are never "unused" in
#: the sense this module reports — they say something about inline content or
#: about the document itself, not about an external host.
_NON_ORIGIN_SOURCE = re.compile(
    r"^(?:'[^']*'|data:|blob:|filesystem:|mediastream:|ws:|wss:|\*|\*:\*)$", re.IGNORECASE
)

# --------------------------------------------------------------------------
# Origins
# --------------------------------------------------------------------------

#: A hostname worth reporting: labelled, dotted, no underscores. This rejects
#: the placeholders every frontend tree carries — `https://...`,
#: `https://YOUR_HOST`, `https://${base}` — which are not origins and would
#: otherwise arrive as findings about hosts that do not exist.
_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

#: RFC 2606 / RFC 6761 reserved names. A documentation example is not a load.
_RESERVED_SUFFIXES = (".example.com", ".example.org", ".example.net", ".example", ".invalid")
_RESERVED_EXACT = frozenset({"example.com", "example.org", "example.net", "localhost"})

#: Any absolute http(s) URL in a blob of source text.
_URL = re.compile(r"https?://[^\s'\"`)>\\]+", re.IGNORECASE)


def normalise_origin(url: str) -> str | None:
    """`https://Host:443/path?q` -> `https://host`, or None if not an origin.

    Returns None rather than a best guess for anything that is not a real
    host — a template placeholder, a reserved documentation name. A check that
    reports `https://...` as an unpermitted origin has stopped measuring and
    started guessing.
    """
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not host:
        return None
    host = host.lower()
    if not _HOSTNAME.match(host):
        return None
    if host in _RESERVED_EXACT or host.endswith(_RESERVED_SUFFIXES):
        return None
    default_port = 443 if parts.scheme == "https" else 80
    if port and port != default_port:
        return f"{parts.scheme}://{host}:{port}"
    return f"{parts.scheme}://{host}"


def source_matches(source: str, origin: str) -> bool:
    """Does one CSP source expression permit `origin` (`scheme://host[:port]`)?

    Implements the host-source grammar the comparison needs: scheme-sources
    (`https:`), the `*` host wildcard, a leading `*.` label wildcard, an
    optional scheme, and an optional port. Keyword sources (`'self'`,
    `'unsafe-inline'`, a nonce) never match a named external origin here —
    `'self'` is resolved separately, against the origins the caller declares
    the app serves from, because a repository cannot know its own hostname.
    """
    source = source.strip()
    if not source or source.startswith("'"):
        return False
    lowered = source.lower()
    if lowered in _ANY_SCHEME_WILDCARDS:
        return True
    target = urlsplit(origin)
    if lowered.endswith(":") and "//" not in lowered:
        return origin.startswith(f"{lowered}//")  # scheme-source: https:

    if "//" in lowered:
        scheme, _, rest = lowered.partition("://")
        if scheme != target.scheme:
            return False
    else:
        rest = lowered
    rest = rest.split("/", 1)[0]
    host, _, port = rest.partition(":")
    target_port = str(target.port or (443 if target.scheme == "https" else 80))
    if port and port not in ("*", target_port):
        return False
    target_host = target.hostname or ""
    if host == "*":
        return True
    if host.startswith("*."):
        return target_host == host[2:] or target_host.endswith(host[1:])
    return target_host == host


# --------------------------------------------------------------------------
# The served policy
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Policy:
    """A parsed `Content-Security-Policy`, with where it came from attached.

    `environment` and `read_from` are not decoration. Every claim this module
    makes is a claim about one environment's policy, and the estate has three
    backends. A finding that does not name which one reproduces the bug it
    was built to catch.
    """

    environment: str
    read_from: str
    directives: dict[str, tuple[str, ...]]
    raw: str

    def effective_sources(self, directive: str) -> tuple[str, str] | None:
        """`(name, sources)` of the directive that actually governs, or None.

        Walks the fallback chain. None means no directive in the chain is
        present, so the load is unrestricted and there is nothing to compare.
        """
        for name in FALLBACK.get(directive, (directive,)):
            if name in self.directives:
                return name, " ".join(self.directives[name])
        return None

    def is_wildcarded(self, directive: str) -> str | None:
        """The source expression that makes this directive permit any host."""
        effective = self.effective_sources(directive)
        if effective is None:
            return None
        for source in effective[1].split():
            if source.lower() in HOST_WILDCARDS:
                return source
        return None


def parse_policy(header: str, *, environment: str, read_from: str) -> Policy:
    """Parse a `Content-Security-Policy` header value.

    Later occurrences of a directive are ignored, which is what a browser does
    within a single policy: the first wins.
    """
    directives: dict[str, tuple[str, ...]] = {}
    for chunk in header.split(";"):
        tokens = chunk.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name in directives:
            continue
        directives[name] = tuple(tokens[1:])
    return Policy(
        environment=environment,
        read_from=read_from,
        directives=directives,
        raw=header.strip(),
    )


# --------------------------------------------------------------------------
# What the code actually loads
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Reference:
    """One external origin, at one place, classified by how it is used.

    `directive` is None when the reference is real but ungoverned (an anchor
    target, a `preconnect` hint) or when no pattern could classify it. Those
    are kept rather than dropped: they are the difference between "nothing
    references this origin" and "nothing I could classify references it", and
    only the first of those is a finding.
    """

    origin: str
    directive: str | None
    evidence: str
    file_path: str
    line: int
    snippet: str

    @property
    def governed(self) -> bool:
        return self.directive is not None


#: Markup attributes, by tag, and the directive each one is fetched under.
#: `<a href>` and `<area href>` are the ungoverned case the issue is about —
#: most of TheHub's `google.com` references are these.
_TAG_RULES: dict[str, tuple[str, str | None]] = {
    "script": ("src", "script-src"),
    "img": ("src", "img-src"),
    "iframe": ("src", "frame-src"),
    "frame": ("src", "frame-src"),
    "audio": ("src", "media-src"),
    "video": ("src", "media-src"),
    "source": ("src", "media-src"),
    "track": ("src", "media-src"),
    "embed": ("src", "object-src"),
    "object": ("data", "object-src"),
    "form": ("action", "form-action"),
    "a": ("href", None),
    "area": ("href", None),
}

_TAG = re.compile(r"<\s*([a-zA-Z][a-zA-Z0-9-]*)\b([^<>]{0,4000}?)/?>", re.DOTALL)
_ATTR = re.compile(r"""([a-zA-Z_:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>'"]+))""")

#: `rel` values on `<link>`, and what the browser does with each. `preconnect`
#: and `dns-prefetch` open a connection and fetch nothing, so no directive
#: governs them — but they are evidence the origin is reached on purpose,
#: which is enough to keep a matching allowance off the unused list.
_LINK_RELS: dict[str, str | None] = {
    "stylesheet": "style-src",
    "preconnect": None,
    "dns-prefetch": None,
    "prefetch": None,
    "icon": "img-src",
    "shortcut icon": "img-src",
    "apple-touch-icon": "img-src",
    "manifest": "connect-src",
}

#: Calls whose argument is fetched over the network as data.
_CONNECT_SINKS = (
    r"fetch\(",
    r"\.open\(\s*['\"][A-Za-z]+['\"]\s*,",
    r"new\s+WebSocket\(",
    r"new\s+EventSource\(",
    r"new\s+Request\(",
    r"sendBeacon\(",
    r"axios(?:\.[a-z]+)?\(",
    r"\$\.(?:get|post|ajax|getJSON)\(",
)

_IDENT = r"[A-Za-z_$][\w$]*"
_ARG = rf"(?:(?P<lit>['\"`])(?P<url>https?://[^'\"`]+)(?P=lit)|(?P<ident>{_IDENT}))"

_CONNECT_CALL = re.compile(rf"(?:{'|'.join(_CONNECT_SINKS)})\s*{_ARG}\s*[,)]")
_IMPORT_SCRIPTS = re.compile(rf"(?:importScripts|new\s+Worker)\(\s*{_ARG}\s*[,)]")
#: `const NAME = <initialiser>;` — wide enough to carry the ternary that holds
#: both Datamuse URLs, which is exactly how the rhyme endpoint is built and
#: why a `fetch('https://...')` pattern misses it entirely.
_BINDING = re.compile(rf"(?:const|let|var)\s+({_IDENT})\s*=\s*([^;]{{0,400}}?);", re.DOTALL)
_SRC_ASSIGN = re.compile(rf"({_IDENT})\s*\.\s*src\s*=\s*{_ARG}")
_ELEMENT_KIND = re.compile(
    rf"(?:const|let|var)\s+({_IDENT})\s*=\s*"
    r"(?:document\.createElement\(\s*['\"](?P<tag>[a-z]+)['\"]"
    r"|new\s+(?P<ctor>Image|Audio)\s*\()"
)
_CSS_IMPORT = re.compile(r"@import\s+(?:url\()?\s*['\"]?(https?://[^'\")\s]+)", re.IGNORECASE)
_CSS_FONT_FACE = re.compile(r"@font-face\s*\{[^}]{0,2000}?\}", re.IGNORECASE | re.DOTALL)
_CSS_URL = re.compile(r"url\(\s*['\"]?(https?://[^'\")\s]+)", re.IGNORECASE)

#: `.src =` on an element we could identify by its constructor.
_KIND_DIRECTIVE = {
    "script": "script-src",
    "img": "img-src",
    "image": "img-src",
    "iframe": "frame-src",
    "audio": "media-src",
    "video": "media-src",
    "link": "style-src",
}

#: Directories a scan of "the app" should not walk into. Vendored code is not
#: this application's choice of origins, and a lockfile is not a load.
SKIP_DIRECTORIES = frozenset(
    {".git", "node_modules", "dist", "build", "vendor", ".venv", "venv", "__pycache__", ".next"}
)

#: Extensions whose contents can perform a load. Markdown is excluded: a URL
#: in a README is not something a CSP can block, and counting it would make
#: every allowance look used.
SCANNED_SUFFIXES = frozenset(
    {".html", ".htm", ".js", ".mjs", ".jsx", ".ts", ".tsx", ".css", ".vue"}
)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _snippet(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    line = text[start : end if end != -1 else len(text)]
    return line.strip()[:200]


def _emit(
    out: list[Reference],
    claimed: set[int],
    text: str,
    index: int,
    url: str,
    directive: str | None,
    evidence: str,
    path: str,
) -> None:
    origin = normalise_origin(url)
    claimed.add(index)
    if origin is None:
        return
    out.append(
        Reference(
            origin=origin,
            directive=directive,
            evidence=evidence,
            file_path=path,
            line=_line_of(text, index),
            snippet=_snippet(text, index),
        )
    )


def _markup_references(text: str, path: str, out: list[Reference], claimed: set[int]) -> None:
    """Tag/attribute loads, in HTML *and* in the HTML that JS builds.

    Run over script files too, on purpose: TheHub assembles markup in template
    literals, so `<img src="https://...">` inside a `.js` file is a real load
    and a detector that only read `.html` would miss it.
    """
    for tag_match in _TAG.finditer(text):
        tag = tag_match.group(1).lower()
        attributes = {
            name.lower(): (dq or sq or bare or "")
            for name, dq, sq, bare in _ATTR.findall(tag_match.group(2))
        }
        if tag == "link":
            rel = attributes.get("rel", "").strip().lower()
            if rel not in _LINK_RELS:
                continue
            value, directive = attributes.get("href", ""), _LINK_RELS[rel]
            evidence = f"<link rel={rel}>"
        elif tag in _TAG_RULES:
            attribute, directive = _TAG_RULES[tag]
            value = attributes.get(attribute, "")
            evidence = f"<{tag} {attribute}>"
        else:
            continue
        if not value.lower().startswith(("http://", "https://")):
            continue
        index = tag_match.start() + tag_match.group(0).find(value)
        _emit(out, claimed, text, index, value, directive, evidence, path)


def _script_references(text: str, path: str, out: list[Reference], claimed: set[int]) -> None:
    """Loads a script performs: fetches, workers, and a dynamic `src`."""
    bindings: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for match in _BINDING.finditer(text):
        name, initialiser = match.group(1), match.group(2)
        for url_match in _URL.finditer(initialiser):
            bindings[name].append((match.start(2) + url_match.start(), url_match.group(0)))

    element_kinds = {
        match.group(1): (match.group("tag") or (match.group("ctor") or "").lower())
        for match in _ELEMENT_KIND.finditer(text)
    }

    def resolve(match: re.Match[str], directive: str | None, evidence: str) -> None:
        if match.group("url"):
            index, url = match.start("url"), match.group("url")
            _emit(out, claimed, text, index, url, directive, evidence, path)
            return
        ident = match.group("ident") or ""
        for index, url in bindings.get(ident, []):
            _emit(out, claimed, text, index, url, directive, f"{evidence} via `{ident}`", path)

    for match in _CONNECT_CALL.finditer(text):
        resolve(match, "connect-src", match.group(0).split("(")[0].strip() + "()")
    for match in _IMPORT_SCRIPTS.finditer(text):
        resolve(match, "worker-src", "importScripts()/new Worker()")
    for match in _SRC_ASSIGN.finditer(text):
        kind = element_kinds.get(match.group(1), "")
        directive = _KIND_DIRECTIVE.get(kind)
        evidence = f"{match.group(1)}.src = ({kind or 'element of unknown type'})"
        resolve(match, directive, evidence)


def _style_references(text: str, path: str, out: list[Reference], claimed: set[int]) -> None:
    """`@import` is a stylesheet load; `url()` inside `@font-face` is a font."""
    for match in _CSS_IMPORT.finditer(text):
        _emit(out, claimed, text, match.start(1), match.group(1), "style-src", "@import", path)
    for block in _CSS_FONT_FACE.finditer(text):
        for match in _CSS_URL.finditer(block.group(0)):
            index = block.start() + match.start(1)
            _emit(out, claimed, text, index, match.group(1), "font-src", "@font-face src", path)


def references_in(text: str, path: str) -> list[Reference]:
    """Every external origin reference in one file, classified where possible.

    Anything a detector claimed keeps its directive. Everything else — a URL
    in a comment, in a configuration default, in a string this module cannot
    attribute to a load — is returned as an `unclassified` reference. That is
    the honest record: it is evidence the origin is mentioned, and it is not
    evidence of anything being loaded.
    """
    out: list[Reference] = []
    claimed: set[int] = set()
    _markup_references(text, path, out, claimed)
    _script_references(text, path, out, claimed)
    _style_references(text, path, out, claimed)

    for match in _URL.finditer(text):
        if match.start() in claimed:
            continue
        _emit(out, claimed, text, match.start(), match.group(0), None, "unclassified", path)
    return out


def scan_repository(repo_root: Path, paths: tuple[str, ...] = ()) -> list[Reference]:
    """Every classified origin reference under the given paths.

    `paths` narrows the sweep — "the frontend tree", not "the repository" —
    and the caller is expected to record what it passed, because "unused"
    means "unreferenced under the paths I read" and nothing stronger.
    """
    roots = [repo_root / p for p in paths] if paths else [repo_root]
    found: list[Reference] = []
    for root in roots:
        if not root.exists():
            continue
        candidates = sorted(root.rglob("*")) if root.is_dir() else [root]
        for path in candidates:
            if not path.is_file() or path.suffix.lower() not in SCANNED_SUFFIXES:
                continue
            if SKIP_DIRECTORIES & set(path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            relative = path.relative_to(repo_root).as_posix()
            found.extend(references_in(text, relative))
    return sorted(found, key=lambda r: (r.file_path, r.line, r.origin, r.evidence))


# --------------------------------------------------------------------------
# The comparison
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Omission:
    """An origin the code loads that the policy does not permit."""

    origin: str
    directive: str
    governing_directive: str
    permitted_sources: str
    references: tuple[Reference, ...]

    rule_id = "mykronos-csp/origin-not-permitted"


@dataclass(frozen=True)
class UnusedAllowance:
    """A named origin in the policy that nothing under the scanned paths loads.

    `verdict` says how weak the claim is:

    * `unreferenced` — the origin appears nowhere at all.
    * `ungoverned-only` — it appears, but only in ways CSP does not govern
      (a link target, a `preconnect` hint). The allowance may still be dead.
    * `other-directive` — it is loaded, but under a different directive than
      the one permitting it here.
    """

    directive: str
    source: str
    verdict: str
    seen_as: tuple[str, ...] = ()

    rule_id = "mykronos-csp/allowance-unused"


@dataclass(frozen=True)
class WildcardedDirective:
    """A directive whose named origins cannot be evaluated, and why."""

    directive: str
    governing_directive: str
    wildcard: str
    named_sources: tuple[str, ...]

    rule_id = "mykronos-csp/directive-wildcarded"


@dataclass(frozen=True)
class Comparison:
    """Both directions of the join, plus what could not be evaluated."""

    policy: Policy
    scanned_paths: tuple[str, ...]
    references: tuple[Reference, ...]
    omissions: tuple[Omission, ...]
    unused: tuple[UnusedAllowance, ...]
    wildcarded: tuple[WildcardedDirective, ...]
    unclassified: tuple[Reference, ...] = field(default=())


def compare(
    references: list[Reference],
    policy: Policy,
    *,
    scanned_paths: tuple[str, ...] = (),
    self_origins: frozenset[str] = frozenset(),
) -> Comparison:
    """Join the two halves, in both directions.

    `self_origins` are the origins the application itself serves from, which
    is what `'self'` resolves to. A repository cannot know its own hostname,
    so an absolute URL back to the app looks external here unless the caller
    says otherwise.
    """
    governed = [r for r in references if r.governed]
    unclassified = tuple(r for r in references if r.evidence == "unclassified")

    wildcarded: list[WildcardedDirective] = []
    for directive in sorted(FALLBACK):
        wildcard = policy.is_wildcarded(directive)
        effective = policy.effective_sources(directive)
        if wildcard is None or effective is None:
            continue
        named = tuple(
            s for s in effective[1].split() if not _NON_ORIGIN_SOURCE.match(s) and s != wildcard
        )
        wildcarded.append(
            WildcardedDirective(
                directive=directive,
                governing_directive=effective[0],
                wildcard=wildcard,
                named_sources=named,
            )
        )
    by_origin: dict[tuple[str, str], list[Reference]] = defaultdict(list)
    for reference in governed:
        assert reference.directive is not None
        by_origin[(reference.origin, reference.directive)].append(reference)

    omissions: list[Omission] = []
    for (origin, directive), hits in sorted(by_origin.items()):
        effective = policy.effective_sources(directive)
        if effective is None:
            continue  # no directive in the chain restricts this load at all
        # A wildcarded directive is *not* skipped here. `https:` permits every
        # https host and still blocks `http://`, so letting the source grammar
        # decide keeps the one load such a directive really does block —
        # skipping the directive wholesale would swallow it.
        sources = effective[1].split()
        if origin in self_origins and "'self'" in sources:
            continue
        if any(source_matches(source, origin) for source in sources):
            continue
        omissions.append(
            Omission(
                origin=origin,
                directive=directive,
                governing_directive=effective[0],
                permitted_sources=effective[1],
                references=tuple(hits),
            )
        )

    referenced: dict[str, set[str | None]] = defaultdict(set)
    for reference in references:
        referenced[reference.origin].add(reference.directive)

    unused: list[UnusedAllowance] = []
    for directive, permitted in sorted(policy.directives.items()):
        if policy.is_wildcarded(directive):
            continue  # see WildcardedDirective — a named source there is moot
        for source in permitted:
            if _NON_ORIGIN_SOURCE.match(source):
                continue
            matching = {o: uses for o, uses in referenced.items() if source_matches(source, o)}
            if not matching:
                unused.append(UnusedAllowance(directive, source, "unreferenced"))
                continue
            uses = {use for used in matching.values() for use in used}
            if directive in uses:
                continue  # loaded under exactly this directive — in use
            if uses == {None}:
                unused.append(
                    UnusedAllowance(directive, source, "ungoverned-only", ("link target/hint",))
                )
            else:
                seen = tuple(sorted(u for u in uses if u))
                unused.append(UnusedAllowance(directive, source, "other-directive", seen))

    return Comparison(
        policy=policy,
        scanned_paths=scanned_paths,
        references=tuple(references),
        omissions=tuple(omissions),
        unused=tuple(unused),
        wildcarded=tuple(wildcarded),
        unclassified=unclassified,
    )


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

#: What the environment qualifier reads like in every message. Repeated on
#: each finding rather than stated once at the top of a report, because a
#: finding travels away from its report the moment it is ingested.
def _qualifier(policy: Policy) -> str:
    return f"policy read from {policy.read_from} (environment: {policy.environment})"


def _omission_message(omission: Omission, policy: Policy) -> str:
    first = omission.references[0]
    return (
        f"{omission.origin} is loaded under {omission.directive} "
        f"({first.evidence} at {first.file_path}:{first.line}) but "
        f"'{omission.governing_directive}' permits only: "
        f"{omission.permitted_sources}. The load is blocked at runtime — "
        f"{_qualifier(policy)}."
    )


_UNUSED_NOTE = {
    "unreferenced": "no reference to it was found at all under the scanned paths",
    "ungoverned-only": (
        "it appears only in ways CSP does not govern (a link target or a "
        "preconnect hint), so the allowance may still be dead"
    ),
    "other-directive": "it is loaded, but under a different directive",
}


def _unused_message(unused: UnusedAllowance, policy: Policy) -> str:
    note = _UNUSED_NOTE[unused.verdict]
    seen = f" (seen as: {', '.join(unused.seen_as)})" if unused.seen_as else ""
    return (
        f"{unused.directive} permits {unused.source}, and {note}{seen}. This is "
        f"an argument from absence over a static sweep, not proof the origin is "
        f"unreachable: a URL built at runtime or fetched by a third-party "
        f"stylesheet is invisible here. {_qualifier(policy)}."
    )


def _wildcard_message(wildcarded: WildcardedDirective, policy: Policy) -> str:
    return (
        f"{wildcarded.governing_directive} contains the scheme-source "
        f"'{wildcarded.wildcard}', which permits every host, so the "
        f"{len(wildcarded.named_sources)} origin(s) named beside it "
        f"({', '.join(wildcarded.named_sources) or 'none'}) neither grant nor "
        f"withhold anything. No omission can be reported under {wildcarded.directive} "
        f"and no allowance there can be called unused. {_qualifier(policy)}."
    )


def to_sarif(comparison: Comparison) -> dict[str, object]:
    """SARIF 2.1.0, for the shared `sarif_to_findings` converter (spec 04 §4).

    Severities are deliberately low. An unpermitted origin is a functional
    break, not a vulnerability, and an unused allowance is quieter still — but
    both belong in the operator's queue, because the person tightening a CSP
    is exactly the person who needs them.

    Only omissions carry a location. An unused allowance and a wildcarded
    directive are facts about the policy, and there is no line in the
    repository to point at; inventing one would be a fabricated location.
    """
    policy = comparison.policy
    rules = [
        {
            "id": "mykronos-csp/origin-not-permitted",
            "name": "Origin loaded but not permitted by the CSP",
            "shortDescription": {"text": "The app loads an origin the served policy omits."},
            "fullDescription": {
                "text": (
                    "A latent functional break: the page loads, the console is "
                    "clean, and the feature fails only when a user exercises it."
                )
            },
            "properties": {"security-severity": "3.0"},
        },
        {
            "id": "mykronos-csp/allowance-unused",
            "name": "CSP allowance with no observed use",
            "shortDescription": {"text": "The policy names an origin no code was seen to load."},
            "properties": {"security-severity": "1.0"},
        },
        {
            "id": "mykronos-csp/directive-wildcarded",
            "name": "Directive wildcarded, named origins unevaluable",
            "shortDescription": {
                "text": "A scheme-source permits every host, making named origins decorative."
            },
            "properties": {"security-severity": "1.0"},
        },
    ]

    results: list[dict[str, object]] = []
    for omission in comparison.omissions:
        results.append(
            {
                "ruleId": omission.rule_id,
                "level": "warning",
                "message": {"text": _omission_message(omission, policy)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": reference.file_path},
                            "region": {"startLine": reference.line},
                        }
                    }
                    for reference in omission.references
                ],
                "properties": {
                    "environment": policy.environment,
                    "policySource": policy.read_from,
                    "directive": omission.directive,
                },
            }
        )
    for unused in comparison.unused:
        results.append(
            {
                "ruleId": unused.rule_id,
                "level": "note",
                "message": {"text": _unused_message(unused, policy)},
                "properties": {
                    "environment": policy.environment,
                    "policySource": policy.read_from,
                    "directive": unused.directive,
                    "verdict": unused.verdict,
                    "scannedPaths": list(comparison.scanned_paths) or ["<repository root>"],
                },
            }
        )
    for wildcarded in comparison.wildcarded:
        results.append(
            {
                "ruleId": wildcarded.rule_id,
                "level": "note",
                "message": {"text": _wildcard_message(wildcarded, policy)},
                "properties": {
                    "environment": policy.environment,
                    "policySource": policy.read_from,
                    "directive": wildcarded.directive,
                },
            }
        )

    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mykronos-csp-origins",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/ToddGBenson/mykronos",
                        "rules": rules,
                    }
                },
                "properties": {
                    "environment": policy.environment,
                    "policySource": policy.read_from,
                    "policy": policy.raw,
                    "scannedPaths": list(comparison.scanned_paths) or ["<repository root>"],
                    "governedReferences": sum(1 for r in comparison.references if r.governed),
                    "unclassifiedReferences": len(comparison.unclassified),
                },
                "results": results,
            }
        ],
    }


def format_report(comparison: Comparison) -> str:
    """The human report: what was measured, then both directions."""
    policy = comparison.policy
    paths = ", ".join(comparison.scanned_paths) or "<repository root>"
    governed = [r for r in comparison.references if r.governed]
    origins = {r.origin for r in comparison.references}
    lines = [
        "CSP origin comparison",
        "=" * 70,
        f"Environment : {policy.environment}",
        f"Policy read : {policy.read_from}",
        f"Paths read  : {paths}",
        (
            f"References  : {len(comparison.references)} across {len(origins)} origin(s) — "
            f"{len(governed)} governed by a directive, "
            f"{len(comparison.unclassified)} unclassified"
        ),
        "",
        f"USED BUT NOT PERMITTED ({len(comparison.omissions)}) — a latent runtime break",
        "-" * 70,
    ]
    if not comparison.omissions:
        lines.append("  none")
    for omission in comparison.omissions:
        lines.append(f"  {omission.origin}  [{omission.directive}]")
        lines.append(
            f"    permitted by '{omission.governing_directive}': {omission.permitted_sources}"
        )
        for reference in omission.references:
            lines.append(
                f"    {reference.file_path}:{reference.line}  {reference.evidence}  "
                f"{reference.snippet[:90]}"
            )

    lines += ["", f"PERMITTED BUT UNUSED ({len(comparison.unused)}) — a quieter signal", "-" * 70]
    if not comparison.unused:
        lines.append("  none")
    for unused in comparison.unused:
        seen = f"  (seen as: {', '.join(unused.seen_as)})" if unused.seen_as else ""
        lines.append(f"  {unused.directive}: {unused.source}  [{unused.verdict}]{seen}")

    lines += ["", f"NOT EVALUABLE ({len(comparison.wildcarded)}) — wildcarded directives", "-" * 70]
    if not comparison.wildcarded:
        lines.append("  none")
    for wildcarded in comparison.wildcarded:
        lines.append(
            f"  {wildcarded.directive} (via '{wildcarded.governing_directive}'): "
            f"'{wildcarded.wildcard}' permits every host; "
            f"{len(wildcarded.named_sources)} named origin(s) are decorative"
        )
        for source in wildcarded.named_sources:
            lines.append(f"    {source}")

    lines += [
        "",
        "-" * 70,
        (
            "An omission is positive evidence: a named line performs a governed "
            "load the policy has no source for. An unused allowance is an "
            "argument from absence over a static sweep of the paths above, and "
            "is weaker by construction."
        ),
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def read_policy_from_url(url: str, *, environment: str, timeout: float = 15.0) -> Policy:
    """Fetch a URL and parse its `Content-Security-Policy` response header.

    Raises if the header is absent rather than returning an empty policy: an
    empty policy would make every origin an omission and every allowance
    unused, which is a very loud way to report "I could not read it".
    """
    import httpx2

    with httpx2.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url)
    header = response.headers.get("content-security-policy")
    if not header:
        raise ValueError(
            f"{url} returned no Content-Security-Policy header (HTTP "
            f"{response.status_code}). There is nothing to compare against."
        )
    return parse_policy(header, environment=environment, read_from=url)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mykronos-csp-origins",
        description=(
            "Compare the external origins an application loads against the "
            "Content-Security-Policy one named environment serves (mykronos#290)."
        ),
    )
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        help=(
            "Narrow the sweep to this path, relative to --repo-root. Repeatable. "
            "Recorded with the result: 'unused' means 'unreferenced under these paths'."
        ),
    )
    parser.add_argument(
        "--environment",
        required=True,
        help=(
            "Which environment's policy this is — 'production', 'staging', 'demo'. "
            "Required, never defaulted: the estate's backends carry different "
            "policies and a finding that does not name one is unusable."
        ),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--policy-url", help="Fetch the policy from this URL's response header.")
    source.add_argument("--policy-file", type=Path, help="Read the header value from a file.")
    source.add_argument("--policy-header", help="The header value, given literally.")
    parser.add_argument(
        "--self-origin",
        action="append",
        default=[],
        help="An origin the app itself serves from, which is what 'self' permits. Repeatable.",
    )
    parser.add_argument("--output", type=Path, help="Write SARIF here.")
    parser.add_argument("--report", type=Path, help="Write the human report here as well.")
    args = parser.parse_args(argv)

    if args.policy_url:
        policy = read_policy_from_url(args.policy_url, environment=args.environment)
    elif args.policy_file:
        policy = parse_policy(
            args.policy_file.read_text(encoding="utf-8"),
            environment=args.environment,
            read_from=str(args.policy_file),
        )
    else:
        policy = parse_policy(
            args.policy_header, environment=args.environment, read_from="--policy-header"
        )

    paths = tuple(args.path)
    references = scan_repository(args.repo_root.resolve(), paths)
    comparison = compare(
        references,
        policy,
        scanned_paths=paths,
        self_origins=frozenset(args.self_origin),
    )

    report = format_report(comparison)
    print(report)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report + "\n", encoding="utf-8")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(to_sarif(comparison), indent=2), encoding="utf-8")

    # Exit 0 either way. This is a measurement, and an omission is a defect in
    # the application's policy, not in the build that measured it — a check
    # that reddens a pipeline on its first honest run is a check people turn
    # off. The findings carry the signal.
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
