"""GitHub App integration (spec 02).

`GitHubClient` is a protocol, not a class, with two implementations: a real
one over the REST API and a fake that keeps repo state in memory. Everything
upstream — the Workflow Installer, onboarding, the reconciliation jobs —
depends only on the protocol.

That is not test scaffolding for its own sake. It means installer logic
(path-collision detection, idempotent PR updates, capability diffing) is
exercised against real assertions without a network, a registered App, or a
scratch repo, and the live client becomes configuration rather than a
rewrite.
"""

from mykronos.github.auth import AppCredentials, InstallationTokenCache
from mykronos.github.client import (
    FakeGitHubClient,
    FileChange,
    GitHubClient,
    GitHubError,
    PullRequest,
    RestGitHubClient,
)
from mykronos.github.secrets import seal_secret

__all__ = [
    "AppCredentials",
    "FakeGitHubClient",
    "FileChange",
    "GitHubClient",
    "GitHubError",
    "InstallationTokenCache",
    "PullRequest",
    "RestGitHubClient",
    "seal_secret",
]
