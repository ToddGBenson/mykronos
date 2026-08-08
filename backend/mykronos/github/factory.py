"""Producing a GitHub client for a given installation (spec 02 §2).

An installation token is scoped to one installation, so clients are made per
installation rather than once globally. The token cache is shared across them
so a burst of work against several repos does not mint a token per call.

The factory is a Protocol for the same reason the client is: onboarding and
the installer depend on the interface, and tests substitute an in-memory
implementation without a network or a registered App.
"""

from __future__ import annotations

from typing import Protocol

from mykronos.github.auth import AppCredentials, InstallationTokenCache
from mykronos.github.client import FakeGitHubClient, GitHubClient, RestGitHubClient


class GitHubClientFactory(Protocol):
    def for_installation(self, installation_id: int) -> GitHubClient: ...


class RestGitHubClientFactory:
    """The live factory. Requires a registered App (spec 02 §4)."""

    def __init__(self, credentials: AppCredentials) -> None:
        self.credentials = credentials
        self.cache = InstallationTokenCache()

    def for_installation(self, installation_id: int) -> GitHubClient:
        return RestGitHubClient(self.credentials, installation_id, cache=self.cache)


class FakeGitHubClientFactory:
    """Hands out one shared in-memory client, whatever the installation.

    Also what runs when no App credentials are configured, so the platform
    boots and the onboarding UI is explorable before the App exists. Any
    operation that would really touch GitHub is visible in `client.calls`
    rather than silently doing nothing.
    """

    def __init__(self, client: FakeGitHubClient | None = None) -> None:
        self.client = client or FakeGitHubClient()

    def for_installation(self, installation_id: int) -> GitHubClient:
        return self.client
