"""Domain policies: which destinations the proxy lets through."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from bulbi.spec import NetworkDefault, NetworkSpec


class DomainPolicy(ABC):
    """Decides whether a request to a domain may leave the sandbox."""

    @abstractmethod
    def allows(self, domain: str) -> bool:
        """True if traffic to ``domain`` may be forwarded."""

    @staticmethod
    def for_network(network: NetworkSpec) -> DomainPolicy:
        """The policy implementing a spec's ``[network]`` section."""
        if network.default is NetworkDefault.ALLOW:
            return AllowAllPolicy()
        return AllowlistPolicy(network.allow)


class AllowlistPolicy(DomainPolicy):
    """Allows only the listed domains (exact match, no wildcards)."""

    def __init__(self, domains: Iterable[str]) -> None:
        self._domains = frozenset(domains)

    def allows(self, domain: str) -> bool:
        return domain in self._domains


class AllowAllPolicy(DomainPolicy):
    """Allows every domain (``network.default = "allow"``); requests are still audited."""

    def allows(self, domain: str) -> bool:
        return True
