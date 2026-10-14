"""Which secrets a box gets: agent built-ins plus user declarations (spec §10.2)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from bulbi.errors import BulbiError
from bulbi.secrets.model import ResolvedSecret, SecretDeclaration
from bulbi.secrets.sources import SecretReaders, SecretUnavailableError
from bulbi.spec import SecretSource, SecretSpec, SecretTarget


class SecretError(BulbiError):
    """A required secret is unavailable. Messages name the secret, never its value."""


@dataclass(frozen=True)
class SecretStatus:
    """For ``bulbi check``: a declaration and whether its value is available right now."""

    declaration: SecretDeclaration
    available: bool | None  # None: not probed (resolved at ``bulbi run``)
    problem: str | None = None


class SecretPlan:
    """Merges declarations (user entries override built-ins by name) and resolves them."""

    def __init__(
        self, builtins: Iterable[SecretDeclaration], declared: Iterable[SecretDeclaration]
    ) -> None:
        merged: dict[str, SecretDeclaration] = {d.name: d for d in builtins}
        merged.update({d.name: d for d in declared})
        self.declarations = tuple(merged.values())

    def resolve(self, readers: SecretReaders) -> list[ResolvedSecret]:
        """Read every value; raise :class:`SecretError` for a missing required one."""
        values: dict[str, ResolvedSecret] = {}
        for declaration in self.declarations:
            try:
                value = readers.read(declaration.source_kind, declaration.source)
            except SecretUnavailableError as exc:
                if declaration.optional:
                    continue
                raise SecretError(
                    f"secret {declaration.name} ({declaration.describe_source()}) is "
                    f"unavailable: {exc}"
                ) from None
            values[declaration.name] = ResolvedSecret(declaration, value)
        return [
            secret
            for secret in values.values()
            if not any(name in values for name in secret.declaration.skip_if_present)
        ]

    def statuses(self, readers: SecretReaders, *, probe_all: bool = False) -> list[SecretStatus]:
        """Availability of each secret, without reading sources that are unsafe to probe
        (commands, keychain) unless ``probe_all``."""
        statuses = []
        for declaration in self.declarations:
            if not probe_all and not readers.safe_to_probe(declaration.source_kind):
                statuses.append(SecretStatus(declaration, available=None))
                continue
            try:
                readers.read(declaration.source_kind, declaration.source)
            except SecretUnavailableError as exc:
                statuses.append(SecretStatus(declaration, available=False, problem=str(exc)))
            else:
                statuses.append(SecretStatus(declaration, available=True))
        return statuses


def user_declarations(secrets: Mapping[str, SecretSpec]) -> list[SecretDeclaration]:
    """Declarations for the spec's well-formed ``[secrets]`` (validation reports the rest)."""
    return [
        SecretDeclaration.from_spec(name, spec)
        for name, spec in secrets.items()
        if isinstance(spec.from_source, SecretSource) and isinstance(spec.to, SecretTarget)
    ]
