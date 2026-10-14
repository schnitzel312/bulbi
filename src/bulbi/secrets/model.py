"""Secrets as Bulbi handles them: what to read on the host and how the box receives it."""

from __future__ import annotations

from dataclasses import dataclass, field

from bulbi.spec import SecretSource, SecretSpec, SecretTarget

REDACTED = "***"


@dataclass(frozen=True)
class SecretDeclaration:
    """One secret: a user's ``[secrets]`` entry or an agent's built-in credential.

    Attributes:
        name: The env var name in the box (``to = "env"``) and the key in reports.
        source_kind: Where the value is read on the host.
        source: Env var name, file path, keychain service or command line.
        target: How the box receives the value.
        path: File location in the box when ``target`` is ``file``.
        optional: A missing optional secret is skipped instead of failing the run.
        skip_if_present: Names of secrets whose presence makes this one unnecessary
            (e.g. Claude's OAuth file is not needed when an API key is set).
        builtin: Declared by the agent rather than the user.
    """

    name: str
    source_kind: SecretSource
    source: str
    target: SecretTarget = SecretTarget.ENV
    path: str | None = None
    optional: bool = False
    skip_if_present: tuple[str, ...] = ()
    builtin: bool = False

    @classmethod
    def from_spec(cls, name: str, spec: SecretSpec) -> SecretDeclaration:
        """A user declaration; the spec must already have passed validation."""
        assert isinstance(spec.from_source, SecretSource)
        assert isinstance(spec.to, SecretTarget)
        return cls(
            name=name,
            source_kind=spec.from_source,
            source=spec.source or name,
            target=spec.to,
            path=spec.path,
        )

    def describe_source(self) -> str:
        return f"{self.source_kind}: {self.source}"

    def describe_target(self) -> str:
        return f"file {self.path}" if self.target is SecretTarget.FILE else f"env ${self.name}"


@dataclass(frozen=True)
class ResolvedSecret:
    """A declaration with its current value. The value never appears in any repr."""

    declaration: SecretDeclaration
    value: str = field(repr=False)

    def __repr__(self) -> str:
        return f"ResolvedSecret({self.declaration.name}={REDACTED})"
