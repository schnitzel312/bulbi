"""Rules about ``[secrets]`` (spec §10.1)."""

from __future__ import annotations

from collections.abc import Iterator

from bulbi.constants import CONTAINER_HOME
from bulbi.secrets.delivery import box_path
from bulbi.spec import BulbiSpec, SecretSource, SecretTarget
from bulbi.validation.base import ValidationIssue, ValidationRule


def _choices(enum_type: type[SecretSource] | type[SecretTarget]) -> str:
    return ", ".join(member.value for member in enum_type)


class SecretSourceRule(ValidationRule):
    """``from`` must name a supported host source."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        for name, secret in spec.secrets.items():
            if secret.from_source is None:
                yield ValidationIssue.error(
                    f"secret '{name}': 'from' is required ({_choices(SecretSource)})"
                )
            elif not isinstance(secret.from_source, SecretSource):
                yield ValidationIssue.error(
                    f"secret '{name}': unknown from '{secret.from_source}' "
                    f"(use {_choices(SecretSource)})"
                )


class SecretTargetRule(ValidationRule):
    """``to`` must be a supported delivery; files need a ``path`` inside the box home."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        for name, secret in spec.secrets.items():
            if not isinstance(secret.to, SecretTarget):
                yield ValidationIssue.error(
                    f"secret '{name}': unknown to '{secret.to}' (use {_choices(SecretTarget)})"
                )
            elif secret.to is SecretTarget.FILE:
                yield from self._check_path(name, secret.path)

    @staticmethod
    def _check_path(name: str, path: str | None) -> Iterator[ValidationIssue]:
        if not path:
            yield ValidationIssue.error(f"secret '{name}': to = 'file' needs a 'path'")
            return
        target = box_path(path)
        inside_home = target.startswith(f"{CONTAINER_HOME}/") and "/../" not in f"{target}/"
        if not inside_home:
            yield ValidationIssue.error(
                f"secret '{name}': path '{path}' must be inside the box user's home (~/...)"
            )


class SecretHostsRule(ValidationRule):
    """``hosts`` belongs to the future ``to = "inject"`` delivery and is ignored for now."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        for name, secret in spec.secrets.items():
            if secret.hosts:
                yield ValidationIssue.warning(
                    f"secret '{name}': 'hosts' is ignored until to = 'inject' is supported; "
                    "the agent can read this secret and send it to any allowed destination"
                )
