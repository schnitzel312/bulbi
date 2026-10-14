"""Rules about declared secrets."""

from __future__ import annotations

from collections.abc import Iterator

from bulbi.spec import BulbiSpec, SecretSource
from bulbi.validation.base import ValidationIssue, ValidationRule


class SecretSourceRule(ValidationRule):
    """Only environment-variable secrets are supported."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        supported = {source.value for source in SecretSource}
        for name, secret in spec.secrets.items():
            if secret.from_source not in supported:
                yield ValidationIssue.error(
                    f"secret '{name}': only 'env' source is supported in v1"
                )


class SecretHostsRule(ValidationRule):
    """Warn about secrets that are not restricted to specific hosts."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        for name, secret in spec.secrets.items():
            if not secret.hosts:
                yield ValidationIssue.warning(
                    f"secret '{name}' has no host restriction — "
                    "it will be available to all proxied requests"
                )
