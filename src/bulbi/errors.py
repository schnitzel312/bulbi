"""Exception hierarchy for Bulbi.

Every error Bulbi raises deliberately derives from :class:`BulbiError`, so the CLI
can turn any of them into a clean user-facing message.
"""

from __future__ import annotations


class BulbiError(Exception):
    """Base class for all expected, user-facing Bulbi errors."""


class SpecError(BulbiError):
    """The sandbox spec is missing or invalid."""


class RuleError(SpecError):
    """A ``[network]`` allow or deny rule is malformed."""


class ToolError(BulbiError):
    """A tool reference is malformed, unknown, or pins an unsupported version."""


class AuditLogError(BulbiError):
    """The proxy audit log cannot be read."""


class SandboxError(BulbiError):
    """Building, starting, or managing a sandbox container failed."""
