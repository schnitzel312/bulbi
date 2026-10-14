"""Spec validation and diagnostic reporting."""

from __future__ import annotations

from dataclasses import dataclass, field

from bulbi.spec import BulbiSpec
from bulbi.tools import available_tools, parse_tool_spec


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0


def validate_spec(spec: BulbiSpec) -> ValidationResult:
    """Validate a parsed spec and return errors and warnings."""
    result = ValidationResult()
    tool_table = available_tools()

    # Check tools are known
    for tool_spec in spec.tools.allow:
        try:
            name, version = parse_tool_spec(tool_spec)
            if name not in tool_table:
                result.errors.append(
                    f"unknown tool '{name}'. "
                    f"Available: {', '.join(sorted(tool_table))}"
                )
            elif version:
                entry = tool_table[name]
                if "allowed_versions" in entry and version not in entry["allowed_versions"]:
                    result.errors.append(
                        f"unsupported version '{version}' for {name}. "
                        f"Available: {', '.join(entry['allowed_versions'])}"
                    )
        except ValueError as e:
            result.errors.append(str(e))

    # Check mounts
    if not spec.mounts:
        result.warnings.append("no mounts defined — the agent won't see any project files")

    has_rw_mount = any(m.mode == "read-write" for m in spec.mounts)
    if not has_rw_mount and spec.mounts:
        result.warnings.append("all mounts are read-only — the agent cannot write to any files")

    # Check network
    if spec.network.default == "allow":
        result.warnings.append(
            "network.default is 'allow' — the agent can reach any domain. "
            "Consider using 'deny' with an explicit allowlist"
        )

    if spec.network.default == "deny" and not spec.network.allow:
        result.warnings.append(
            "network denies all domains and allowlist is empty — "
            "the agent will have no network access"
        )

    # Check profiles don't reference unknown tools
    for pname, profile in spec.profiles.items():
        if profile.tools:
            extra = set(profile.tools.allow) - set(spec.tools.allow)
            if extra:
                result.errors.append(
                    f"profile '{pname}' allows tools not in root: {extra}"
                )
        if profile.network:
            extra_domains = set(profile.network.allow) - set(spec.network.allow)
            if extra_domains:
                result.errors.append(
                    f"profile '{pname}' allows domains not in root: {extra_domains}"
                )
        if profile.mounts:
            root_paths = {m.path for m in spec.mounts}
            for path in profile.mounts:
                if path not in root_paths:
                    result.errors.append(
                        f"profile '{pname}' references mount '{path}' not in root spec"
                    )

    # Check secrets
    for name, secret in spec.secrets.items():
        if secret.from_source != "env":
            result.errors.append(f"secret '{name}': only 'env' source is supported in v1")
        if not secret.hosts:
            result.warnings.append(
                f"secret '{name}' has no host restriction — "
                "it will be available to all proxied requests"
            )

    # Warn about powerful interpreters
    interpreter_tools = {"python", "node", "bun", "ruby"}
    allowed_names = {parse_tool_spec(t)[0] for t in spec.tools.allow}
    active_interpreters = interpreter_tools & allowed_names
    if active_interpreters:
        result.warnings.append(
            f"interpreters allowed ({', '.join(sorted(active_interpreters))}): "
            "these can open sockets and read mounted files. "
            "The network and mount rules are the real security boundary"
        )

    return result
