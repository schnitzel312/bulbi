"""Tests for spec validation."""

from bulbi.spec import (
    BoxSpec,
    BulbiSpec,
    LimitsSpec,
    MountSpec,
    NetworkSpec,
    ProfileSpec,
    SecretSpec,
    SetupSpec,
    ToolsSpec,
)
from bulbi.tools import ToolRegistry
from bulbi.validation import SpecValidator

validate_spec = SpecValidator.default(ToolRegistry.builtin()).validate


def _make_spec(**overrides) -> BulbiSpec:
    defaults = {
        "spec_version": "0.1",
        "box": BoxSpec(name="test"),
        "tools": ToolsSpec(allow=["python@3.12", "git"]),
        "setup": SetupSpec(),
        "mounts": [MountSpec(path=".", mode="read-write")],
        "network": NetworkSpec(default="deny", allow=["pypi.org"]),
        "secrets": {},
        "limits": LimitsSpec(),
        "profiles": {},
    }
    defaults.update(overrides)
    return BulbiSpec(**defaults)


def test_valid_spec():
    result = validate_spec(_make_spec())
    assert result.ok


def test_unknown_tool():
    spec = _make_spec(tools=ToolsSpec(allow=["nonexistent"]))
    result = validate_spec(spec)
    assert not result.ok
    assert "unknown tool" in result.errors[0]


def test_bad_version():
    spec = _make_spec(tools=ToolsSpec(allow=["python@2.7"]))
    result = validate_spec(spec)
    assert not result.ok


def test_no_mounts_warning():
    spec = _make_spec(mounts=[])
    result = validate_spec(spec)
    assert any("no mounts" in w for w in result.warnings)


def test_all_readonly_warning():
    spec = _make_spec(mounts=[MountSpec(path=".", mode="read-only")])
    result = validate_spec(spec)
    assert any("read-only" in w for w in result.warnings)


def test_network_allow_all_warning():
    spec = _make_spec(network=NetworkSpec(default="allow"))
    result = validate_spec(spec)
    assert any("allow" in w for w in result.warnings)


def test_interpreter_warning():
    spec = _make_spec(tools=ToolsSpec(allow=["python@3.12"]))
    result = validate_spec(spec)
    assert any("interpreter" in w for w in result.warnings)


def test_profile_widens_tools():
    spec = _make_spec(profiles={"bad": ProfileSpec(tools=ToolsSpec(allow=["curl"]))})
    result = validate_spec(spec)
    assert not result.ok
    assert "not in root" in result.errors[0]


def test_secret_no_hosts_warning():
    spec = _make_spec(secrets={"KEY": SecretSpec(from_source="env", hosts=[])})
    result = validate_spec(spec)
    assert any("no host restriction" in w for w in result.warnings)


def test_errors_and_warnings_are_reported_in_rule_order():
    spec = _make_spec(
        tools=ToolsSpec(allow=["nonexistent", "python"]),
        mounts=[],
        secrets={"KEY": SecretSpec(from_source="vault", hosts=[])},
    )
    result = validate_spec(spec)
    assert [e.split(":")[0] for e in result.errors] == ["unknown tool", "secret 'KEY'"]
    assert [w.split(" ")[0] for w in result.warnings] == ["no", "secret", "interpreters"]


def test_invalid_tool_reference_is_an_error_not_a_crash():
    result = validate_spec(_make_spec(tools=ToolsSpec(allow=["123bad"])))
    assert result.errors == ["invalid tool spec: '123bad'"]


def test_empty_allowlist_warning():
    result = validate_spec(_make_spec(network=NetworkSpec(default="deny", allow=[])))
    assert any("allowlist is empty" in w for w in result.warnings)


def test_profile_widening_read_only_mount_is_an_error():
    spec = _make_spec(
        mounts=[MountSpec(path=".", mode="read-only")],
        profiles={"rw": ProfileSpec(mounts={".": "read-write"})},
    )
    result = validate_spec(spec)
    assert result.errors == ["profile 'rw' widens mount '.' from read-only to read-write"]


def test_profile_unknown_mount_and_domains_are_all_reported():
    spec = _make_spec(
        profiles={
            "bad": ProfileSpec(network=NetworkSpec(allow=["x.com"]), mounts={"/y": "read-only"})
        }
    )
    assert validate_spec(spec).errors == [
        "profile 'bad' widens network: ['x.com'] not in root",
        "profile 'bad' adds mount '/y' not in root",
    ]


def test_validator_runs_only_given_rules():
    from bulbi.validation import ValidationIssue, ValidationRule

    class AlwaysWarn(ValidationRule):
        def check(self, spec):
            yield ValidationIssue.warning(f"box {spec.box.name}")

    result = SpecValidator([AlwaysWarn()]).validate(_make_spec(mounts=[]))
    assert result.ok
    assert result.warnings == ["box test"]


def test_invalid_resource_limits_are_errors():
    result = validate_spec(_make_spec(limits=LimitsSpec(cpu=0, memory="lots")))
    assert result.errors == [
        "limits.cpu must be a positive integer, got 0",
        "limits.memory: invalid memory string: 'lots'",
    ]
