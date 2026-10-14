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
from bulbi.validate import validate_spec


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
    spec = _make_spec(
        profiles={"bad": ProfileSpec(tools=ToolsSpec(allow=["curl"]))}
    )
    result = validate_spec(spec)
    assert not result.ok
    assert "not in root" in result.errors[0]


def test_secret_no_hosts_warning():
    spec = _make_spec(
        secrets={"KEY": SecretSpec(from_source="env", hosts=[])}
    )
    result = validate_spec(spec)
    assert any("no host restriction" in w for w in result.warnings)
