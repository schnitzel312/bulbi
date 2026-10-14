"""Tests for spec validation."""

import pytest

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


def test_secret_hosts_key_is_ignored_with_a_warning():
    spec = _make_spec(secrets={"KEY": SecretSpec(from_source="env", hosts=["api.x"])})
    (warning,) = [w for w in validate_spec(spec).warnings if "secret" in w]
    assert "'hosts' is ignored until to = 'inject'" in warning
    assert validate_spec(_make_spec(secrets={"KEY": SecretSpec(from_source="env")})).ok


def test_errors_and_warnings_are_reported_in_rule_order():
    spec = _make_spec(
        tools=ToolsSpec(allow=["nonexistent", "python"]),
        mounts=[],
        secrets={"KEY": SecretSpec(from_source="vault", hosts=["a"])},
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


def test_profile_widening_network_default_is_an_error():
    spec = _make_spec(profiles={"open": ProfileSpec(network=NetworkSpec(default="allow"))})
    assert validate_spec(spec).errors == [
        "profile 'open' widens network default from 'deny' to 'allow'"
    ]


def test_secret_warning_does_not_claim_the_secret_is_protected():
    spec = _make_spec(secrets={"KEY": SecretSpec(from_source="env", hosts=["api.x"])})
    (warning,) = [w for w in validate_spec(spec).warnings if "secret" in w]
    assert "the agent can read this secret" in warning


@pytest.mark.parametrize("source", ["vault", ["env"], {"x": 1}, 7])
def test_unknown_secret_source_is_kept_for_the_rule_to_report(source):
    from bulbi.spec import SecretSource

    assert SecretSpec(from_source="env").from_source is SecretSource.ENV
    spec = _make_spec(secrets={"KEY": SecretSpec(from_source=source, hosts=["a"])})
    (error,) = validate_spec(spec).errors
    assert error.startswith("secret 'KEY': unknown from ")
    assert error.endswith("(use env, file, keychain, command)")


def test_non_string_secret_source_from_toml_is_a_validation_error(tmp_path):
    from bulbi.spec import SpecLoader

    (tmp_path / "bulbi.toml").write_text(
        'spec = "0.1"\n[box]\nname = "x"\n[secrets]\nK = { from = ["env"], hosts = ["a"] }\n'
    )
    result = validate_spec(SpecLoader().load(tmp_path))
    assert result.errors == [
        "secret 'K': unknown from '['env']' (use env, file, keychain, command)"
    ]


# ---- Network rules (sandbox isolation spec §5) ---------------------------------------


def _network(default="deny", allow=(), deny=()) -> NetworkSpec:
    return NetworkSpec(default=default, allow=list(allow), deny=list(deny))


def test_malformed_network_rules_are_errors():
    result = validate_spec(_make_spec(network=_network(allow=["pypi.org", "[::1"], deny=["x:0"])))
    assert len(result.errors) == 2
    assert result.errors[0].startswith("network.allow: invalid network rule '[::1'")
    assert result.errors[1].startswith("network.deny: invalid port '0'")


def test_deny_identical_to_allow_is_an_error():
    result = validate_spec(
        _make_spec(network=_network(allow=["PyPI.org:443"], deny=["pypi.org:443"]))
    )
    assert result.errors == ["network rule 'pypi.org:443' is both allowed and denied (deny wins)"]


def test_blacklist_mode_warns_best_effort_and_missing_denies():
    warnings = validate_spec(_make_spec(network=_network("allow"))).warnings
    assert any("best effort" in w for w in warnings)
    assert any("network.deny is empty" in w for w in warnings)
    warnings = validate_spec(_make_spec(network=_network("allow", deny=["x.com"]))).warnings
    assert not any("network.deny is empty" in w for w in warnings)


@pytest.mark.parametrize(
    ("rule", "warned"),
    [("10.20.0.0/16", True), ("192.168.1.0/24", False), ("fd00::/48", True), ("8.0.0.0/8", False)],
)
def test_wide_private_range_warning(rule, warned):
    warnings = validate_spec(_make_spec(network=_network(allow=[rule]))).warnings
    assert any("wide local/private range" in w for w in warnings) is warned


def test_host_without_port_warning():
    warnings = validate_spec(_make_spec(network=_network(allow=["host"]))).warnings
    assert any("allows every port on your machine" in w for w in warnings)
    warnings = validate_spec(_make_spec(network=_network(allow=["host:5432"]))).warnings
    assert not any("every port" in w for w in warnings)


# ---- Filesystem and box rules (spec §3.6, §8.3, §9.2) --------------------------------------


def _with_mounts(*paths: str) -> BulbiSpec:
    return _make_spec(mounts=[MountSpec(path=p) for p in paths])


def _fs_validate(spec, tmp_path, project=None):
    from bulbi.project import Project

    return SpecValidator.default(
        ToolRegistry.builtin(), project or Project.plain(tmp_path), home=tmp_path / "home"
    ).validate(spec)


def _socket_errors(tmp_path, path: str) -> list[str]:
    result = _fs_validate(_with_mounts(".", path), tmp_path)
    return [e for e in result.errors if "Docker socket" in e]


def test_docker_socket_mounts_are_errors(tmp_path):
    (tmp_path / "run").mkdir()
    (tmp_path / "run" / "docker.sock").write_text("")
    desktop = tmp_path / "home" / ".docker" / "run"
    desktop.mkdir(parents=True)
    (desktop / "docker.sock").write_text("")
    for path in ("/var/run/docker.sock", str(tmp_path / "run"), "~/.docker/run", "~/.docker", "~"):
        assert _socket_errors(tmp_path, path), path


def test_known_socket_locations_only_count_when_a_socket_exists(tmp_path):
    (tmp_path / "home" / ".docker" / "run").mkdir(parents=True)
    assert _socket_errors(tmp_path, "~/.docker") == []
    assert _socket_errors(tmp_path, "~") == []


def test_mounting_root_home_or_above_warns(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    for path in ("/", "~", str(tmp_path)):
        warnings = _fs_validate(_with_mounts(".", path), tmp_path).warnings
        assert any("whole home directory" in w for w in warnings), path
    assert not any(
        "whole home" in w for w in _fs_validate(_with_mounts("~/docs"), tmp_path).warnings
    )


def test_worktree_dirs_must_only_hold_worktrees(tmp_path):
    from bulbi.project import ProjectLocator
    from bulbi.spec import ProjectSpec
    from tests.repos import add_worktree, make_repo

    repo = make_repo(tmp_path / "app")
    add_worktree(repo, tmp_path / "trees" / "a", "a")
    project = ProjectLocator().locate(repo)
    good = _make_spec(project=ProjectSpec(worktree_dirs=[str(tmp_path / "trees")]))
    assert _fs_validate(good, tmp_path, project).ok
    (tmp_path / "trees" / "notes").mkdir()
    errors = _fs_validate(good, tmp_path, project).errors
    trees = tmp_path / "trees"
    assert errors == [
        f"project.worktree_dirs entry '{trees}' must contain only worktrees of this repository"
    ]


@pytest.mark.parametrize(
    ("value", "seconds"), [("0", 0), ("90s", 90), ("10m", 600), ("2h", 7200), ("15", 15)]
)
def test_idle_timeout_values(value, seconds):
    assert BoxSpec(name="x", idle_timeout=value).idle_timeout_seconds() == seconds
    assert validate_spec(_make_spec(box=BoxSpec(name="x", idle_timeout=value))).ok


def test_malformed_idle_timeout_is_an_error():
    result = validate_spec(_make_spec(box=BoxSpec(name="x", idle_timeout="soon")))
    assert result.errors == [
        "box.idle_timeout must look like '0', '30s', '10m' or '1h', got 'soon'"
    ]
