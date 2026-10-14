"""Tests for spec parsing, validation, and profile merging."""

from pathlib import Path
from textwrap import dedent

import pytest

from bulbi.spec import BulbiSpec, SpecError, load_spec, merge_profile


@pytest.fixture
def sample_toml(tmp_path: Path) -> Path:
    spec = dedent("""\
        spec = "0.1"

        [box]
        name = "test-project"
        agent = "claude"

        [tools]
        allow = ["python@3.12", "git", "rg"]

        [setup]
        run = ["pip install -e ."]

        [[mount]]
        path = "."
        mode = "read-write"
        exclude = [".env"]

        [[mount]]
        path = "~/docs"
        mode = "read-only"

        [network]
        default = "deny"
        allow = ["pypi.org", "files.pythonhosted.org"]

        [secrets]
        API_KEY = { from = "env", hosts = ["api.example.com"] }

        [limits]
        cpu = 2
        memory = "4GB"

        [profiles.reviewer]
        mounts = { "." = "read-only" }
        network.allow = []

        [profiles.test-runner]
        tools.allow = ["python@3.12"]
    """)
    (tmp_path / "bulbi.toml").write_text(spec)
    return tmp_path


def test_load_spec(sample_toml: Path):
    spec = load_spec(sample_toml)
    assert spec.box.name == "test-project"
    assert spec.box.agent == "claude"
    assert spec.tools.allow == ["python@3.12", "git", "rg"]
    assert spec.setup.run == ["pip install -e ."]
    assert len(spec.mounts) == 2
    assert spec.mounts[0].path == "."
    assert spec.mounts[0].mode == "read-write"
    assert spec.mounts[0].exclude == [".env"]
    assert spec.mounts[1].path == "~/docs"
    assert spec.mounts[1].mode == "read-only"
    assert spec.network.default == "deny"
    assert spec.network.allow == ["pypi.org", "files.pythonhosted.org"]
    assert "API_KEY" in spec.secrets
    assert spec.limits.cpu == 2
    assert spec.limits.memory == "4GB"
    assert "reviewer" in spec.profiles
    assert "test-runner" in spec.profiles


def test_network_allow(sample_toml: Path):
    spec = load_spec(sample_toml)
    assert "pypi.org" in spec.network.allow


def test_content_hash_stable(sample_toml: Path):
    spec = load_spec(sample_toml)
    assert spec.content_hash() == spec.content_hash()


def test_profile_narrows_tools(sample_toml: Path):
    spec = load_spec(sample_toml)
    narrowed = spec.resolve_profile("test-runner")
    assert narrowed.tools.allow == ["python@3.12"]


def test_profile_narrows_mounts(sample_toml: Path):
    spec = load_spec(sample_toml)
    narrowed = spec.resolve_profile("reviewer")
    dot_mount = next(m for m in narrowed.mounts if m.path == ".")
    assert dot_mount.mode == "read-only"


def test_profile_narrows_network(sample_toml: Path):
    spec = load_spec(sample_toml)
    narrowed = spec.resolve_profile("reviewer")
    assert narrowed.network.allow == []


def test_profile_cannot_widen_tools(sample_toml: Path):
    spec = load_spec(sample_toml)
    from bulbi.spec import ProfileSpec, ToolsSpec

    bad_profile = ProfileSpec(tools=ToolsSpec(allow=["python@3.12", "curl"]))
    with pytest.raises(SpecError, match="widens tools"):
        merge_profile(spec, bad_profile)


def test_profile_cannot_widen_network(sample_toml: Path):
    spec = load_spec(sample_toml)
    from bulbi.spec import NetworkSpec, ProfileSpec

    bad_profile = ProfileSpec(network=NetworkSpec(allow=["evil.com"]))
    with pytest.raises(SpecError, match="widens network"):
        merge_profile(spec, bad_profile)


def test_profile_cannot_widen_mounts(sample_toml: Path):
    spec = load_spec(sample_toml)
    from bulbi.spec import ProfileSpec

    # Try to make read-only mount writable
    bad_profile = ProfileSpec(mounts={"~/docs": "read-write"})
    with pytest.raises(SpecError, match="widens mount"):
        merge_profile(spec, bad_profile)


def test_unknown_profile(sample_toml: Path):
    spec = load_spec(sample_toml)
    with pytest.raises(SpecError, match="unknown profile"):
        spec.resolve_profile("nonexistent")


def test_missing_spec_file(tmp_path: Path):
    with pytest.raises(SpecError, match="no bulbi.toml"):
        load_spec(tmp_path)


def test_missing_box_name(tmp_path: Path):
    (tmp_path / "bulbi.toml").write_text(dedent("""\
        spec = "0.1"
        [box]
        agent = "claude"
        [tools]
        allow = ["git"]
    """))
    with pytest.raises(SpecError, match="box.name is required"):
        load_spec(tmp_path)


def test_invalid_mount_mode(tmp_path: Path):
    (tmp_path / "bulbi.toml").write_text(dedent("""\
        spec = "0.1"
        [box]
        name = "test"
        [tools]
        allow = ["git"]
        [[mount]]
        path = "."
        mode = "execute"
    """))
    with pytest.raises(SpecError, match="mount mode"):
        load_spec(tmp_path)


def test_pyproject_toml_fallback(tmp_path: Path):
    pyproject = dedent("""\
        [tool.bulbi]
        spec = "0.1"

        [tool.bulbi.box]
        name = "from-pyproject"

        [tool.bulbi.tools]
        allow = ["python@3.12"]
    """)
    (tmp_path / "pyproject.toml").write_text(pyproject)
    spec = load_spec(tmp_path)
    assert spec.box.name == "from-pyproject"
