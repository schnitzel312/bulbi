"""Tests for spec parsing, validation, and profile merging."""

from pathlib import Path
from textwrap import dedent

import pytest

from bulbi.errors import SpecError
from bulbi.spec import ProfileMerger, SpecLoader


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
    spec = SpecLoader().load(sample_toml)
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
    spec = SpecLoader().load(sample_toml)
    assert "pypi.org" in spec.network.allow


def test_content_hash_stable(sample_toml: Path):
    spec = SpecLoader().load(sample_toml)
    assert spec.content_hash() == spec.content_hash()


def test_profile_narrows_tools(sample_toml: Path):
    spec = SpecLoader().load(sample_toml)
    narrowed = ProfileMerger().resolve(spec, "test-runner")
    assert narrowed.tools.allow == ["python@3.12"]


def test_profile_narrows_mounts(sample_toml: Path):
    spec = SpecLoader().load(sample_toml)
    narrowed = ProfileMerger().resolve(spec, "reviewer")
    dot_mount = next(m for m in narrowed.mounts if m.path == ".")
    assert dot_mount.mode == "read-only"


def test_profile_narrows_network(sample_toml: Path):
    spec = SpecLoader().load(sample_toml)
    narrowed = ProfileMerger().resolve(spec, "reviewer")
    assert narrowed.network.allow == []


def test_profile_cannot_widen_tools(sample_toml: Path):
    spec = SpecLoader().load(sample_toml)
    from bulbi.spec import ProfileSpec, ToolsSpec

    bad_profile = ProfileSpec(tools=ToolsSpec(allow=["python@3.12", "curl"]))
    with pytest.raises(SpecError, match="widens tools"):
        ProfileMerger().merge(spec, bad_profile)


def test_profile_cannot_widen_network(sample_toml: Path):
    spec = SpecLoader().load(sample_toml)
    from bulbi.spec import NetworkSpec, ProfileSpec

    bad_profile = ProfileSpec(network=NetworkSpec(allow=["evil.com"]))
    with pytest.raises(SpecError, match="widens network"):
        ProfileMerger().merge(spec, bad_profile)


def test_profile_cannot_widen_mounts(sample_toml: Path):
    spec = SpecLoader().load(sample_toml)
    from bulbi.spec import ProfileSpec

    # Try to make read-only mount writable
    bad_profile = ProfileSpec(mounts={"~/docs": "read-write"})
    with pytest.raises(SpecError, match="widens mount"):
        ProfileMerger().merge(spec, bad_profile)


def test_unknown_profile(sample_toml: Path):
    spec = SpecLoader().load(sample_toml)
    with pytest.raises(SpecError, match="unknown profile"):
        ProfileMerger().resolve(spec, "nonexistent")


def test_missing_spec_file(tmp_path: Path):
    with pytest.raises(SpecError, match="no bulbi.toml"):
        SpecLoader().load(tmp_path)


def test_missing_box_name(tmp_path: Path):
    (tmp_path / "bulbi.toml").write_text(
        dedent("""\
        spec = "0.1"
        [box]
        agent = "claude"
        [tools]
        allow = ["git"]
    """)
    )
    with pytest.raises(SpecError, match="box.name is required"):
        SpecLoader().load(tmp_path)


def test_invalid_mount_mode(tmp_path: Path):
    (tmp_path / "bulbi.toml").write_text(
        dedent("""\
        spec = "0.1"
        [box]
        name = "test"
        [tools]
        allow = ["git"]
        [[mount]]
        path = "."
        mode = "execute"
    """)
    )
    with pytest.raises(SpecError, match="mount mode"):
        SpecLoader().load(tmp_path)


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
    spec = SpecLoader().load(tmp_path)
    assert spec.box.name == "from-pyproject"


def _minimal_spec_toml(name: str) -> str:
    return f'spec = "0.1"\n[box]\nname = "{name}"\n'


def test_bulbi_toml_takes_precedence_over_pyproject(tmp_path: Path):
    (tmp_path / "bulbi.toml").write_text(_minimal_spec_toml("from-bulbi-toml"))
    (tmp_path / "pyproject.toml").write_text(
        '[tool.bulbi]\nspec = "0.1"\n[tool.bulbi.box]\nname = "from-pyproject"\n'
    )
    assert SpecLoader().load(tmp_path).box.name == "from-bulbi-toml"


def test_pyproject_without_bulbi_table_is_not_a_spec(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    with pytest.raises(SpecError, match="no bulbi.toml"):
        SpecLoader().load(tmp_path)


def test_invalid_toml_raises_spec_error(tmp_path: Path):
    (tmp_path / "bulbi.toml").write_text("this is = = not toml")
    with pytest.raises(SpecError, match="invalid TOML"):
        SpecLoader().load(tmp_path)


def test_parser_accepts_single_setup_command_string():
    from bulbi.spec import SpecParser

    spec = SpecParser().parse({"box": {"name": "x"}, "setup": {"run": "make"}})
    assert spec.setup.run == ["make"]


def test_parser_rejects_unsupported_version():
    from bulbi.spec import SpecParser

    with pytest.raises(SpecError, match="unsupported spec version"):
        SpecParser().parse({"spec": "9.9", "box": {"name": "x"}})


def test_parser_rejects_invalid_network_default():
    from bulbi.spec import SpecParser

    with pytest.raises(SpecError, match="network.default must be 'deny' or 'allow'"):
        SpecParser().parse({"box": {"name": "x"}, "network": {"default": "maybe"}})


def test_parser_requires_mount_path():
    from bulbi.spec import SpecParser

    with pytest.raises(SpecError, match="mount.path is required"):
        SpecParser().parse({"box": {"name": "x"}, "mount": [{"mode": "read-only"}]})


def test_profile_cannot_add_mount(sample_toml: Path):
    from bulbi.spec import ProfileSpec

    spec = SpecLoader().load(sample_toml)
    with pytest.raises(SpecError, match="adds mount '/etc' not in root"):
        ProfileMerger().merge(spec, ProfileSpec(mounts={"/etc": "read-only"}))


def test_profile_rejects_invalid_mount_mode(sample_toml: Path):
    from bulbi.spec import ProfileSpec

    spec = SpecLoader().load(sample_toml)
    with pytest.raises(SpecError, match="invalid mount mode 'execute'"):
        ProfileMerger().merge(spec, ProfileSpec(mounts={".": "execute"}))


def test_profile_violations_reports_every_widening(sample_toml: Path):
    from bulbi.spec import NetworkSpec, ProfileSpec, ToolsSpec

    spec = SpecLoader().load(sample_toml)
    profile = ProfileSpec(
        tools=ToolsSpec(allow=["curl"]),
        network=NetworkSpec(allow=["evil.com"]),
        mounts={"~/docs": "read-write"},
    )
    assert list(ProfileMerger().violations(spec, profile)) == [
        "widens tools: ['curl'] not in root",
        "widens network: ['evil.com'] not in root",
        "widens mount '~/docs' from read-only to read-write",
    ]


def test_merge_keeps_unrelated_sections(sample_toml: Path):
    spec = SpecLoader().load(sample_toml)
    narrowed = ProfileMerger().resolve(spec, "test-runner")
    assert narrowed.network == spec.network
    assert narrowed.mounts == spec.mounts
    assert narrowed.box == spec.box


@pytest.mark.parametrize(
    ("memory", "expected"),
    [("4GB", 4 * 1024**3), ("512mb", 512 * 1024**2), ("1.5 KB", 1536), ("10B", 10)],
)
def test_memory_bytes(memory: str, expected: int):
    from bulbi.spec import LimitsSpec

    assert LimitsSpec(memory=memory).memory_bytes == expected


def test_memory_bytes_rejects_unknown_units():
    from bulbi.spec import LimitsSpec

    with pytest.raises(SpecError, match="invalid memory string"):
        LimitsSpec(memory="4 gigs").memory_bytes  # noqa: B018
