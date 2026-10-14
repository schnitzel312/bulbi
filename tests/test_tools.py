"""Tests for tool parsing and resolution."""

import pytest

from bulbi.errors import ToolError
from bulbi.tools import ToolDefinition, ToolInstaller, ToolRegistry

registry = ToolRegistry.builtin()


def test_parse_simple():
    assert registry.parse("git") == ("git", None)


def test_parse_with_version():
    assert registry.parse("python@3.12") == ("python", "3.12")


def test_parse_invalid():
    with pytest.raises(ToolError, match="invalid tool spec"):
        registry.parse("123bad")


def test_resolve_git():
    tool = registry.resolve("git")
    assert tool.name == "git"
    assert "git" in tool.packages
    assert tool.verify_cmd == "git --version"


def test_resolve_python_with_version():
    tool = registry.resolve("python@3.12")
    assert tool.name == "python"
    assert tool.version == "3.12"
    assert "python3" in tool.packages


def test_resolve_python_default_version():
    tool = registry.resolve("python")
    assert tool.version == "3.12"  # default


def test_resolve_unknown_tool():
    with pytest.raises(ToolError, match="unknown tool"):
        registry.resolve("doesnotexist")


def test_resolve_bad_version():
    with pytest.raises(ToolError, match="unsupported version"):
        registry.resolve("python@2.7")


def test_resolve_all_deduplicates():
    tools = registry.resolve_all(["python@3.12", "git", "rg"])
    assert len(tools) == 3
    names = [t.name for t in tools]
    assert names == ["python", "git", "rg"]


def test_tool_without_allowed_versions_accepts_any_pin():
    assert registry.resolve("go@1.21").version == "1.21"


def test_tool_without_default_version_has_none():
    assert registry.resolve("git").version is None


def test_names_are_sorted():
    assert registry.names == sorted(registry.names)
    assert "python" in registry.names


def test_custom_registry_only_knows_its_definitions():
    custom = ToolRegistry([ToolDefinition(name="zig", packages=("zig",), verify_cmd="zig")])
    assert custom.resolve("zig").packages == ["zig"]
    with pytest.raises(ToolError, match="Available: zig"):
        custom.resolve("git")


class _PinnedInstaller(ToolInstaller):
    def system_packages(self, tool, version):
        return ("curl",)

    def install_commands(self, tool, version):
        return (f"install-{tool.name} {version}",)


def test_definition_installer_drives_resolution():
    definition = ToolDefinition(
        name="python",
        packages=("python3",),
        verify_cmd="python --version",
        default_version="3.12",
        installer=_PinnedInstaller(),
    )
    resolved = ToolRegistry([definition]).resolve("python")
    assert resolved.packages == ["curl"]
    assert resolved.post_install == ["install-python 3.12"]


def test_apt_installer_uses_definition_packages_and_post_install():
    resolved = registry.resolve("fd")
    assert resolved.packages == ["fd-find"]
    assert resolved.post_install == ["ln -sf /usr/bin/fdfind /usr/local/bin/fd"]
