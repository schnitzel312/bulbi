"""Tests for tool resolution."""

import pytest

from bulbi.tools import parse_tool_spec, resolve_tool, resolve_all


def test_parse_simple():
    assert parse_tool_spec("git") == ("git", None)


def test_parse_with_version():
    assert parse_tool_spec("python@3.12") == ("python", "3.12")


def test_parse_invalid():
    with pytest.raises(ValueError, match="invalid tool spec"):
        parse_tool_spec("123bad")


def test_resolve_git():
    tool = resolve_tool("git")
    assert tool.name == "git"
    assert "git" in tool.packages
    assert tool.verify_cmd == "git --version"


def test_resolve_python_with_version():
    tool = resolve_tool("python@3.12")
    assert tool.name == "python"
    assert tool.version == "3.12"
    assert "python3" in tool.packages


def test_resolve_python_default_version():
    tool = resolve_tool("python")
    assert tool.version == "3.12"  # default


def test_resolve_unknown_tool():
    with pytest.raises(ValueError, match="unknown tool"):
        resolve_tool("doesnotexist")


def test_resolve_bad_version():
    with pytest.raises(ValueError, match="unsupported version"):
        resolve_tool("python@2.7")


def test_resolve_all_deduplicates():
    tools = resolve_all(["python@3.12", "git", "rg"])
    assert len(tools) == 3
    names = [t.name for t in tools]
    assert names == ["python", "git", "rg"]
