"""Tests for agent definitions, the agent registry, and agent configuration hooks."""

import json
from pathlib import Path

import pytest

from bulbi.agents import (
    AgentRegistry,
    BoxContext,
    ClaudeAgent,
    CodexAgent,
    ExecResult,
    UnmanagedAgent,
)
from tests.fakes import FakeContainerHandle

HOME = "/home/bulbi"
PROJECT = "/Users/me/code/app"


@pytest.fixture
def host_home(tmp_path: Path) -> Path:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"theme": "dark"}))
    (tmp_path / ".claude.json").write_text(json.dumps({"numStartups": 3, "projects": {}}))
    return tmp_path


def test_registry_resolves_builtin_agents():
    registry = AgentRegistry.builtin()
    assert isinstance(registry.resolve("claude"), ClaudeAgent)
    assert isinstance(registry.resolve("codex"), CodexAgent)
    assert registry.names == ["claude", "codex"]


def test_registry_falls_back_to_unmanaged_agent():
    agent = AgentRegistry.builtin().resolve("aider")
    assert isinstance(agent, UnmanagedAgent)
    assert agent.launch_command == ("aider",)
    assert agent.install_commands == ()
    assert "aider" not in AgentRegistry.builtin().names


def test_custom_registry():
    registry = AgentRegistry([CodexAgent()])
    assert isinstance(registry.resolve("claude"), UnmanagedAgent)


def test_builtin_agent_launch_commands():
    assert ClaudeAgent().launch_command == ("claude", "--dangerously-skip-permissions")
    assert CodexAgent().launch_command == ("codex", "--full-auto")


def test_default_prepare_container_does_nothing():
    container = FakeContainerHandle()
    CodexAgent().prepare_container(container, BoxContext())
    assert container.commands == []


def test_claude_writes_settings_and_user_config(host_home: Path):
    container = FakeContainerHandle(
        {("claude", "--version"): ExecResult(0, "2.1.0 (Claude Code)\n")}
    )
    agent = ClaudeAgent(host_home=host_home)

    agent.prepare_container(container, BoxContext({"ANTHROPIC_API_KEY": "sk"}, (PROJECT,)))

    files = container.files
    settings = json.loads(files[f"{HOME}/.claude/settings.json"])
    assert settings == {"theme": "dark", "skipDangerousModePermissionPrompt": True}
    config = json.loads(files[f"{HOME}/.claude.json"])
    assert config["hasCompletedOnboarding"] is True
    assert config["numStartups"] == 9999
    assert config["lastReleaseNotesSeen"] == "2.1.0"
    assert config["projects"][PROJECT] == {"hasTrustDialogAccepted": True}


def test_claude_version_falls_back_to_host_config(tmp_path: Path):
    (tmp_path / ".claude.json").write_text(json.dumps({"lastReleaseNotesSeen": "1.0.0"}))
    container = FakeContainerHandle({("claude", "--version"): ExecResult(1, "not found")})
    ClaudeAgent(host_home=tmp_path).prepare_container(container, BoxContext())
    config = json.loads(container.files[f"{HOME}/.claude.json"])
    assert config["lastReleaseNotesSeen"] == "1.0.0"


def test_claude_tolerates_missing_or_malformed_host_config(tmp_path: Path):
    (tmp_path / ".claude.json").write_text("{not json")
    container = FakeContainerHandle()
    ClaudeAgent(host_home=tmp_path).prepare_container(container, BoxContext())
    config = json.loads(container.files[f"{HOME}/.claude.json"])
    assert config["lastReleaseNotesSeen"] == "99.99.99"


# ---- refresh() on attach (spec §8.2, §9.5) ------------------------------------------------

CLAUDE_JSON = f"{HOME}/.claude.json"


def test_refresh_trusts_a_new_worktree_keeping_everything_else(tmp_path: Path):
    existing = {"numStartups": 9999, "projects": {PROJECT: {"hasTrustDialogAccepted": True}}}
    container = FakeContainerHandle({("cat", CLAUDE_JSON): ExecResult(0, json.dumps(existing))})
    agent = ClaudeAgent(host_home=tmp_path)
    agent.refresh(container, BoxContext({}, (PROJECT, "/Users/me/wt/new")))
    config = json.loads(container.files[CLAUDE_JSON])
    assert config["numStartups"] == 9999
    assert config["projects"]["/Users/me/wt/new"] == {"hasTrustDialogAccepted": True}
    assert f"{HOME}/.claude/settings.json" not in container.files  # never rewritten on attach


def test_refresh_writes_nothing_when_everything_is_trusted(tmp_path: Path):
    existing = {"projects": {PROJECT: {"hasTrustDialogAccepted": True}}}
    container = FakeContainerHandle({("cat", CLAUDE_JSON): ExecResult(0, json.dumps(existing))})
    ClaudeAgent(host_home=tmp_path).refresh(
        container, BoxContext({"ANTHROPIC_API_KEY": "sk"}, (PROJECT,))
    )
    assert container.files == {}


def test_refresh_never_clobbers_a_half_written_config(tmp_path: Path):
    container = FakeContainerHandle({("cat", CLAUDE_JSON): ExecResult(0, '{"projects": {')})
    ClaudeAgent(host_home=tmp_path).refresh(
        container, BoxContext({"ANTHROPIC_API_KEY": "sk"}, (PROJECT,))
    )
    assert CLAUDE_JSON not in container.files


def test_default_refresh_does_nothing():
    container = FakeContainerHandle()
    CodexAgent().refresh(container, BoxContext())
    assert container.commands == [] and container.files == {}


# ---- built-in secrets (spec §10.2) ----------------------------------------------------------


def test_claude_declares_api_key_and_keychain_oauth_file():
    api_key, oauth = ClaudeAgent.secrets
    assert (api_key.name, api_key.source_kind, api_key.target, api_key.optional) == (
        "ANTHROPIC_API_KEY", "env", "env", True,
    )  # fmt: skip
    assert (oauth.source_kind, oauth.source, oauth.target, oauth.path) == (
        "keychain", "Claude Code-credentials", "file", "~/.claude/.credentials.json",
    )  # fmt: skip
    assert oauth.skip_if_present == ("ANTHROPIC_API_KEY",) and oauth.optional


def test_codex_declares_openai_api_key():
    (secret,) = CodexAgent.secrets
    assert (secret.name, secret.source_kind, secret.optional) == ("OPENAI_API_KEY", "env", True)


def test_claude_prepare_writes_no_credentials_itself(host_home: Path):
    container = FakeContainerHandle()
    ClaudeAgent(host_home=host_home).prepare_container(container, BoxContext())
    assert not any("credentials" in path for path in container.files)
