"""Tests for agent definitions, the agent registry, and credential providers."""

import json
import subprocess
from pathlib import Path

import pytest

from bulbi.agents import (
    AgentRegistry,
    ClaudeAgent,
    CodexAgent,
    ExecResult,
    KeychainCredentialProvider,
    NoCredentialProvider,
    UnmanagedAgent,
)
from tests.fakes import FakeContainerHandle, StaticCredentials

HOME = "/home/bulbi"


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


def test_api_keys_from_host_env_skips_unset_and_empty():
    agent = ClaudeAgent(credentials=NoCredentialProvider())
    assert agent.api_keys_from({"ANTHROPIC_API_KEY": "sk", "OTHER": "x"}) == {
        "ANTHROPIC_API_KEY": "sk"
    }
    assert agent.api_keys_from({"ANTHROPIC_API_KEY": ""}) == {}


def test_default_prepare_container_does_nothing():
    container = FakeContainerHandle()
    CodexAgent().prepare_container(container, {})
    assert container.commands == []


def test_claude_writes_settings_and_user_config(host_home: Path):
    container = FakeContainerHandle(
        {("claude", "--version"): ExecResult(0, "2.1.0 (Claude Code)\n")}
    )
    agent = ClaudeAgent(credentials=StaticCredentials(None), host_home=host_home)

    agent.prepare_container(container, {"ANTHROPIC_API_KEY": "sk"})

    files = container.files
    settings = json.loads(files[f"{HOME}/.claude/settings.json"])
    assert settings == {"theme": "dark", "skipDangerousModePermissionPrompt": True}
    config = json.loads(files[f"{HOME}/.claude.json"])
    assert config["hasCompletedOnboarding"] is True
    assert config["numStartups"] == 9999
    assert config["lastReleaseNotesSeen"] == "2.1.0"
    assert config["projects"][f"{HOME}/workspace"] == {"hasTrustDialogAccepted": True}


def test_claude_skips_credentials_when_api_key_is_forwarded(host_home: Path):
    credentials = StaticCredentials('{"token": "t"}')
    container = FakeContainerHandle()
    ClaudeAgent(credentials=credentials, host_home=host_home).prepare_container(
        container, {"ANTHROPIC_API_KEY": "sk"}
    )
    assert credentials.reads == 0
    assert f"{HOME}/.claude/.credentials.json" not in container.files


def test_claude_injects_credentials_with_private_mode(host_home: Path):
    container = FakeContainerHandle()
    ClaudeAgent(
        credentials=StaticCredentials('{"token": "t"}'), host_home=host_home
    ).prepare_container(container, {})
    target = f"{HOME}/.claude/.credentials.json"
    assert container.files[target] == '{"token": "t"}'
    assert container.modes[target] == 0o600


def test_claude_version_falls_back_to_host_config(tmp_path: Path):
    (tmp_path / ".claude.json").write_text(json.dumps({"lastReleaseNotesSeen": "1.0.0"}))
    container = FakeContainerHandle({("claude", "--version"): ExecResult(1, "not found")})
    ClaudeAgent(credentials=NoCredentialProvider(), host_home=tmp_path).prepare_container(
        container, {}
    )
    config = json.loads(container.files[f"{HOME}/.claude.json"])
    assert config["lastReleaseNotesSeen"] == "1.0.0"


def test_claude_tolerates_missing_or_malformed_host_config(tmp_path: Path):
    (tmp_path / ".claude.json").write_text("{not json")
    container = FakeContainerHandle()
    ClaudeAgent(credentials=NoCredentialProvider(), host_home=tmp_path).prepare_container(
        container, {}
    )
    config = json.loads(container.files[f"{HOME}/.claude.json"])
    assert config["lastReleaseNotesSeen"] == "99.99.99"


def _fake_security(returncode: int, stdout: str):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")

    return run, calls


def test_keychain_provider_returns_valid_json():
    run, calls = _fake_security(0, '{"a": 1}\n')
    assert KeychainCredentialProvider("svc", runner=run).read() == '{"a": 1}'
    assert calls == [["security", "find-generic-password", "-s", "svc", "-w"]]


@pytest.mark.parametrize(("returncode", "stdout"), [(44, ""), (0, "not json")])
def test_keychain_provider_returns_none_on_failure(returncode, stdout):
    run, _ = _fake_security(returncode, stdout)
    assert KeychainCredentialProvider("svc", runner=run).read() is None


def test_keychain_provider_handles_missing_binary():
    def run(argv, **kwargs):
        raise FileNotFoundError(argv[0])

    assert KeychainCredentialProvider("svc", runner=run).read() is None


def test_for_host_only_uses_keychain_on_macos():
    assert isinstance(
        KeychainCredentialProvider.for_host("svc", "Darwin"), KeychainCredentialProvider
    )
    assert isinstance(KeychainCredentialProvider.for_host("svc", "Linux"), NoCredentialProvider)
