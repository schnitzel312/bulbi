"""Tests for secrets (spec §10): parsing, validation, readers, plan, delivery, redaction."""

import subprocess
from pathlib import Path

import pytest

from bulbi.agents import ClaudeAgent, CodexAgent
from bulbi.errors import SandboxError
from bulbi.secrets import (
    CommandReader,
    EnvReader,
    FileReader,
    KeychainReader,
    ResolvedSecret,
    SecretDeclaration,
    SecretDeliveries,
    SecretError,
    SecretPlan,
    SecretReaders,
    SecretUnavailableError,
    user_declarations,
)
from bulbi.spec import SecretSource, SecretSpec, SecretTarget, SpecParser
from bulbi.tools import ToolRegistry
from bulbi.validation import SpecValidator
from tests.fakes import FakeContainerHandle

SECRET_VALUE = "s3cr3t-value-123"


def _parse(secrets_toml: dict) -> dict[str, SecretSpec]:
    return SpecParser().parse({"box": {"name": "x"}, "secrets": secrets_toml}).secrets


def _errors(secrets: dict) -> list[str]:
    spec = SpecParser().parse({"box": {"name": "x"}, "secrets": secrets})
    return SpecValidator.default(ToolRegistry.builtin()).validate(spec).errors


# ---- parsing (spec §10.1) ---------------------------------------------------------------------


def test_inline_tables_parse_with_defaults():
    import tomllib

    raw = tomllib.loads(
        "[secrets]\n"
        'GITHUB_TOKEN = { from = "env" }\n'
        'OPENAI_KEY   = { from = "env", source = "MY_OPENAI_KEY" }\n'
        'NPM_RC       = { from = "file", source = "~/.npmrc", to = "file", path = "~/.npmrc" }\n'
    )
    secrets = _parse(raw["secrets"])
    github = SecretDeclaration.from_spec("GITHUB_TOKEN", secrets["GITHUB_TOKEN"])
    assert (github.source_kind, github.source, github.target, github.path) == (
        SecretSource.ENV, "GITHUB_TOKEN", SecretTarget.ENV, None,
    )  # fmt: skip
    assert (
        SecretDeclaration.from_spec("OPENAI_KEY", secrets["OPENAI_KEY"]).source == "MY_OPENAI_KEY"
    )
    npm = secrets["NPM_RC"]
    assert (npm.from_source, npm.to, npm.path) == (
        SecretSource.FILE,
        SecretTarget.FILE,
        "~/.npmrc",
    )


def test_table_form_parses_to_the_same_data():
    import tomllib

    inline = tomllib.loads('[secrets]\nX = { from = "command", source = "op read y" }\n')
    tables = tomllib.loads('[secrets.X]\nfrom = "command"\nsource = "op read y"\n')
    assert _parse(inline["secrets"]) == _parse(tables["secrets"])


# ---- validation (spec §10.1) ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({}, "secret 'S': 'from' is required"),
        ({"from": "vault"}, "secret 'S': unknown from 'vault'"),
        ({"from": "env", "to": "inject"}, "secret 'S': unknown to 'inject' (use env, file)"),
        ({"from": "env", "to": "file"}, "secret 'S': to = 'file' needs a 'path'"),
        (
            {"from": "env", "to": "file", "path": "/etc/passwd"},
            "must be inside the box user's home",
        ),
        (
            {"from": "env", "to": "file", "path": "~/../root/x"},
            "must be inside the box user's home",
        ),
    ],
)
def test_every_validation_error(entry, message):
    (error,) = _errors({"S": entry})
    assert message in error


def test_valid_file_secret_paths():
    assert _errors({"S": {"from": "env", "to": "file", "path": "~/.config/x"}}) == []
    assert _errors({"S": {"from": "env", "to": "file", "path": "/home/bulbi/x"}}) == []


# ---- readers -------------------------------------------------------------------------------


def _completed(argv, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)


def test_env_reader():
    assert EnvReader({"A": "1"}).read("A") == "1"
    with pytest.raises(SecretUnavailableError, match="environment variable B is not set"):
        EnvReader({"B": ""}).read("B")


def test_file_reader_expands_home(tmp_path: Path):
    (tmp_path / ".npmrc").write_text("token")
    assert FileReader(home=tmp_path).read("~/.npmrc") == "token"
    with pytest.raises(SecretUnavailableError, match="cannot read ~/missing"):
        FileReader(home=tmp_path).read("~/missing")


def test_keychain_reader():
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return _completed(argv, stdout=SECRET_VALUE + "\n")

    assert KeychainReader(run, system="Darwin").read("svc") == SECRET_VALUE
    assert calls == [["security", "find-generic-password", "-s", "svc", "-w"]]
    missing = KeychainReader(lambda argv, **k: _completed(argv, 44), system="Darwin")
    with pytest.raises(SecretUnavailableError, match="no keychain item svc"):
        missing.read("svc")
    with pytest.raises(SecretUnavailableError, match="only available on macOS"):
        KeychainReader(run, system="Linux").read("svc")


def test_command_reader_runs_without_a_shell_and_trims():
    seen = {}

    def run(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return _completed(argv, stdout=f"  {SECRET_VALUE}\n")

    assert CommandReader(run).read("op read 'op://dev/npm token'") == SECRET_VALUE
    assert seen["argv"] == ["op", "read", "op://dev/npm token"]
    assert seen["timeout"] == 10 and "shell" not in seen


def test_command_reader_timeout_and_failures_never_echo_output():
    def timeout(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 10)

    with pytest.raises(SecretUnavailableError, match=r"`op` timed out after 10s"):
        CommandReader(timeout).read("op read x")
    failing = CommandReader(lambda argv, **k: _completed(argv, 1, SECRET_VALUE, SECRET_VALUE))
    with pytest.raises(SecretUnavailableError) as excinfo:
        failing.read("op read x")
    assert "exited with status 1" in str(excinfo.value)
    assert SECRET_VALUE not in str(excinfo.value)
    with pytest.raises(SecretUnavailableError, match="could not run"):
        CommandReader(
            lambda argv, **k: (_ for _ in ()).throw(FileNotFoundError(2, "No such file"))
        ).read("nope")
    with pytest.raises(SecretUnavailableError, match="printed nothing"):
        CommandReader(lambda argv, **k: _completed(argv, 0, "  \n")).read("true")


# ---- plan: built-ins, overrides, missing values -------------------------------------------


def _readers(env: dict[str, str], keychain: dict[str, str] | None = None) -> SecretReaders:
    class FakeKeychain(KeychainReader):
        def read(self, source):
            if source not in (keychain or {}):
                raise SecretUnavailableError(f"no keychain item {source}")
            return (keychain or {})[source]

    return SecretReaders({SecretSource.ENV: EnvReader(env), SecretSource.KEYCHAIN: FakeKeychain()})


def test_claude_uses_the_api_key_and_skips_oauth_when_both_exist():
    plan = SecretPlan(ClaudeAgent.secrets, [])
    readers = _readers({"ANTHROPIC_API_KEY": "sk"}, {"Claude Code-credentials": '{"t":1}'})
    assert [s.declaration.name for s in plan.resolve(readers)] == ["ANTHROPIC_API_KEY"]


def test_claude_falls_back_to_keychain_oauth_and_optional_secrets_are_skipped():
    plan = SecretPlan(ClaudeAgent.secrets, [])
    resolved = plan.resolve(_readers({}, {"Claude Code-credentials": '{"t":1}'}))
    assert [s.declaration.name for s in resolved] == ["CLAUDE_OAUTH"]
    assert plan.resolve(_readers({})) == []


def test_user_entry_overrides_the_builtin_with_the_same_name():
    user = user_declarations({"OPENAI_API_KEY": SecretSpec(from_source="env", source="MY_KEY")})
    plan = SecretPlan(CodexAgent.secrets, user)
    (secret,) = plan.resolve(_readers({"MY_KEY": "k", "OPENAI_API_KEY": "other"}))
    assert (secret.declaration.source, secret.value, secret.declaration.builtin) == (
        "MY_KEY",
        "k",
        False,
    )


def test_missing_user_secret_is_an_error_naming_it_and_its_source():
    plan = SecretPlan([], user_declarations({"GITHUB_TOKEN": SecretSpec(from_source="env")}))
    with pytest.raises(
        SecretError, match=r"secret GITHUB_TOKEN \(env: GITHUB_TOKEN\) is unavailable"
    ):
        plan.resolve(_readers({}))


def test_statuses_report_availability_without_values():
    plan = SecretPlan(CodexAgent.secrets, user_declarations({"X": SecretSpec(from_source="env")}))
    statuses = plan.statuses(_readers({"X": SECRET_VALUE}))
    assert [(s.declaration.name, s.available) for s in statuses] == [
        ("OPENAI_API_KEY", False), ("X", True),
    ]  # fmt: skip
    assert SECRET_VALUE not in repr(statuses)


def test_resolved_secret_repr_is_redacted():
    secret = ResolvedSecret(SecretDeclaration("X", SecretSource.ENV, "X"), SECRET_VALUE)
    assert SECRET_VALUE not in repr(secret) and SECRET_VALUE not in str(secret)
    assert SECRET_VALUE not in repr([secret])


# ---- delivery --------------------------------------------------------------------------------


def test_env_secrets_go_to_sessions_and_file_secrets_to_files():
    env_secret = ResolvedSecret(SecretDeclaration("TOKEN", SecretSource.ENV, "T"), "v1")
    file_secret = ResolvedSecret(
        SecretDeclaration("RC", SecretSource.FILE, "~/.npmrc", SecretTarget.FILE, "~/.npmrc"), "v2"
    )
    deliveries = SecretDeliveries.builtin()
    container = FakeContainerHandle()
    deliveries.write_files([env_secret, file_secret], container)
    assert container.files == {"/home/bulbi/.npmrc": "v2"}
    assert container.modes["/home/bulbi/.npmrc"] == 0o600
    assert deliveries.session_environment([env_secret, file_secret]) == {"TOKEN": "v1"}


def test_file_secret_without_path_is_refused():
    secret = ResolvedSecret(SecretDeclaration("RC", SecretSource.ENV, "X", SecretTarget.FILE), "v")
    with pytest.raises(SandboxError, match="RC has no path"):
        SecretDeliveries.builtin().write_files([secret], FakeContainerHandle())
