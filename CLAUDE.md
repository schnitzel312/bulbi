# Bulbi

CLI tool that runs coding agents (Claude Code, Codex) inside isolated Docker containers with spec-driven configuration (`bulbi.toml`).

## Commands

```bash
# Dev setup
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

# All four must pass before every commit
.venv/bin/pytest -q                        # ~220 tests, ~4s, no Docker needed
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src                         # strict, configured in pyproject.toml

# Run the CLI locally
bulbi init                      # generate starter spec
bulbi check                     # validate bulbi.toml and show what the box can do
bulbi run [-p PROFILE] [-- CMD] # run the agent (or CMD) in the sandbox; use `--` before CMD flags
bulbi shell [-p PROFILE]        # interactive shell in the sandbox
bulbi log [--denied]            # proxy audit log
bulbi ls | rm ID | reset        # manage bulbi containers/images
```

## Architecture

All source lives in `src/bulbi/`, grouped by concern. Each extension point is an ABC with one subclass per variant, registered in a single place.

```
errors.py      BulbiError -> SpecError, ToolError, AuditLogError, SandboxError
constants.py   cross-cutting values (container paths, Docker labels, defaults)
docker_sdk.py  lazy Docker SDK import + error wrapping (shared by image/ and container/)
spec/          models.py (frozen dataclasses + StrEnums), parser.py (SpecParser),
               loader.py (SpecSource ABC: BulbiTomlSource, PyprojectSource), profiles.py (ProfileMerger)
tools/         catalog.py (BUILTIN_TOOLS data), registry.py (ToolRegistry: parse/resolve/version check),
               installers.py (ToolInstaller ABC -> AptInstaller)
agents/        base.py (Agent ABC), claude.py, codex.py, credentials.py (CredentialProvider ABC),
               ports.py (ContainerHandle ABC that agents depend on), registry.py (AgentRegistry)
detection/     base.py (ProjectDetector ABC), python/node/rust/go.py, registry.py, starter_spec.py
validation/    base.py (ValidationRule ABC, ValidationResult), rules/*.py (one rule per concern), validator.py
image/         dockerfile.py (DockerfileBuilder), entrypoint.py, builder.py (ImageBuilder)
container/     handle.py (DockerContainerHandle), mounts.py (MountPlanner), environment.py,
               terminal.py (`docker exec` CLI for interactive runs), manager.py (BoxManager)
proxy/         policy.py (DomainPolicy ABC + policy_for), handler.py, server.py (ProxyServer), audit.py
sandbox/       session.py (SandboxSession: build -> proxy -> container -> prepare -> run -> teardown)
cli/           app.py (root group `main`, entry point `bulbi.cli:main`), context.py (AppContext,
               the composition root), commands/ (BulbiCommand ABC, one file per command), render/ (Rich output)
```

How a run works: `SandboxSession` builds the image once and starts the allowlist proxy. It then starts the container (`sleep infinity`), lets the `Agent` prepare it (files via `put_archive`) and runs the command with `docker exec`. Teardown happens in reverse via an `ExitStack`, even on failure or Ctrl-C.

### Extending

| To add… | Do this |
|---|---|
| Agent | Subclass `Agent` in `agents/<name>.py`; add it to `AgentRegistry.builtin()`. Put file injection in `prepare_container`. |
| Tool | Append a `ToolDefinition` to `tools/catalog.py`. For a custom install method, subclass `ToolInstaller`. |
| Project type for `init` | Subclass `ProjectDetector` in `detection/`; add it to `DetectorRegistry.builtin()` (order = priority). |
| Validation check | Subclass `ValidationRule` in `validation/rules/`; add it to `SpecValidator.default()`. |
| CLI command | Subclass `BulbiCommand` (or `SandboxCommand`) in `cli/commands/`; add it to `COMMANDS`. |
| Network policy | Subclass `DomainPolicy`; select it in `policy_for`. |

Never branch on an agent, tool or language name outside its own class (no `if agent == "claude"`).

## Code conventions

- Python 3.11+, `from __future__ import annotations` in every module. Ruff (line length 99, rules E F I N W UP B SIM RUF PL) and strict mypy.
- SOLID: one responsibility per class/module; extend by adding a subclass and registering it, not by editing conditionals.
- Dependencies are injected (Docker client, subprocess runner, clock, host env, credential provider), wired in `cli/context.py`. Library code never creates its own Docker client.
- Frozen dataclasses for data models; spec enumerations are `StrEnum`s in `spec/models.py`.
- Cross-cutting constants live in `constants.py`; module-specific constants live at the top of their module. No magic strings.
- Agent-specific details (paths, keychain service, API key vars, domains) live only in that agent's class.
- User-facing failures raise a `BulbiError` subclass; `BulbiCommand` turns them into CLI errors. No bare `except Exception`.
- Network allow rules are enforced only from `bulbi.toml`. Agent/detector domains in source are just suggestions written into the starter spec.
- Mark known gaps with `TODO(bulbi):`.
- Security-sensitive code (`proxy/`, `container/mounts.py`, `agents/claude.py` credentials) needs a test that fails without the change.

## Testing

- One test file per package (`test_spec.py`, `test_tools.py`, `test_validation.py`, `test_agents.py`, `test_detection.py`, `test_image.py`, `test_container.py`, `test_container_handle.py`, `test_proxy.py`, `test_sandbox.py`, `test_cli.py`).
- No real Docker, keychain or internet in unit tests: use the hand-written fakes in `tests/fakes.py`. CLI tests go through `click.testing.CliRunner` with an injected `AppContext`.
- Proxy tests start real servers on localhost.
- `.env` is excluded from git; never commit it.
