# Bulbi

CLI tool that runs coding agents (Claude Code, Codex) inside isolated Docker containers with spec-driven configuration (`bulbi.toml`).

## Commands

```bash
# Dev setup
pip install -e ".[dev]"         # or: pip install -e .

# Run tests (44 tests, ~2s)
.venv/bin/pytest tests/ -x -q

# Lint
ruff check src/ tests/
ruff format --check src/ tests/

# Run the CLI locally
bulbi run                       # starts agent in sandbox
bulbi shell                     # interactive shell in sandbox
bulbi check                     # validate bulbi.toml
bulbi init                      # generate starter spec
```

## Architecture

All source lives in `src/bulbi/`. Key module responsibilities:

- `spec.py` — Parses `bulbi.toml` into dataclasses. Pure data, no side effects.
- `agents.py` — Agent runtime configs (install commands, env vars, domains, credentials). Single source of truth for agent-specific behavior.
- `constants.py` — Shared constants (paths, labels, defaults). All hardcoded values live here.
- `tools.py` — Tool registry mapping tool names to apt packages and post-install commands.
- `image.py` — Generates Dockerfiles from specs and builds images.
- `container.py` — Container lifecycle (start, exec, stop) and agent config injection.
- `proxy.py` — HTTP/HTTPS allowlist proxy that enforces `network.allow` rules.
- `cli.py` — Click CLI entry point. Uses `_run_in_sandbox()` shared helper for `run`/`shell`.
- `init.py` — Project auto-detection and starter spec generation.
- `validate.py` — Spec validation and diagnostics.
- `log.py` — Proxy audit log utilities.

## Code conventions

- Python 3.11+, `from __future__ import annotations` in every module.
- Frozen dataclasses for all data models.
- No hardcoded strings — use `constants.py`.
- Agent-specific config belongs in `agents.py`, not scattered across modules.
- `tools.py` exposes `available_tools()` as public API — never import `_TOOL_TABLE` directly.
- Network allowlists are configured only in `bulbi.toml`, never hardcoded in source.
- Ruff for linting/formatting, line length 99.

## Testing

- Tests use `pytest` with no external fixtures or mocks of Docker.
- Test files mirror source: `test_spec.py`, `test_tools.py`, `test_validate.py`, `test_init.py`, `test_proxy.py`.
- `.env` is excluded from git — never commit it.
