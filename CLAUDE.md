# Bulbi

Security-first sandbox for running AI coding CLIs (Claude Code, Codex, …) fully autonomously. The agent runs inside a Docker box whose file access, network egress, secrets and git access are defined by one `bulbi.toml`; the box, not the agent, is the trust boundary.

Product principles:
- **Secure by default:** the agent can do only what `bulbi.toml` allows.
- **No artificial limits:** never restrict by protocol. Any TCP/UDP traffic that policy allows must just work, using real hostnames and no proxy config.
- **Easy to configure:** keep configuration in `bulbi.toml` and keep it readable.

Design specs live in `docs/specs/`; read the relevant one before changing behaviour.

## Commands

```bash
# Dev setup
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

# All four must pass before every commit
.venv/bin/pytest -q                        # ~540 unit tests, ~8s, no Docker needed
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src                         # strict, configured in pyproject.toml

# Real-Docker suite (escape tests + git safety + lifecycle), ~6 min, needs Docker and internet.
# Required for changes to gateway/, container/, image/, sandbox/, gitsafety/ or mounts.
.venv/bin/pytest -m docker

# Run the CLI locally
bulbi init                      # generate starter spec
bulbi check [--probe-secrets]   # validate bulbi.toml, show effective policy; exits 1 on errors
bulbi run [-p PROFILE] [-- CMD] # attach to (or create) the project's box and run the agent or CMD
bulbi shell [-p PROFILE]        # interactive shell in the project's box
bulbi log [--denied]            # network audit log (DNS/TCP/UDP decisions with reason and rule)
bulbi ls                        # boxes, state and active sessions
bulbi stop | restart            # stop the project's box, or recreate it with the current spec
bulbi rm ID | reset             # remove a box, or every Bulbi container, network and image
bulbi git-scan [-p PROFILE]     # scan the checkouts for planted git metadata, apply [git] on_finding
bulbi git-restore [ID]          # list quarantine records, or put one back (and trust it)
bulbi pull [--branch B]         # isolated git mode: fetch the box's branches as bulbi/<branch> (bundle)
```

## Architecture

All source lives in `src/bulbi/`, grouped by concern. Each extension point is an ABC with one subclass per variant, registered in a single place.

```
errors.py      BulbiError -> SpecError, ToolError, AuditLogError, SandboxError, SecretError, GitSafetyError
constants.py   cross-cutting values (container paths, Docker labels, defaults)
paths.py       expand_home: the single `~` rule
docker_sdk.py  lazy Docker SDK import + error wrapping
spec/          models (frozen dataclasses + StrEnums), parser, loader (SpecSource ABC), profiles (ProfileMerger)
tools/         catalog (BUILTIN_TOOLS), registry (ToolRegistry), installers (ToolInstaller ABC -> AptInstaller)
agents/        Agent ABC, claude.py, codex.py, ports.py (ContainerHandle ABC agents depend on), registry
detection/     ProjectDetector ABC + python/node/rust/go, registry, starter_spec
validation/    ValidationRule ABC, rules/*.py (one per concern), validator
project/       git.py, locator.py (ProjectLocator: project = git common dir, so all worktrees share one box)
secrets/       model, sources (SecretReader ABC: Env/File/Keychain/Command), delivery (SecretDelivery ABC:
               Env/File), plan (merges agent built-ins with user [secrets])
gateway/       runs INSIDE the gateway container; standard library only.
               rules (Rule ABC: Domain/Address/Host, RuleParser), policy (PolicyMatcher), protected ranges,
               firewall (FirewallBackend ABC -> NftablesBackend), dns + resolver (DNS-pinned answers),
               nflog, audit, supervisor, daemon, relay (Linux host relay)
image/         DockerfileBuilder, entrypoint (incl. idle watcher), gateway image, ImageBuilder
container/     manager (BoxManager), gateway (GatewayManager), mounts (MountPlanner, read-only spec and
               .bulbi overlays, GitMetadataMounts ABC: Protected/Isolated, host_exposure), identity
               (names/labels), sessions (session counting), handle, terminal (`docker exec`), gitvolume
               (box-repo volumes), execstream (BoxStream ABC: binary stdout out of the box, for bundles)
gitsafety/     host side, docs/specs/git-safety.md. inventory (GitSnapshot of .git entries, admin dirs,
               configs incl. includes, hooks), baseline (.bulbi/git-baseline.json), checks (GitCheck ABC:
               NewGitDir/ForeignPointer/ExecConfig/HookChanged), exec_keys (ExecConfigRegistry), scanner,
               findings (GitFinding hierarchy), actions (FindingAction ABC: Quarantine/Block), quarantine
               (.bulbi/quarantine + restore), guard (GitGuard facade + audit), modes (GitMode ABC:
               Guarded/Isolated), isolated (HostRefsExporter, BoxRepo, BundlePuller), config, hostgit
sandbox/       orchestrator, planner (BoxPlanner: attach / restart / recreate / refuse), lock (.bulbi/box.lock),
               session (start sequence + teardown), hashing (spec hash), relay launcher, observer
cli/           app.py (`bulbi.cli:main`), context.py (AppContext, composition root), commands/ (BulbiCommand ABC),
               render/ (Rich output)
```

### How a run works
1. `ProjectLocator` resolves the project. For a git repo that's the repository's common dir, so every worktree maps to the same box.
2. The spec always comes from the main checkout's `bulbi.toml`, and is validated before anything starts.
3. Under `.bulbi/box.lock`, `BoxPlanner` decides: attach to the running box, restart a stopped one, recreate it if the spec hash changed and no sessions are live, or refuse if the spec changed while sessions are live.
4. Starting a new box:
   - a dedicated network;
   - the gateway container (nftables + DNS resolver + audit log);
   - the box with `network_mode=container:<gateway>`, `cap_drop=ALL` and `no-new-privileges`, with project dirs mounted at their host paths;
   - the agent `prepare()`s the box.
5. Each session is its own `docker exec`, with cwd set to the worktree it was launched from. Secrets are delivered on every attach.
   Git safety (`[git]`): before every attach and after every session `GitGuard` scans the mounted checkouts against the baseline recorded at box creation and quarantines (or, with `on_finding = "block"`, refuses on) git metadata that would run code on the host. `mode = "isolated"` gives the box its own small git dir in a volume instead of the host's `.git`: history is read through read-only alternates on the host's `objects/`, and `bulbi pull` brings commits back as a bundle.
6. The box's PID 1 idle watcher stops it after `[box] idle_timeout` with no sessions. Stopped boxes are kept for fast restart.

Network enforcement:
- Kernel-level nftables rules in the shared namespace decide every connection. Domain rules work through DNS pinning: only answers for allowed names are added to the allowed sets.
- Private and host destinations are reachable only via explicit address or `host` rules.
- In whitelist mode, nothing gets out except what is allowed.

### Extending

| To add… | Do this |
|---|---|
| Agent | Subclass `Agent` in `agents/<name>.py`, declare its credentials as `SecretDeclaration`s, and add it to `AgentRegistry.builtin()`. Put file setup in `prepare_container`. |
| Tool | Append a `ToolDefinition` to `tools/catalog.py`. For a custom install method, subclass `ToolInstaller`. |
| Project type for `init` | Subclass `ProjectDetector` in `detection/` and add it to `DetectorRegistry.builtin()` (order = priority). |
| Validation check | Subclass `ValidationRule` in `validation/rules/` and add it to `SpecValidator.default()`. |
| CLI command | Subclass `BulbiCommand` (or `SandboxCommand`) in `cli/commands/` and add it to `COMMANDS`. |
| Network rule kind | Subclass `Rule` in `gateway/rules.py` and teach `RuleParser` its syntax. |
| Firewall backend | Subclass `FirewallBackend`. |
| Secret source / delivery | Subclass `SecretReader` / `SecretDelivery` and register it in `SecretReaders.builtin()` / `SecretDeliveries.builtin()`. |
| Git safety check | Subclass `GitCheck` in `gitsafety/checks.py` (with a `GitFinding` subclass if it needs its own neutralisation) and add it to `GitSafetyScanner.default_checks()`. |
| Exec-capable git key | Add an `ExecKey` to `ExecConfigRegistry.builtin()`. |
| Git mode / finding policy | Subclass `GitMode` / `FindingAction` and register it in `GitModes.builtin()` / `FindingActions.builtin()`. |

Never branch on an agent, tool or language name outside its own class (no `if agent == "claude"`).

## Code conventions

- Python 3.11+, `from __future__ import annotations` in every module. Ruff (line length 99, rules E F I N W UP B SIM RUF PL) and strict mypy.
- SOLID: one responsibility per class/module; extend by adding a subclass and registering it, not by editing conditionals.
- Dependencies are injected (Docker client, subprocess runner, clock, host env, secret readers) and wired in `cli/context.py`. Library code never creates its own Docker client.
- Frozen dataclasses for data models; spec enumerations are `StrEnum`s.
- `gateway/` must stay standard-library only, because it runs inside the gateway image.
- Cross-cutting constants live in `constants.py`; module-specific constants live at the top of their module. No magic strings.
- Agent-specific details (paths, keychain service, credentials, domains) live only in that agent's class.
- User-facing failures raise a `BulbiError` subclass; `BulbiCommand` turns them into CLI errors. No bare `except Exception`.
- Secret values are never logged, printed or put in argv or reprs. `bulbi check` never runs `command`/`keychain` sources unless `--probe-secrets` is given.
- Network rules are enforced only from `bulbi.toml`. Agent/detector domains in source are just suggestions written into the starter spec.
- Mark known gaps with `TODO(bulbi):`.
- Host git is only run through `gitsafety.hostgit.HostGit` (hermetic: neutral cwd, no system/global config); the scanner never runs git in an agent-controlled repository.
- Security-sensitive changes (`gateway/`, `container/mounts.py`, `secrets/`, `gitsafety/`, agent credentials) need a test that fails without the change. Anything that affects isolation also needs a case in the Docker escape suite.

## Testing

- **Unit tests,** one file per package: `test_spec`, `test_tools`, `test_validation`, `test_agents`, `test_detection`, `test_project`, `test_secrets`, `test_gateway`, `test_image`, `test_container`, `test_container_handle`, `test_sandbox`, `test_gitsafety`, `test_cli`.
  - No real Docker, keychain or internet: use the fakes in `tests/fakes.py`, and always inject fake secret readers. The keychain must never be touched.
  - CLI tests go through `click.testing.CliRunner` with an injected `AppContext`.
  - `tests/repos.py` builds real temporary git repos.
  - Firewall rulesets are golden-file tested against `tests/golden/*.nft`.
- **`tests/docker/`** (`-m docker`): escape suite, git-escape suite, git-safety suite (vectors A/B/C in both git modes, `bulbi pull`), lifecycle.
  - Test resources (boxes, gateways, networks, `bulbi-git-` volumes) are named `bulbitest…`, and each test removes only what it created.
  - Never touch the user's real boxes or the real repo's `.git`.
- `.env` is excluded from git; never commit it.
