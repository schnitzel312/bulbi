# Bulbi

**Let AI coding agents run fully autonomously without trusting them with your machine.**

Bulbi runs Claude Code, Codex and other AI CLIs in full-auto mode (`--dangerously-skip-permissions`, `--full-auto`) inside an isolated Docker box. One `bulbi.toml` decides which files the agent can see and change, where it can connect on the network, and which secrets it gets. Nothing else is reachable.

```console
$ bulbi init     # generate a bulbi.toml for this project
$ bulbi check    # see exactly what the box will be allowed to do
$ bulbi run      # start Claude Code inside the box, no permission prompts
```

## Why

Autonomous agents are most useful when you stop approving every command, which is also when they're most dangerous. A prompt injection in a README, an issue or a web page can turn "fix this test" into "upload `~/.ssh` somewhere".

Bulbi moves the trust boundary from the agent to the box:

- **Files:** only the paths you mount are visible. Secrets like `.env` can be masked, and mounts can be read-only.
- **Network:** every connection goes through a firewall you configure, for any protocol (HTTP, gRPC, Postgres, AMQP, SSH…). Your machine, your LAN and other containers are unreachable unless you explicitly allow them.
- **Secrets:** you declare exactly which credentials enter the box, and `bulbi check` lists them.
- **No limits on how the agent works:** tools need no proxy settings. If the policy allows a destination, it just works, using its real hostname.

## How it works

```
 your machine                        Docker
 ────────────                        ──────────────────────────────────────────────────────
                                      ┌────────────── shared network namespace ──────────┐
 bulbi run ──docker exec──────────────┼─▶ box (agent)               gateway              │
 bulbi run (2nd terminal) ────────────┼─▶   no capabilities,        nftables firewall    │
                                      │     can't change rules      DNS resolver         │
 project files ◀── bind mounts ───────┼──   (only what you mount)   audit log            │
                                      └──────────────────────────────────┬───────────────┘
                                                                         ▼
                                                     only destinations your policy allows
```

- **The gateway owns the network:** each project gets a small gateway container that owns the box's network namespace. Its kernel-level firewall decides every TCP/UDP connection, so a program that ignores proxy settings still can't get out.
- **Domain rules are enforced through DNS:** the gateway is the box's only resolver. Allowed names resolve, and only their addresses become reachable. Denied names don't resolve at all.
- **Private and host addresses are blocked by default:** loopback, LAN ranges, cloud metadata (`169.254.169.254`) and Docker networks stay blocked even if an allowed name resolves to them.
- **One box per project:** every terminal you open joins the same box, including from other git worktrees of the same repo. Each session runs in its own `docker exec`. The box stops by itself after an idle timeout.

## Requirements

- **Python 3.11+**
- **Docker:** Docker Desktop on macOS, or Docker Engine on Linux
- **The agent you want to run:** Claude Code and Codex are installed *inside* the box automatically.

## Installation

Bulbi isn't on PyPI yet. Install it from GitHub:

```bash
pipx install git+https://github.com/schnitzel312/bulbi.git
# or
pip install git+https://github.com/schnitzel312/bulbi.git
```

## Quick start

```bash
cd your-project
bulbi init          # detects Python/Node/Rust/Go and writes a starter bulbi.toml
bulbi check         # review tools, mounts, network policy and secrets
bulbi run           # build the box and start the configured agent (Claude Code by default)
```

- **Second session:** run `bulbi run` in another terminal; it joins the same box.
- **Other commands:**
  - `bulbi run -- pytest -q` runs any command inside the box instead of the agent.
  - `bulbi shell` opens an interactive shell.
  - `bulbi log --denied` shows what the agent tried to reach and was refused.

**Claude Code login:** if you use a Claude subscription on macOS, Bulbi copies your Claude Code login from the Keychain into the box, so the agent starts already signed in. Alternatively, set `ANTHROPIC_API_KEY`.

## Configuration: `bulbi.toml`

A complete example:

```toml
spec = "0.1"

[box]
name = "my-app"
agent = "claude"            # "claude" or "codex"
idle_timeout = "10m"        # stop the box after 10 min with no sessions ("0" = immediately)

[tools]
allow = ["python", "node", "git", "rg"]

[setup]
run = ["pip install -e ."]  # runs once, at first box start

[[mount]]
path = "."                  # the project; mounted at the same path inside the box
mode = "read-write"         # or "read-only"
exclude = [".env", "*.pem", "*.key"]

[network]
default = "deny"            # "deny" = whitelist mode, "allow" = blacklist mode
allow = [
  "pypi.org", "files.pythonhosted.org",
  "*.github.com", "github.com",
  "api.anthropic.com", "claude.ai",
  "host:5432",              # Postgres running on your machine
]
deny = ["gist.github.com"]

[secrets]
GITHUB_TOKEN = { from = "env" }
NPM_TOKEN    = { from = "command", source = "op read op://dev/npm/token" }

[limits]
cpu = 2
memory = "4GB"
```

You can also put the same content under `[tool.bulbi]` in `pyproject.toml`.

### Network rules

| Rule | Example | Matches |
|---|---|---|
| Domain | `pypi.org` | exactly that name |
| Wildcard | `*.github.com` | any subdomain, **not** `github.com` itself |
| Port(s) | `broker.example.com:5671`, `host:5672,15672`, `db.local:5000-5010` | only those ports (no port = all ports) |
| Protocol | `1.1.1.1:53/udp` | only TCP or only UDP |
| Address | `192.168.1.20:6379`, `10.20.0.0/16` | an IP or range |
| Host | `host:5432` | a service on your own machine, reached from the box as `host.bulbi.internal` |

How rules are applied:
- **Precedence:** the most specific rule wins. An exact name beats a wildcard, a longer CIDR beats a shorter one, and a rule with a port beats one without. When an `allow` and a `deny` are equally specific, deny wins. Anything unmatched falls to `default`.
- **Private and local addresses** are only reachable through an explicit address or `host` rule, even with `default = "allow"`.
- **Whitelist mode** (`default = "deny"`) is the strong boundary. **Blacklist mode** (`default = "allow"`) is best effort: a determined agent can reach a denied service by its raw IP. `bulbi check` says so.

### Secrets

One line per secret under `[secrets]`:

```toml
[secrets]
GITHUB_TOKEN = { from = "env" }                                    # $GITHUB_TOKEN → $GITHUB_TOKEN
OPENAI_KEY   = { from = "env", source = "MY_OPENAI_KEY" }
NPM_RC       = { from = "file", source = "~/.npmrc", to = "file", path = "~/.npmrc" }
SENTRY_DSN   = { from = "keychain", source = "sentry-dsn" }        # macOS Keychain
NPM_TOKEN    = { from = "command", source = "op read op://dev/npm/token" }
```

| Key | Values | Default |
|---|---|---|
| `from` | `env`, `file`, `keychain`, `command` | required |
| `source` | env var name, file path, keychain service, or command | the secret's name |
| `to` | `env` (environment variable) or `file` | `env` |
| `path` | file location in the box (under `~`), mode `600` | required when `to = "file"` |

- **What enters the box:** `bulbi check` lists every secret entering the box, including the agent's own credentials, without showing values. Values are never baked into the image or written to logs.
- **Refreshing:** secrets are re-read every time a session starts, so rotated tokens are picked up.
- **The agent can read the secrets it's given.** Bulbi's protection is that the network policy controls where it can send them.

### Mounts

- **Path inside the box:** each project directory is mounted at the same path inside the box as on your machine.
- **Read-only parts:** `bulbi.toml` and the repository's existing git metadata (`.git/hooks`, `.git/config`, and the pointer files that link worktrees) are always read-only inside the box. The agent can't loosen its own sandbox or plant git hooks there. See [Known gap: git on the host](#known-gap-git-on-the-host) for what isn't covered yet.
- **Excludes** hide matching files that exist when the box starts.
- **Checks:** `bulbi check` refuses to mount a Docker socket, and warns about mounting `/` or your home directory.

### Profiles

Profiles can only *narrow* the main spec:

```toml
[profiles.readonly.mounts]
"." = "read-only"

[profiles.offline.network]
allow = ["pypi.org"]
```

```bash
bulbi run -p readonly
```

Each profile gets its own box, so a read-only session never shares a container with a read-write one.

### Git worktrees

All worktrees of a repository share **one** box, so you can run several agents in parallel, each on its own branch:

- **Where sessions start:** each session starts in the worktree you ran `bulbi run` from.
- **Which spec applies:** the policy always comes from the main checkout's `bulbi.toml`, so an agent on a branch can't loosen it by editing that branch's copy.
- **Where worktrees live:** a directory that only holds this repo's worktrees is mounted as a whole, so new worktrees appear without a restart. Add more with `[project] worktree_dirs = ["~/worktrees/my-app"]`.

### Tools

`python`, `node`, `git`, `rg`, `fd`, `jq`, `curl`, `make`, `gcc`, `go`, `rust`, `cargo`, `poetry`, `uv`, `pnpm`, `yarn`, `bun`

Version pins like `python@3.12` and `node@22` are validated, but the box currently installs Debian bookworm's packages (Python 3.11, Node 18). Exact version installs are planned.

## Commands

| Command | What it does |
|---|---|
| `bulbi init [--force]` | Detect the project type and write a starter `bulbi.toml` |
| `bulbi check [--probe-secrets]` | Validate the spec and show tools, mounts, effective network policy and secrets. Exits 1 on errors |
| `bulbi run [-p PROFILE] [-- CMD…]` | Attach to (or create) the project's box and run the agent, or `CMD` |
| `bulbi shell [-p PROFILE]` | Interactive bash shell in the box |
| `bulbi log [--denied]` | Network audit log: every DNS answer and connection, with the rule that decided it |
| `bulbi ls` | Boxes, their projects, state and active sessions |
| `bulbi stop [-p PROFILE] [--all] [--yes]` | Stop the project's box and gateway |
| `bulbi restart [-p PROFILE] [--yes]` | Recreate the box with the current spec |
| `bulbi rm CONTAINER` | Remove a box and its gateway |
| `bulbi reset [--yes]` | Remove every Bulbi container, network and image |

`run` and `shell` validate the spec first and refuse to start if it has errors. If you edit `bulbi.toml` while sessions are running, the next `bulbi run` asks you to `bulbi restart` instead of silently running with the old policy.

## Security model and limitations

Bulbi assumes the agent may be hostile, for example through prompt injection. **It protects against:**
- reading or writing files outside the mounts;
- network access outside the policy, over any protocol and including DNS;
- reaching your machine, your LAN, cloud metadata or other containers;
- changing the firewall from inside the box;
- tampering with its own `bulbi.toml` or git hooks.

**It does not protect against:**
- **Exfiltration to destinations you allow.** If `github.com` is allowed, the agent can push there.
- **Shared CDN addresses.** Another site served from the same IP as an allowed domain is reachable.
- **Running git on the host on git metadata the agent created.** See below.
- **Kernel or Docker escapes,** or anyone who already has access to your Docker socket.

### Known gap: git on the host

When **you** run `git` on your machine, git reads the repository's configuration, and some settings make git run commands (`core.fsmonitor`, `core.hooksPath`, `core.sshCommand`, filters, `!` aliases…). Bulbi makes the repository's existing git metadata read-only inside the box. Docker can only protect files that exist when the box starts, though. So an agent can still **create new git metadata** during a session and have it run commands on your machine the next time you run `git` there. Two ways:

- a new nested repository, e.g. `src/.git`, pointing at a config the agent wrote;
- a worktree the agent creates inside the box.

**Until this is closed:**
- **Don't run `git` on the host inside directories the agent created** while its sessions are live. Run git for the project inside the box instead (`bulbi shell`).
- **Review new `.git` files or folders before using them on the host:** `find . -name .git -newer bulbi.toml`.

**A fix is in progress:**
- **Default "guarded" mode:** Bulbi scans for new git metadata and dangerous settings after each session and before each `bulbi run`, quarantines what it finds (it can be restored), and reports it.
- **Opt-in "isolated" mode** (`[git] mode = "isolated"`): the agent commits into its own clone inside the box, and you fetch its work with `bulbi pull`. Your real `.git` is then never writable from the box.

The design is documented in [`docs/specs/sandbox-isolation.md`](docs/specs/sandbox-isolation.md). The test suite includes a real-Docker escape suite that tries to break out in each of these ways. It runs on macOS (Docker Desktop); Linux, especially the `host:` relay, is less tested.

## Development

```bash
git clone https://github.com/schnitzel312/bulbi.git && cd bulbi
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

.venv/bin/pytest -q                 # unit tests (no Docker needed)
.venv/bin/pytest -m docker          # real-Docker escape and lifecycle suite (~3 min)
.venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests
.venv/bin/mypy src                  # strict
```

[`CLAUDE.md`](CLAUDE.md) describes the architecture, conventions and extension points: how to add an agent, a tool, a network rule kind or a secret source. Contributions are welcome. Every change that touches isolation needs a test that fails without it.

## License

[MIT](LICENSE)
