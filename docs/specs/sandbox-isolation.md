# Spec: Sandbox network & host isolation (v3)

Status: proposed v3 (protocol-agnostic egress firewall) · Repo path once committed: `docs/specs/sandbox-isolation.md`

## 0. Product principle

Bulbi lets AI CLIs run **fully autonomously** (`--dangerously-skip-permissions`, `--full-auto`) because the box, not the agent, is the trust boundary.
- **Secure by default:** the agent can touch only what `bulbi.toml` grants, both files and network.
- **No artificial limits:** if the policy allows a destination, any protocol works (HTTP, gRPC, AMQP, Postgres, Redis, SSH, QUIC…), using the destination's **real hostname**, with **no proxy configuration** in the tools.
- **One readable file:** policy lives in `bulbi.toml`, in firewall terms developers already know (default + allow + deny).

## 1. Requirements

| # | Requirement |
|---|---|
| R1 | Every outbound connection (TCP and UDP, any port, any protocol) is decided by the box's ACL: `default` (allow/deny) + `allow` + `deny`. Whitelist, blacklist and mixed styles are all supported. |
| R2 | Local and private destinations (the host, LAN, other containers, cloud metadata) are blocked unless an **address rule** explicitly allows them. Neither allow-mode nor an allowed domain that resolves to such an address unlocks them. |
| R3 | Nothing can open a connection into the box: not other containers, the LAN or the host network. |
| R4 | Enforcement is in the kernel and needs no cooperation from the agent: no `HTTP_PROXY`. A program that ignores everything still cannot get out. |
| R5 | The box resolves names only through Bulbi's DNS. In whitelist mode, names that aren't allowed don't resolve, which closes DNS exfiltration. |
| R6 | Fail closed: if the gateway dies, the box has no connectivity. |
| R7 | Every DNS answer and every connection attempt (allowed or denied) is audit-logged with the deciding rule. |
| R8 | Same guarantees on Linux and macOS (Docker Desktop). |

Out of scope, documented as residual risk: exfiltration to an allowed destination; other sites on a shared CDN IP of an allowed domain (§3.5); kernel or Docker escapes; a user who grants Docker-socket access.

## 2. Current state (why it fails today)
- The box is on Docker's default bridge with a full route to the internet, the host, the LAN and other containers. The HTTP proxy is only advisory, and only programs that honour `HTTP_PROXY` use it.
- On Linux the proxy is unreachable (it binds 127.0.0.1, and the box is pointed at 172.17.0.1).
- Only HTTP(S) is mediated. Databases and message queues are either wide open or impossible, depending on the tool.
- The project's `.git/hooks` and `.git/config` (and `.git-main`) are writable. The agent can plant code that runs on the host the next time the user runs `git`.

## 3. Architecture: a gateway that owns the box's network namespace

```
 Docker
 ┌──────────────────────── shared network namespace ───────────────────────┐
 │  gateway container (bulbi/gateway)          box container (agent)       │
 │  • CAP_NET_ADMIN, owns nftables rules       • network_mode=container:gw │
 │  • DNS resolver on 127.0.0.1:53             • cap_drop=ALL, uid bulbi   │
 │  • audit logger                             • cannot touch nft rules    │
 │                                                                         │
 │  nftables:  INPUT  new connections → drop          (R3)                 │
 │             OUTPUT box traffic → ACL sets → accept / reject + log  (R1–R2)│
 │             udp/tcp :53 from box → redirect to local resolver      (R5) │
 └───────────────────────────────┬─────────────────────────────────────────┘
                                 │ eth0 on dedicated bridge bulbi-net-<box>-<hash>
                                 ▼  (no other containers attached)
                               internet / allowed private targets
```

### 3.1 Why this shape
- **Namespace sharing:** the box runs with `network_mode="container:<gateway>"`, so it uses the gateway's network stack. This is the Kubernetes sidecar pattern.
- **The gateway holds the rules:** it has `CAP_NET_ADMIN` and installs nftables rules in that namespace. The box has `cap_drop=["ALL"]` and `no-new-privileges`, so it can't change routes, rules, or raw sockets. Kernel-enforced and protocol-agnostic (R1, R4).
- **Nothing for tools to configure:** there's no proxy env and no forwards. `psql -h db.mycompany.cloud`, `amqps://broker:5671` and `git@github.com` all just work if allowed, and get rejected immediately (`ECONNREFUSED` via `reject`, not a hang) if not.
- **Same everywhere:** works identically on Linux and Docker Desktop, since both run a Linux kernel with nftables.

### 3.2 DNS-pinned name rules
Domain rules can't be matched by the kernel directly; it only sees IPs. The gateway therefore runs the box's resolver:
1. The box's `/etc/resolv.conf` points at `127.0.0.1`. Any packet the box sends to port 53 elsewhere is redirected there too.
2. For each query, the name is evaluated against the domain rules **before** resolving upstream:
   - If denied: `NXDOMAIN`, logged `denied_by_rule` or `denied_by_default`.
   - If allowed: the gateway resolves the name, **vets every returned address** (§3.3), and drops protected addresses from the answer unless an address rule allows them.
   - The surviving IPs go into a dynamic nftables set with the rule's ports, keyed by the record's TTL (minimum 5 min).
3. Connections to an IP are accepted only if:
   - (a) it's in the pinned set for that port, or
   - (b) an address rule (IP, CIDR or `host`) allows it, or
   - (c) in allow-default mode, it's a public address not matched by any deny rule.

   Established connections survive set expiry (conntrack).

### 3.3 Policy model (`bulbi.toml`)
```toml
[network]
default = "deny"                    # "deny" = whitelist, "allow" = blacklist
allow = [
  "pypi.org",                       # exact domain, any port
  "*.github.com",                   # any subdomain (not the apex)
  "broker.cloudamqp.com:5671",      # domain limited to one port
  "host:5432",                      # the machine running Bulbi
  "host:15672,5672",                # several ports
  "192.168.1.20:6379",              # LAN address + port
  "10.20.0.0/16",                   # a private range (any port)
]
deny = [
  "gist.github.com",                # carve-out inside an allowed wildcard
  "*.telemetry.example",
  "203.0.113.0/24:25",              # range + port
]
```
- **Rule kinds:**
  - **Domain:** `name`, `*.name`.
  - **Address:** IPv4/IPv6 literal or CIDR.
  - **Host:** `host`, the machine running Bulbi.
  - **Ports:** any kind may carry `:port`, `:p1,p2` or `:lo-hi`. With no port, the rule means **all ports**. A rule covers both TCP and UDP; `/tcp` or `/udp` restricts it.
- **Precedence:** the most specific matching rule wins:
  - exact domain > longer wildcard > shorter wildcard;
  - longer CIDR prefix > shorter;
  - a rule with a port > the same rule without one.

  When an allow and a deny are equally specific, **deny wins**. No match falls to `default`.
- **Protected ranges:** loopback, RFC 1918, `fc00::/7`, link-local (incl. `169.254.169.254`), CGNAT, Docker subnets, multicast, reserved, and IPv4-mapped forms of these. They're reachable **only** via an Address or Host allow rule covering the address and port. `default="allow"` means "any *public* destination not denied".
- **The `host` keyword:** the box addresses the user's machine as **`host.bulbi.internal`**, which Bulbi's DNS resolves. How it reaches services bound to the host's `127.0.0.1`:
  - **macOS:** Docker Desktop's host gateway (`host.docker.internal`) already does this.
  - **Linux:** the Bulbi CLI runs a tiny host-side relay bound to the dedicated bridge's gateway IP. It's opened only for the ports in `host:` allow rules, accepts connections only from the gateway's IP, and relays to `127.0.0.1:<port>`.
- **Blacklist mode is best effort**, and `check` says so. The gateway also resolves denied names itself and blocks their current IPs, but a determined agent can still reach a denied service by a raw IP or via DNS-over-HTTPS. Whitelist mode is the strong boundary.

### 3.4 Box and gateway hardening
- **Box:**
  - `cap_drop=["ALL"]`, `no-new-privileges`, `pids_limit` (default 512);
  - no ports, no `extra_hosts`, not privileged, no devices;
  - runs as `bulbi`.
- **Gateway:**
  - only `CAP_NET_ADMIN` (+ `NET_BIND_SERVICE` for :53), read-only root FS;
  - no published ports; attached only to its dedicated bridge;
  - its own upstream DNS and log writes are exempted by uid (`meta skuid`), and every other process in the namespace is subject to the ACL;
  - audit log written to the project's bind-mounted `.bulbi/`.
- **INPUT:** nftables drops all new inbound connections (R3). The dedicated bridge has no other members.
- **Fail closed:** the box shares the gateway's namespace, so if the gateway stops, the namespace and its interface go away and the box has no network (R6).

### 3.5 Known limitation: shared IPs
Pinning works per IP. If an allowed name and a non-allowed name share a CDN IP, the agent could reach the second by sending a different TLS SNI or `Host` to that IP. This is accepted, the same trade-off as Cilium's and AWS Network Firewall's FQDN policies, and documented in `check` output. A later optional `strict_tls = true` can add SNI inspection on 443.

### 3.6 Filesystem-escape hardening (same phase)
- `.git/hooks` and `.git/config` are mounted read-only over the project mount, and the same in `.git-main`. Commits and branches still work.
- `check` **errors** on mounts that are or contain a Docker socket, and **warns** on mounting `/`, `~` or an ancestor of home.
- Excludes that match a directory are masked with an empty read-only tmpfs (fixes the start failure).

## 4. Lifecycle (`SandboxSession`)
Start, in order, when §8 decides a new box is needed (each step registered for teardown first):
1. Create the dedicated network.
2. On Linux, if there are `host:` rules, start the host relay.
3. Start the gateway and wait until it reports its rules are loaded (health file; timeout 10 s → `SandboxError`).
4. Start the box (`network_mode=container:<gateway>`).
5. Agent prepare.
6. `docker exec` the command.

Teardown always runs, in reverse order, on error and on Ctrl-C.
- **`reset`:** removes gateways, networks and relays.
- **`ls`:** hides gateways (`bulbi.role=gateway`).

The current in-process HTTP proxy (`proxy/`) is replaced by `gateway/`, which holds:
- the rule model and matcher (pure Python, used by `check` and the gateway);
- the nftables ruleset renderer;
- the DNS resolver;
- the audit logger;
- the host relay.

## 5. Spec-format compatibility
- Existing specs keep working: `allow` domain lists mean the same, except a domain allow now covers **all ports**, not just 80/443.
- **New:** `deny`; IP, CIDR and `host` rules; ports and port lists; `/tcp` / `/udp`.
- **`bulbi check` prints the effective policy in plain words**, for example: "Whitelist. Any protocol to 9 domains, host:5432, 10.20.0.0/16. Deny 2 rules. Local/private blocked unless listed."
- **Warnings:**
  - blacklist mode (best effort);
  - wide private CIDRs (shorter than /24 or /64);
  - `host` with no port;
  - `network.default="allow"` with no deny rules.
- **Errors:** malformed rules; a deny identical to an allow.
- **Audit log JSONL** keeps the existing keys (`timestamp, domain, action, method, url`), with `method` = `DNS`/`TCP`/`UDP`. It adds `reason, rule, ip, port, proto`. `bulbi log` shows them.

## 6. Verification

### 6.1 Unit tests (no Docker)
- **Rule parsing:** every rule kind, port form and proto suffix; malformed rules rejected.
- **Matcher precedence:** exact vs wildcard, CIDR prefix, port specificity, deny wins ties, both defaults.
- **Protected-range vetting:** incl. IPv4-mapped IPv6; DNS answers with mixed addresses get filtered.
- **Ruleset rendering:** the nftables renderer is golden-file tested for whitelist, blacklist and mixed specs.
- **DNS:** a denied name never triggers an upstream query (fake upstream records calls).
- **Host relay:** only declared ports; rejects other sources.
- **Session:** teardown completeness on failure at every step.
- **Mount planner:** git overlays and docker-socket validation.
- **Carried over from the code-quality review:** malformed input (e.g. bad brackets `[::1`) never produces a traceback; it is logged as a deny.

### 6.2 Escape test suite: real Docker (`pytest -m docker`, skipped if Docker is unavailable)
Test fixtures started by the test:
- a TCP echo server on the host's `127.0.0.1:<p>`;
- a canary container on the default bridge.

Whitelist box: `allow=["pypi.org", "*.github.com", "host:<p>", "1.1.1.1:53/udp"]`, `deny=["gist.github.com"]`.

| Attempt from inside the box | Expected |
|---|---|
| `curl https://pypi.org/simple/` (no proxy env) | ✅ |
| `git ls-remote https://github.com/git/git` and `ssh -T git@github.com` (port 22 to an allowed name) | ✅ connects |
| `curl https://gist.github.com` | ❌ DNS NXDOMAIN, logged |
| `nc host.bulbi.internal <p>` | ✅ echo works, logged `TCP` |
| `nc host.bulbi.internal <other port>` | ❌ refused |
| `curl https://example.com` and `curl --resolve example.com:443:93.184.215.14 https://example.com` | ❌ / ❌ (DNS denied; raw IP not pinned) |
| Python raw `socket.create_connection(("1.1.1.1", 443))` | ❌ refused |
| `dig @8.8.8.8 example.com` (alternate resolver) | ❌ redirected to Bulbi DNS, NXDOMAIN |
| `dig @1.1.1.1 pypi.org` (allowed UDP) | ✅ |
| Connect to `172.17.0.1`, the canary's IP, `169.254.169.254` | ❌ refused |
| Allowed name resolving to `127.0.0.1` (`localtest.me` allowed) | ❌ address stripped from the answer |
| `nft flush ruleset` / `ip route del default` inside the box | ❌ operation not permitted |
| Write `.git/hooks/pre-commit`, `.git/config` | ❌ read-only |
| Canary container connects to the box / gateway | ❌ unreachable |
| Stop the gateway, retry pypi | ❌ no network |

The same suite in blacklist mode (`default="allow"`, `deny=["example.com"]`):
- pypi ✅;
- example.com ❌;
- AMQP-style TCP to a public test server on any port ✅;
- `host.bulbi.internal:<p>` without a host rule ❌;
- `localtest.me` ❌.

**Done when** the suite passes on macOS (Docker Desktop) and Linux.

## 7. Decisions
- **Kernel-level, protocol-agnostic firewall + DNS pinning** instead of an HTTP proxy or port forwards. No limits on protocols, and nothing for tools to configure.
- **Rules without a port cover all ports.**
- **Most specific rule wins; deny wins ties.**
- **Private/local destinations are allowed only through explicit address or `host` rules.**
- **Blacklist mode is supported but labelled best effort;** whitelist is the strong mode.
- **One gateway container per running box**, plus a host relay on Linux only when `host:` rules exist.

## 8. One shared box per project (multi-session)

**Goal:** all agent and shell sessions for a project run in **one** box (plus its one gateway), each in its own terminal. A different project gets its own box. No container sprawl.

### 8.1 Identity
- **Box key: the project, not the folder.**
  - In a git repo, the project is the repository: the realpath of `git rev-parse --git-common-dir`. Every worktree of the same repo maps to the same box (§9).
  - Outside git, the project is the resolved project root.
  - The profile is part of the key, because a read-only profile can't share a box with read-write sessions.
- **Names:**
  - box: `bulbi-<box.name>-<hash(project)>[-<profile>]`;
  - gateway: the same name + `-gw`.
  - Labels: `bulbi.project`, `bulbi.profile`, `bulbi.spec_hash`.
- **Spec hash:** covers the image, mounts, network policy, limits and agent.

### 8.2 Attach-or-create (`bulbi run`, `bulbi shell`)
1. Take an exclusive lock on `.bulbi/box.lock` (`fcntl.flock`) so two terminals starting at once can't race.
2. Find the box by labels, then:
   - **Running, same spec hash:** attach. Agent `refresh()` (credentials only, never overwriting files a live session may be writing).
   - **Stopped, same spec hash:** start it again (gateway first). Setup state in the box is preserved, so setup commands don't re-run. Then attach.
   - **Different spec hash (`bulbi.toml` changed):**
     - no active sessions: recreate box + gateway;
     - active sessions: refuse with "box is running an older spec with N active sessions; finish them or run `bulbi restart`". New policy must never silently not apply.
   - **Missing:** create it (full start sequence, §4). Agent `prepare()` runs once per container start.
3. Release the lock, then `docker exec -it` the session. Each session is a separate `docker exec`, so any number of terminals can run at once.

### 8.3 Session tracking and shutdown
- **Active sessions are counted from Docker itself:** running exec instances on the box (`ExecIDs` → `exec_inspect().Running`), excluding Bulbi's own setup execs (each carries env `BULBI_EXEC=session`). This is crash-proof: if a terminal or the CLI is killed, its exec ends and stops counting.
- **When a session ends,** the CLI (under the lock) checks the count. If it's zero, the box becomes idle.
- **The idle policy** is `[box] idle_timeout` in `bulbi.toml`, default `"10m"`, with `"0"` meaning stop immediately.
  - **The box shuts itself down:** its PID 1 is a small Bulbi idle watcher, replacing `sleep infinity`. It checks every 30 s and exits once there have been no session processes for `idle_timeout`, which stops the box.
  - **The gateway** is stopped by the CLI after the last session when the timeout is 0. Otherwise the next Bulbi command reaps any gateway whose box is stopped, and `ls` shows it.
  - **Stopped boxes are kept, not removed**, so a restart is fast and setup state survives. They use no CPU or RAM. `bulbi rm` / `bulbi reset` remove them.
- **Commands:**
  - `bulbi ls`: project, profile, state, **active sessions**, uptime, idle time.
  - `bulbi stop [--all]`: stop this project's box + gateway. Asks first if sessions are active.
  - `bulbi restart`: stop then start with the current spec (asks first if sessions are active).

### 8.4 Tests
- **Unit (fakes):**
  - attach to a running box with the same hash; restart a stopped box;
  - recreate on hash change with no sessions; refuse on hash change with sessions;
  - lock serialises concurrent starts (two threads → one create);
  - session count ignores setup execs;
  - the gateway is stopped only when the last session leaves;
  - profiles map to distinct boxes.
- **Docker suite:**
  - two concurrent `bulbi run -- sleep 5` → exactly one box + one gateway, two sessions in `ls`;
  - after both exit with `idle_timeout="0"` → both stopped;
  - with `"1m"` the box stops itself after about 1 min;
  - editing `bulbi.toml` while a session runs → the next `run` refuses with the restart hint.

## 9. Git worktrees: one box for all worktrees of a repo

**Goal:** run several agents in parallel, each in its own worktree of the same repo, all inside the project's single box and all under the same policy.

### 9.1 Same paths inside and outside
- **Mount at the host path:** every project directory is mounted at **its exact host path** inside the box (e.g. `/Users/ariel/Code/bulbi` → `/Users/ariel/Code/bulbi`), instead of `/home/bulbi/workspace`.
  - Git's absolute links (a worktree's `.git` file → `<main>/.git/worktrees/<name>`, and back) then just work.
  - The `.git-main` mount hack is removed.
  - Paths in agent output match the host.
- **Working directory:** a session starts in the worktree where `bulbi run` was invoked (`docker exec -w <host path>`). One box, many terminals, each in its own worktree.
- `bulbi run` from **any** worktree attaches to the same box (§8.2).

### 9.2 What gets mounted
At box creation, Bulbi reads `git worktree list --porcelain` and mounts:
1. **The main checkout** (it holds the shared `.git`).
2. **Worktree containers:** if every entry in a worktree's parent directory is a worktree of this repo (e.g. `~/.superset/worktrees/bulbi/`), that whole parent directory is mounted. Worktrees created there later appear in the running box with no restart.
3. **Scattered worktrees:** otherwise each worktree is mounted individually. A parent like `~/Code` that holds unrelated projects is **never** mounted. Worktrees created later in such places need `bulbi restart`, and `bulbi run` from one says so.
4. **Explicit dirs:** `[project] worktree_dirs = ["~/.superset/worktrees/bulbi"]` mounts extra worktree container dirs. Explicit dirs are validated: `check` errors if they contain anything other than worktrees of this repo.

**Which mode and excludes apply:** the `[[mount]] path = "."` rule (mode and excludes) applies to the main checkout **and every worktree**. Other `[[mount]]` entries are unchanged.

### 9.3 Policy comes from the main checkout
- The box's spec is **the main checkout's `bulbi.toml`**. A branch's own copy is ignored, and `run` warns if it differs. An agent on a branch therefore can't loosen the policy by editing its worktree's spec.
- `.bulbi/` (lock, audit log) lives in the main checkout.
- These are mounted **read-only in every mounted checkout:**
  - `bulbi.toml`;
  - the shared `.git/hooks` and `.git/config`;
  - each worktree's `config.worktree`.

  `.git/objects`, refs and `.git/worktrees/*` stay writable, so commits, branches and `git worktree add` (inside a mounted worktree dir) work.

### 9.4 Excludes on worktrees that appear later
Bind-mount excludes are fixed when the box starts. When a session attaches from a worktree that wasn't present at box start:
- if it contains files matching an exclude pattern (e.g. `.env`), the session is **refused** with "this worktree has excluded files that the running box can't hide; run `bulbi restart` when the other sessions finish";
- otherwise it is allowed, with the same documented limitation as today: secrets created on the host after start aren't hidden.

### 9.5 Agent configuration
- **Claude trust:** `ClaudeAgent.prepare()` marks the main checkout and each worktree container dir as trusted in `~/.claude.json`.
- **New worktrees:** `refresh()` adds trust for a newly seen worktree path with an atomic read-modify-write of that single key.
- The docker suite verifies that Claude starts without a trust prompt in a worktree created after box start.

### 9.6 Tests
- **Unit:**
  - the project key is the same from the main checkout and from every worktree;
  - mount planning in each case: a dedicated parent dir, scattered worktrees, refusal to mount a mixed parent, `worktree_dirs` validation;
  - host-path targets; read-only overlays in every checkout;
  - spec taken from the main checkout, with the differing-spec warning;
  - the late-worktree exclude refusal.
- **Docker:**
  1. Two worktrees plus `bulbi run` from each gives one box and two sessions, each with the right cwd.
  2. `git commit` works in both.
  3. A worktree added after start in the dedicated dir is usable without a restart.
  4. Writing `.git/hooks/*` or `bulbi.toml` from any worktree fails.

## 10. Secrets

**Goal:** give the box exactly the credentials it needs (agent logins, API tokens, config files) through one declarative mechanism. Every secret that enters the box is visible in `bulbi check`.

### 10.1 Format: one line per secret under `[secrets]`
```toml
[secrets]
GITHUB_TOKEN = { from = "env" }
OPENAI_KEY   = { from = "env", source = "MY_OPENAI_KEY" }
NPM_TOKEN    = { from = "command", source = "op read op://dev/npm/token" }
NPM_RC       = { from = "file", source = "~/.npmrc", to = "file", path = "~/.npmrc" }
SENTRY_DSN   = { from = "keychain", source = "sentry-dsn", to = "file", path = "~/.config/sentry/dsn" }
```
| Key | Values | Default | Meaning |
|---|---|---|---|
| `from` | `env` · `file` · `keychain` · `command` | required | Where Bulbi reads the value on the host. `keychain` is the macOS Keychain (`security find-generic-password -s <source> -w`). `command` runs on the host via argv split, with no shell, a 10 s timeout and stdout trimmed. |
| `source` | string | the secret's name | Env var name / file path / keychain service / command line. |
| `to` | `env` · `file` | `env` | How the box receives it: env var named after the secret, or a file. |
| `path` | path in the box (`~` = box user's home) | required if `to = "file"` | File location. Mode `600`, owned by the box user. Must be under the box home (the existing `write_file` restriction). |

- **Inline tables are the documented style;** `bulbi init`, the docs and the examples use it. `[secrets.NAME]` tables parse to the same data and stay accepted for compatibility.
- **The old `hosts` key** is accepted but ignored with a warning until `to = "inject"` exists (§10.4).

### 10.2 Agents use the same mechanism
- Each `Agent` declares its built-in secrets through the same model, replacing today's special-case code:
  - `ClaudeAgent`: `CLAUDE_OAUTH` (keychain `Claude Code-credentials` → file `~/.claude/.credentials.json`, used only when no API key is present) and `ANTHROPIC_API_KEY` (env → env, optional);
  - `CodexAgent`: `OPENAI_API_KEY`.
- **Missing values:**
  - an optional built-in secret is simply skipped;
  - a missing **user-declared** secret is an error at `run`, with a message naming the secret and its source.
- **Conflicts:** a user entry with the same name overrides the agent's built-in one.

### 10.3 Delivery and visibility
- **Never in the image:** secrets are never baked into the image and never in the spec hash.
- **Delivery:** at box start, via env (`docker exec -e`, per session) or `put_archive` files.
- **Refresh:** re-read and refreshed on every session attach (§8.2), so rotated tokens are picked up. Files are rewritten atomically.
- **No secret values anywhere in Bulbi's output:** never logged, never in the audit log, never in error messages (secret values are redacted).
- **`bulbi check` lists them** in a "Secrets entering the box" table: name, from/source, to/path, and whether the value is currently available on the host (✓/✗). It never shows values.
- **Threat model, stated in `check` output and the docs:** the agent can read the secrets it is given. The network policy limits where it can send them.

### 10.4 Future (not this phase): `to = "inject"`
The gateway adds the secret to requests for the listed `hosts` via TLS interception (a per-box CA trusted only inside the box), so the agent never sees the value. Specced separately.

### 10.5 Tests
- **Unit:**
  - parsing the inline and table forms, and defaults;
  - every validation error: unknown `from`/`to`, missing `path`, a path outside home;
  - each source reader with fakes (env, file, keychain, command incl. timeout and failure);
  - built-in agent secrets and user override;
  - redaction in errors;
  - `check` table output.
- **Docker:**
  - an env secret visible as `$NAME` in a session;
  - a file secret at its path with mode 600;
  - a rotated host value picked up by the next session.
