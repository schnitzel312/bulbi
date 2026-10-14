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
Start, in order (each step registered for teardown first):
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
