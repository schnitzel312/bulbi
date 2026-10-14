"""The escape suite (spec §6.2): attempts from inside a real box, whitelist and blacklist.

Needs Docker and internet access. Every attempt runs as the box user unless noted.
"""

from __future__ import annotations

import json
import socket
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import docker
import pytest

from bulbi.agents.ports import ExecResult
from bulbi.cli.context import AppContext
from bulbi.sandbox import BoxOrchestrator
from tests.docker.conftest import (
    ESCAPE_TOOLS,
    RUN_ID,
    TEST_LABEL,
    box_name,
    free_port,
    write_spec,
)
from tests.repos import make_repo

TOOLS = ["curl", "git", "ssh", "dig", "nc", "python", "nft", "ip"]


@dataclass
class Box:
    orchestrator: BoxOrchestrator
    container: docker.models.containers.Container
    gateway: docker.models.containers.Container
    root: Path

    def sh(self, command: str, user: str = "bulbi") -> ExecResult:
        result = self.container.exec_run(
            ["timeout", "20", "bash", "-c", command], user=user, workdir=str(self.root)
        )
        return ExecResult(result.exit_code, result.output.decode(errors="replace"))

    def log(self) -> list[dict]:
        log = self.root / ".bulbi" / "proxy.log"
        return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]

    def logged(self, predicate, timeout: float = 5.0) -> bool:
        """Whether a matching audit entry appears (firewall events are written async)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(predicate(entry) for entry in self.log()):
                return True
            time.sleep(0.2)
        return False


def _start(client, root: Path, name: str) -> Box:
    app = AppContext(project_root=root, tools=ESCAPE_TOOLS)
    orchestrator = app.orchestrator(app.load_spec())
    running = orchestrator.ensure()
    container = client.containers.get(running.id)
    gateway = client.containers.get(orchestrator.identity.gateway_name)
    return Box(orchestrator, container, gateway, root)


# ---- whitelist -------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def whitelist(docker_client, echo_server, tmp_path_factory) -> Iterator[Box]:
    root = make_repo(tmp_path_factory.mktemp("whitelist") / "app")
    write_spec(
        root,
        box_name("wl"),
        allow=["pypi.org", "github.com", "*.github.com", f"host:{echo_server}",
               "1.1.1.1:53/udp", "localtest.me"],
        deny=["gist.github.com"],
        tools=TOOLS,
    )  # fmt: skip
    yield _start(docker_client, root, box_name("wl"))


@pytest.fixture(scope="module")
def canary(docker_client) -> Iterator[docker.models.containers.Container]:
    container = docker_client.containers.run(
        "debian:bookworm-slim",
        ["sleep", "600"],
        detach=True,
        labels={TEST_LABEL: RUN_ID},
        name=f"bulbitest-canary-{RUN_ID}",
    )
    container.reload()
    yield container
    container.remove(force=True)


def test_https_to_allowed_domain_works_without_proxy_config(whitelist):
    result = whitelist.sh(
        "env | grep -ci proxy; curl -sS -o /dev/null -w '%{http_code}' https://pypi.org/simple/pip/"
    )
    assert result.output.strip().endswith("200"), result.output
    assert result.output.startswith("0")  # no proxy variables at all


def test_git_and_ssh_to_allowed_names(whitelist):
    git = whitelist.sh("git ls-remote https://github.com/git/git HEAD")
    assert git.exit_code == 0 and "HEAD" in git.output, git.output
    ssh = whitelist.sh(
        "ssh -T -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 git@github.com"
    )
    # Reaching the authentication step proves port 22 connected to an allowed name.
    assert "Permission denied (publickey)" in ssh.output or "successfully" in ssh.output, (
        ssh.output
    )


def test_denied_subdomain_does_not_resolve_and_is_logged(whitelist):
    result = whitelist.sh("curl -sS https://gist.github.com")
    assert result.exit_code == 6, result.output  # could not resolve host
    assert whitelist.logged(
        lambda e: (
            e["domain"] == "gist.github.com"
            and e["reason"] == "denied_by_rule"
            and e["method"] == "DNS"
        )
    )


def test_host_service_on_allowed_port_echoes_and_is_logged(whitelist, echo_server):
    result = whitelist.sh(f"echo ping | nc -w 5 host.bulbi.internal {echo_server}")
    assert result.output.strip() == "ping", result.output
    assert whitelist.logged(
        lambda e: e["method"] == "TCP" and e["port"] == echo_server and e["action"] == "allow"
    ), whitelist.log()[-5:]


def test_host_service_on_other_port_is_refused(whitelist):
    result = whitelist.sh(f"nc -z -w 5 host.bulbi.internal {free_port()}; echo rc=$?")
    assert "rc=1" in result.output, result.output


def test_unlisted_domain_by_name_and_by_raw_ip_are_both_blocked(whitelist):
    by_name = whitelist.sh("curl -sS -m 10 https://example.com")
    assert by_name.exit_code == 6, by_name.output
    address = socket.gethostbyname("example.com")
    pinned = whitelist.sh(
        f"curl -sS -m 10 --resolve example.com:443:{address} https://example.com"
    )
    assert pinned.exit_code == 7, pinned.output  # connection refused, not a hang


def test_raw_socket_to_unlisted_address_is_refused(whitelist):
    script = "import socket; socket.create_connection(('1.1.1.1', 443), timeout=5)"
    result = whitelist.sh(f'python -c "{script}"')
    assert "ConnectionRefusedError" in result.output, result.output


def test_alternate_resolver_is_redirected_to_bulbi_dns(whitelist):
    result = whitelist.sh("dig +time=5 +tries=1 @8.8.8.8 example.com")
    assert "status: NXDOMAIN" in result.output, result.output


def test_allowed_udp_resolver_still_answers(whitelist):
    result = whitelist.sh("dig +time=5 +tries=1 @1.1.1.1 pypi.org")
    assert "status: NOERROR" in result.output and "ANSWER SECTION" in result.output, result.output


def test_host_lan_canary_and_metadata_addresses_are_refused(whitelist, canary):
    canary_ip = canary.attrs["NetworkSettings"]["IPAddress"]
    for address in ("172.17.0.1", canary_ip, "169.254.169.254"):
        result = whitelist.sh(f"nc -z -w 5 {address} 80; echo rc=$?")
        assert "rc=1" in result.output, (address, result.output)


def test_allowed_name_resolving_to_loopback_is_stripped(whitelist):
    result = whitelist.sh("dig +short localtest.me")
    assert result.output.strip() == "", result.output


@pytest.mark.parametrize("user", ["bulbi", "root"])
def test_firewall_and_routes_cannot_be_changed_from_the_box(whitelist, user):
    flush = whitelist.sh("nft flush ruleset", user=user)
    route = whitelist.sh("ip route del default", user=user)
    assert flush.exit_code != 0 and "Operation not permitted" in flush.output, flush.output
    assert route.exit_code != 0 and "Operation not permitted" in route.output, route.output


def test_git_hooks_and_config_are_read_only(whitelist):
    hooks = whitelist.sh("echo evil > .git/hooks/pre-commit")
    config = whitelist.sh("echo evil >> .git/config")
    assert hooks.exit_code != 0 and "Read-only" in hooks.output, hooks.output
    assert config.exit_code != 0 and "Read-only" in config.output, config.output


def test_nothing_can_connect_into_the_box(whitelist, canary):
    whitelist.container.exec_run(
        ["python3", "-m", "http.server", "8000"], user="bulbi", detach=True
    )
    whitelist.gateway.reload()
    networks = whitelist.gateway.attrs["NetworkSettings"]["Networks"]
    gateway_ip = next(iter(networks.values()))["IPAddress"]
    inside = whitelist.sh("sleep 1; curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/")
    assert inside.output.strip() == "200"  # the listener is up inside the box
    attempt = canary.exec_run(
        ["timeout", "5", "bash", "-c", f"echo > /dev/tcp/{gateway_ip}/8000 && echo CONNECTED"]
    )
    assert b"CONNECTED" not in attempt.output, attempt.output


def test_stopping_the_gateway_leaves_the_box_without_network(whitelist):
    whitelist.gateway.stop(timeout=5)
    result = whitelist.sh("curl -sS -m 10 -o /dev/null https://pypi.org/simple/pip/")
    assert result.exit_code != 0, result.output


# ---- blacklist -------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def blacklist(docker_client, tmp_path_factory) -> Iterator[Box]:
    root = make_repo(tmp_path_factory.mktemp("blacklist") / "app")
    write_spec(root, box_name("bl"), default="allow", allow=[], deny=["example.com"], tools=TOOLS)
    yield _start(docker_client, root, box_name("bl"))


def test_blacklist_allows_public_https(blacklist):
    result = blacklist.sh("curl -sS -o /dev/null -w '%{http_code}' https://pypi.org/simple/pip/")
    assert result.output.strip() == "200", result.output


def test_blacklist_denies_listed_domain(blacklist):
    assert blacklist.sh("curl -sS -m 10 https://example.com").exit_code == 6


def test_blacklist_allows_any_protocol_on_any_port_to_public_hosts(blacklist):
    script = (
        "import socket; socket.create_connection(('portquiz.net', 5672), timeout=10); print('OK')"
    )
    result = blacklist.sh(f'python -c "{script}"')
    assert "OK" in result.output, result.output


def test_blacklist_still_blocks_host_without_a_host_rule(blacklist, echo_server):
    result = blacklist.sh(f"nc -z -w 5 host.bulbi.internal {echo_server}; echo rc=$?")
    assert "rc=1" in result.output, result.output


def test_blacklist_still_strips_loopback_answers(blacklist):
    assert blacklist.sh("dig +short localtest.me").output.strip() == ""
