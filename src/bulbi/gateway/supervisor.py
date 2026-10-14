"""The gateway's privileged half: applies firewall entries and writes the audit log.

The gateway runs two processes. The **supervisor** (root, ``CAP_NET_ADMIN``) loads the
ruleset, adds DNS-learned entries and writes every audit line; it never opens a network
connection. The **resolver** (an unprivileged uid, the only one the firewall exempts,
and only towards Docker's DNS) answers queries and reports what it learned over a pipe.
The supervisor does not trust those reports: it re-derives every entry from the name
with its own policy matcher.

Standard-library only: it runs in the gateway image.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
import threading
from collections.abc import Callable, Iterable
from dataclasses import asdict
from typing import IO, Any

from bulbi.gateway.audit import AuditLogWriter, LogEntry, timestamp
from bulbi.gateway.firewall import FirewallBackend
from bulbi.gateway.nflog import ConnectionAttempt
from bulbi.gateway.policy import NetworkPolicy, PolicyMatcher
from bulbi.gateway.protected import is_protected
from bulbi.gateway.resolver import ResolverSink, address_entries
from bulbi.gateway.rules import IPAddress

logger = logging.getLogger(__name__)

NFT_COMMAND = ("nft", "-f", "-")
LEARNED = "learned"
AUDIT = "audit"
_UNKNOWN_PROTOCOL = "IP"

CommandRunner = Callable[..., "subprocess.CompletedProcess[str]"]


class FirewallLoader:
    """Feeds nftables scripts to ``nft -f -``."""

    def __init__(self, runner: CommandRunner = subprocess.run) -> None:
        self._run = runner

    def load(self, script: str) -> None:
        if not script.strip():
            return
        result = self._run(list(NFT_COMMAND), input=script, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"nft failed: {result.stderr.strip()}")


class PipeSink(ResolverSink):
    """The resolver side of the pipe: one JSON message per line."""

    def __init__(self, stream: IO[str]) -> None:
        self._stream = stream
        self._lock = threading.Lock()

    def learned(self, name: str, records: list[tuple[IPAddress, int]]) -> None:
        self._send({"kind": LEARNED, "name": name, "records": [[str(a), t] for a, t in records]})

    def audit(self, entry: LogEntry) -> None:
        self._send({"kind": AUDIT, "entry": asdict(entry)})

    def _send(self, message: dict[str, Any]) -> None:
        with self._lock:
            self._stream.write(json.dumps(message) + "\n")
            self._stream.flush()


class Supervisor:
    """Turns resolver reports and firewall log events into firewall entries and audit lines."""

    def __init__(
        self,
        policy: NetworkPolicy,
        matcher: PolicyMatcher,
        backend: FirewallBackend,
        firewall: FirewallLoader,
        audit: AuditLogWriter,
        clock: Callable[[], str] = timestamp,
    ) -> None:
        self._policy = policy
        self._matcher = matcher
        self._backend = backend
        self._firewall = firewall
        self._audit = audit
        self._timestamp = clock
        self._names: dict[IPAddress, str] = {}

    # ---- resolver reports ----------------------------------------------------------

    def consume(self, lines: Iterable[str]) -> None:
        """Handle every message from the resolver pipe until it closes."""
        for line in lines:
            self.handle_message(line)

    def handle_message(self, line: str) -> None:
        try:
            message = json.loads(line)
            if message["kind"] == LEARNED:
                self.learned(str(message["name"]), message["records"])
            elif message["kind"] == AUDIT:
                self._audit.write(LogEntry.from_mapping(message["entry"]))
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning("ignoring malformed resolver message: %s", exc)

    def learned(self, name: str, records: Iterable[Iterable[Any]]) -> None:
        """Pin (or block) the vetted answers of ``name``, re-checked against the policy."""
        coverage = self._matcher.name_coverage(name)
        if not coverage.resolvable:
            logger.warning("resolver reported a denied name %r; ignored", name)
            return
        entries = []
        for address_text, ttl in records:
            address = ipaddress.ip_address(address_text)
            if is_protected(address) and not self._matcher.address_allowed_by_rule(address):
                logger.warning("resolver reported protected %s for %r; ignored", address, name)
                continue
            self._names[address] = name
            entries.extend(address_entries(self._matcher, coverage, address, int(ttl)))
        self._firewall.load(self._backend.render_entries(entries))

    # ---- firewall log ----------------------------------------------------------------

    def record_attempt(self, attempt: ConnectionAttempt) -> None:
        rule = None
        if attempt.tag.rule_id is not None and attempt.tag.rule_id < len(self._policy.rules):
            rule = str(self._policy.rules[attempt.tag.rule_id][1])
        protocol = attempt.protocol
        url = str(attempt.address)
        if attempt.port is not None:
            url = f"{url}:{attempt.port}"
        self._audit.write(
            LogEntry(
                timestamp=self._timestamp(),
                domain=self._names.get(attempt.address, str(attempt.address)),
                action=attempt.tag.action,
                method=protocol.upper() if protocol else _UNKNOWN_PROTOCOL,
                url=url,
                reason=attempt.tag.reason,
                rule=rule,
                ip=str(attempt.address),
                port=attempt.port,
                proto=protocol,
            )
        )
