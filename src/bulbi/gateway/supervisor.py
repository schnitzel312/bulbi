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
import itertools
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
ACK = "ack"
ACK_TIMEOUT_SECONDS = 2.0
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
    """The resolver side of the pipes: one JSON message per line each way.

    :meth:`learned` blocks until the supervisor acknowledges that the addresses are in
    the firewall, so the box never receives an answer before it can use it.
    """

    def __init__(
        self, stream: IO[str], acks: IO[str], ack_timeout: float = ACK_TIMEOUT_SECONDS
    ) -> None:
        self._stream = stream
        self._lock = threading.Lock()
        self._ack_timeout = ack_timeout
        self._pending: dict[int, threading.Event] = {}
        self._ids = itertools.count(1)
        self._closed = threading.Event()
        threading.Thread(target=self._read_acks, args=(acks,), daemon=True).start()

    def learned(self, name: str, records: list[tuple[IPAddress, int]]) -> None:
        message_id = next(self._ids)
        done = threading.Event()
        self._pending[message_id] = done
        try:
            self._send(
                {
                    "kind": LEARNED,
                    "id": message_id,
                    "name": name,
                    "records": [[str(a), t] for a, t in records],
                }
            )
            if not self._closed.is_set() and not done.wait(self._ack_timeout):
                logger.warning("supervisor did not confirm pins for %r in time", name)
        finally:
            self._pending.pop(message_id, None)

    def _read_acks(self, acks: IO[str]) -> None:
        try:
            for line in acks:
                try:
                    event = self._pending.get(int(json.loads(line)[ACK]))
                except (ValueError, KeyError, TypeError):
                    continue
                if event is not None:
                    event.set()
        finally:
            self._closed.set()
            for event in list(self._pending.values()):
                event.set()

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

    def consume(self, lines: Iterable[str], acks: IO[str] | None = None) -> None:
        """Handle every message from the resolver pipe until it closes, acknowledging pins."""
        for line in lines:
            message_id = self.handle_message(line)
            if message_id is not None and acks is not None:
                acks.write(json.dumps({ACK: message_id}) + "\n")
                acks.flush()

    def handle_message(self, line: str) -> int | None:
        """Apply one resolver message; returns the id to acknowledge, if any."""
        try:
            message = json.loads(line)
            if message["kind"] == AUDIT:
                self._audit.write(LogEntry.from_mapping(message["entry"]))
                return None
            if message["kind"] == LEARNED:
                message_id = message.get("id")
                try:
                    self.learned(str(message["name"]), message["records"])
                finally:
                    # Always acknowledge, even a rejected report, so the resolver never stalls.
                    ack = int(message_id) if message_id is not None else None
                return ack
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            logger.warning("ignoring malformed resolver message: %s", exc)
        return None

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
