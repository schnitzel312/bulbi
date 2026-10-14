"""What the CLI tells the gateway container, passed as JSON in one environment variable."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from bulbi.constants import LOG_FILENAME

CONFIG_ENV = "BULBI_GATEWAY_CONFIG"
RESOLVER_UID = 999
LOG_MOUNT = "/var/log/bulbi"
READY_DIR = "/run/bulbi"
READY_FILE = f"{READY_DIR}/ready"
DOCKER_DESKTOP_HOST_NAME = "host.docker.internal"


class HostAccess(StrEnum):
    """How the box reaches the machine running Bulbi (``host`` rules)."""

    DOCKER_DESKTOP = "docker-desktop"  # Docker Desktop's host.docker.internal gateway.
    BRIDGE_RELAY = "bridge-relay"  # Linux: CLI relay on the bridge gateway address.


@dataclass(frozen=True)
class GatewayConfig:
    default: str
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    host_access: HostAccess = HostAccess.DOCKER_DESKTOP
    host_address: str | None = None
    resolver_uid: int = RESOLVER_UID
    log_file: str = f"{LOG_MOUNT}/{LOG_FILENAME}"
    log_owner: tuple[int, int] | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, text: str) -> GatewayConfig:
        data: dict[str, Any] = json.loads(text)
        owner = data.get("log_owner")
        return cls(
            default=data["default"],
            allow=list(data.get("allow", [])),
            deny=list(data.get("deny", [])),
            host_access=HostAccess(data.get("host_access", HostAccess.DOCKER_DESKTOP)),
            host_address=data.get("host_address"),
            resolver_uid=int(data.get("resolver_uid", RESOLVER_UID)),
            log_file=data.get("log_file", cls.log_file),
            log_owner=(int(owner[0]), int(owner[1])) if owner else None,
        )
