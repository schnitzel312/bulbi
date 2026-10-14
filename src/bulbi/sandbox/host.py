"""Facts about the machine running Bulbi."""

from __future__ import annotations

import os
import platform

from bulbi.gateway.config import HostAccess

LINUX_SYSTEM_NAME = "Linux"


def detect_host_access(system: str | None = None) -> HostAccess:
    """Linux needs the CLI's relay; Docker Desktop (macOS, Windows) has its own gateway."""
    if (system or platform.system()) == LINUX_SYSTEM_NAME:
        return HostAccess.BRIDGE_RELAY
    return HostAccess.DOCKER_DESKTOP


def current_user() -> tuple[int, int] | None:
    """The host user's (uid, gid), so files the gateway writes stay theirs."""
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    return (getuid(), getgid()) if getuid and getgid else None
