"""Shared constants for Bulbi."""

from __future__ import annotations

# platform.system() on macOS (Docker Desktop host).
MACOS_SYSTEM_NAME = "Darwin"

# Container filesystem layout.
CONTAINER_USER = "bulbi"
CONTAINER_HOME = f"/home/{CONTAINER_USER}"
CONTAINER_WORKSPACE = f"{CONTAINER_HOME}/workspace"
ENTRYPOINT_PATH = "/entrypoint.sh"

# Docker labels used to identify Bulbi-managed resources.
DOCKER_LABEL = "bulbi"
DOCKER_LABEL_VALUE = "true"
DOCKER_LABEL_BOX = "bulbi.box"
DOCKER_LABEL_ROLE = "bulbi.role"
DOCKER_LABEL_PROJECT = "bulbi.project"
DOCKER_LABEL_PROFILE = "bulbi.profile"
DOCKER_LABEL_SPEC_HASH = "bulbi.spec_hash"
GATEWAY_ROLE = "gateway"

# Agent launched when the spec does not name one.
DEFAULT_AGENT = "claude"

# How long an idle box keeps running before its watcher stops it.
DEFAULT_IDLE_TIMEOUT = "10m"

# Default resource limits.
DEFAULT_CPU = 2
DEFAULT_MEMORY = "4GB"

# Spec file.
SPEC_VERSION = "0.1"
SPEC_FILENAME = "bulbi.toml"

# Host interface the network proxy listens on (see TODO(bulbi) in container/environment.py).
PROXY_BIND_HOST = "127.0.0.1"

# Proxy log directory (relative to project root).
LOG_DIR = ".bulbi"
LOG_FILENAME = "proxy.log"
