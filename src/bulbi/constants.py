"""Shared constants for Bulbi."""

# Container filesystem layout.
CONTAINER_USER = "bulbi"
CONTAINER_HOME = f"/home/{CONTAINER_USER}"
CONTAINER_WORKSPACE = f"{CONTAINER_HOME}/workspace"

# Docker labels used to identify Bulbi-managed resources.
DOCKER_LABEL = "bulbi"
DOCKER_LABEL_BOX = "bulbi.box"

# Agent launched when the spec does not name one.
DEFAULT_AGENT = "claude"

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
