"""Coding agents that can run inside a box."""

from __future__ import annotations

from bulbi.agents.base import Agent, UnmanagedAgent
from bulbi.agents.claude import ClaudeAgent
from bulbi.agents.codex import CodexAgent
from bulbi.agents.credentials import (
    CredentialProvider,
    KeychainCredentialProvider,
    NoCredentialProvider,
)
from bulbi.agents.ports import ContainerHandle, ExecResult
from bulbi.agents.registry import AgentRegistry

__all__ = [
    "Agent",
    "AgentRegistry",
    "ClaudeAgent",
    "CodexAgent",
    "ContainerHandle",
    "CredentialProvider",
    "ExecResult",
    "KeychainCredentialProvider",
    "NoCredentialProvider",
    "UnmanagedAgent",
]
