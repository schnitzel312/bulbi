"""Secrets entering the box: declarations, host readers, box deliveries (spec §10)."""

from __future__ import annotations

from bulbi.secrets.delivery import EnvDelivery, FileDelivery, SecretDeliveries, SecretDelivery
from bulbi.secrets.model import ResolvedSecret, SecretDeclaration
from bulbi.secrets.plan import SecretError, SecretPlan, SecretStatus, user_declarations
from bulbi.secrets.sources import (
    CommandReader,
    EnvReader,
    FileReader,
    KeychainReader,
    SecretReader,
    SecretReaders,
    SecretUnavailableError,
)

__all__ = [
    "CommandReader",
    "EnvDelivery",
    "EnvReader",
    "FileDelivery",
    "FileReader",
    "KeychainReader",
    "ResolvedSecret",
    "SecretDeclaration",
    "SecretDeliveries",
    "SecretDelivery",
    "SecretError",
    "SecretPlan",
    "SecretReader",
    "SecretReaders",
    "SecretStatus",
    "SecretUnavailableError",
    "user_declarations",
]
