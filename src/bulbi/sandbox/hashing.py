"""The spec hash that decides whether a running box is still current (spec §8.1)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

from bulbi.spec import BulbiSpec

_HASH_LENGTH = 16


class SpecHasher:
    """Hashes everything that shapes a box: images, mounts, network, limits, agent, idling.

    Mount *configuration* counts (paths, modes, excludes, which checkouts are mounted),
    but not which files currently match an exclude: a new ``.env`` must not make an
    otherwise identical box look outdated.
    """

    def hash(
        self,
        spec: BulbiSpec,
        box_image: str,
        gateway_image: str,
        checkout_roots: Sequence[Path],
    ) -> str:
        inputs = {
            "images": [box_image, gateway_image],
            "agent": spec.box.agent,
            "idle_timeout": spec.box.idle_timeout,
            "mounts": [[m.path, m.mode, list(m.exclude)] for m in spec.mounts],
            "checkouts": [str(root) for root in checkout_roots],
            "network": [spec.network.default, spec.network.allow, spec.network.deny],
            "limits": [spec.limits.cpu, spec.limits.memory],
        }
        encoded = json.dumps(inputs, sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()[:_HASH_LENGTH]
