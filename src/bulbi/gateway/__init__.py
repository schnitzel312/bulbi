"""The network gateway that owns a box's network namespace.

Everything in this package is standard-library only, because it is also copied into
the gateway image. Host-side Docker orchestration lives in ``bulbi.container``.
"""

from __future__ import annotations
