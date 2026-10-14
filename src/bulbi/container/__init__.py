"""Docker containers that host a box.

Import from the submodules directly. This package deliberately re-exports nothing,
because ``bulbi.agents`` depends on the low-level ``container.execution`` and
``container.files`` modules while ``container.environment`` refers to agents.
"""

from __future__ import annotations
