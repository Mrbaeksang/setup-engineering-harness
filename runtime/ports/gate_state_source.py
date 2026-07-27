"""Port for reading host-controlled Gate state."""

from __future__ import annotations

from typing import Protocol


class GateStateReadError(RuntimeError):
    """The authoritative state could not be read safely."""


class GateStateSource(Protocol):
    def read(self) -> bytes:
        """Return one complete state snapshot or raise GateStateReadError."""
