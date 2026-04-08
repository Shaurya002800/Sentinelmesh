from __future__ import annotations

import random
from dataclasses import dataclass

from config import MANUAL_TAMPER_FILE, SIMULATION_MODE, TAMPER_PROBABILITY


@dataclass
class TamperState:
    triggered: bool
    source: str
    touch_count: int


class TamperSensor:
    def __init__(self, seed: int = 7) -> None:
        self.rng = random.Random(seed)

    def _consume_manual_trigger(self) -> TamperState | None:
        if MANUAL_TAMPER_FILE.exists():
            MANUAL_TAMPER_FILE.unlink(missing_ok=True)
            return TamperState(triggered=True, source="manual-flag", touch_count=1)
        return None

    def read(self) -> TamperState:
        manual = self._consume_manual_trigger()
        if manual is not None:
            return manual

        if SIMULATION_MODE:
            triggered = self.rng.random() < TAMPER_PROBABILITY
            return TamperState(
                triggered=triggered,
                source="simulated-touch" if triggered else "idle",
                touch_count=self.rng.randint(1, 3) if triggered else 0,
            )

        return TamperState(triggered=False, source="hardware-idle", touch_count=0)
