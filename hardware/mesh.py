from __future__ import annotations

import json
from typing import Any, Dict, List

from config import DEVICE_ID, MESH_ENABLED


class MeshBroadcaster:
    def __init__(self) -> None:
        self.enabled = MESH_ENABLED
        self.broadcast_log: List[Dict[str, Any]] = []

    def broadcast(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        message = {
            "from": DEVICE_ID,
            "mesh_enabled": self.enabled,
            "payload": payload,
        }
        self.broadcast_log.append(message)
        return {
            "mesh_status": "broadcasted" if self.enabled else "disabled",
            "mesh_message": json.dumps(message),
        }
