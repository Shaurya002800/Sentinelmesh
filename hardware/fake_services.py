from __future__ import annotations

from typing import Dict, List

from config import FAKE_SERVICES


class FakeServiceRegistry:
    def __init__(self) -> None:
        self.services: List[Dict[str, object]] = FAKE_SERVICES

    def list_services(self) -> List[Dict[str, object]]:
        return self.services

    def get_banner(self, port: int) -> str:
        for service in self.services:
            if service["port"] == port:
                return str(service["banner"])
        return "Unknown service"
