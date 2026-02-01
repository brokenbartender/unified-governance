from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class ConnectorMeta:
    name: str
    version: str
    description: str
    capabilities: List[str]


class ConnectorBase:
    meta: ConnectorMeta

    def sample_resources(self) -> List[Dict[str, Any]]:
        raise NotImplementedError


_CONNECTORS: Dict[str, ConnectorBase] = {}


def register_connector(connector: ConnectorBase) -> None:
    _CONNECTORS[connector.meta.name] = connector


def list_connectors() -> List[ConnectorMeta]:
    return [connector.meta for connector in _CONNECTORS.values()]


def get_connector(name: str) -> ConnectorBase | None:
    return _CONNECTORS.get(name)
