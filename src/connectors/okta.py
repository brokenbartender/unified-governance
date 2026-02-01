from __future__ import annotations

from typing import Any, Dict, List

from .base import ConnectorBase, ConnectorMeta, register_connector


class OktaConnector(ConnectorBase):
    meta = ConnectorMeta(
        name="okta",
        version="0.1.0",
        description="Okta connector for identity governance metadata.",
        capabilities=["users", "groups", "scim"],
    )

    def sample_resources(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "okta-user-alice",
                "type": "identity",
                "attributes": {
                    "sensitivity": "low",
                    "group": "engineering",
                },
                "source_system": "okta",
                "external_id": "00u123",
            }
        ]


register_connector(OktaConnector())
