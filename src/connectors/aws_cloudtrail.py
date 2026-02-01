from __future__ import annotations

from typing import Any, Dict, List

from .base import ConnectorBase, ConnectorMeta, register_connector


class CloudTrailConnector(ConnectorBase):
    meta = ConnectorMeta(
        name="aws-cloudtrail",
        version="0.1.0",
        description="AWS CloudTrail connector for audit events metadata.",
        capabilities=["audit", "events"],
    )

    def sample_resources(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "cloudtrail-event-1",
                "type": "audit-event",
                "attributes": {
                    "event": "AssumeRole",
                    "sensitivity": "medium",
                },
                "source_system": "aws-cloudtrail",
                "external_id": "evt-123",
            }
        ]


register_connector(CloudTrailConnector())
