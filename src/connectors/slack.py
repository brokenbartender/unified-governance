from __future__ import annotations

from .base import ConnectorBase, ConnectorMeta, register_connector


class SlackConnector(ConnectorBase):
    meta = ConnectorMeta(
        name="slack",
        version="0.1",
        description="Slack connector (mock)",
        capabilities=["channels", "messages", "files"],
    )

    def sample_resources(self):
        return [
            {"external_id": "slack-channel-1", "name": "#security", "type": "channel", "attributes": {"sensitivity": "high"}},
            {"external_id": "slack-message-1", "name": "Incident update", "type": "message", "attributes": {"sensitivity": "high"}},
        ]


register_connector(SlackConnector())
