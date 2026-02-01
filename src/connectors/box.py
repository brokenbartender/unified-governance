from __future__ import annotations

from .base import ConnectorBase, ConnectorMeta, register_connector


class BoxConnector(ConnectorBase):
    meta = ConnectorMeta(
        name="box",
        version="0.1",
        description="Box connector (mock)",
        capabilities=["files", "folders", "permissions"],
    )

    def sample_resources(self):
        return [
            {"external_id": "box-file-1", "name": "Quarterly Report.pdf", "type": "file", "attributes": {"sensitivity": "high"}},
            {"external_id": "box-folder-1", "name": "Finance", "type": "folder", "attributes": {"sensitivity": "medium"}},
        ]


register_connector(BoxConnector())
