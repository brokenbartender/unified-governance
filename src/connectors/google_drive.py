from __future__ import annotations

from typing import Any, Dict, List

from .base import ConnectorBase, ConnectorMeta, register_connector


class GoogleDriveConnector(ConnectorBase):
    meta = ConnectorMeta(
        name="google-drive",
        version="0.1.0",
        description="Google Drive connector for file-level governance metadata.",
        capabilities=["catalog", "sharing-audit", "classification"],
    )

    def sample_resources(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "Q4-Financials.xlsx",
                "type": "file",
                "attributes": {
                    "sensitivity": "high",
                    "shared_with": ["board@example.com"],
                    "owner": "finance",
                },
            }
        ]


register_connector(GoogleDriveConnector())
