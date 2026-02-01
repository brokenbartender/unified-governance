from __future__ import annotations

from typing import Any, Dict, List

from .base import ConnectorBase, ConnectorMeta, register_connector


class SnowflakeConnector(ConnectorBase):
    meta = ConnectorMeta(
        name="snowflake",
        version="0.1.0",
        description="Snowflake connector for warehouse governance metadata.",
        capabilities=["catalog", "lineage", "policy-enforcement"],
    )

    def sample_resources(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "PROD_CUSTOMERS",
                "type": "table",
                "attributes": {
                    "warehouse": "analytics",
                    "sensitivity": "high",
                    "owner": "data-platform",
                },
                "source_system": "snowflake",
                "external_id": "snowflake-table-prod_customers",
            }
        ]


register_connector(SnowflakeConnector())
