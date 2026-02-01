from __future__ import annotations

from .base import ConnectorBase, ConnectorMeta, register_connector


class SalesforceConnector(ConnectorBase):
    meta = ConnectorMeta(
        name="salesforce",
        version="0.1",
        description="Salesforce connector (mock)",
        capabilities=["accounts", "opportunities", "cases"],
    )

    def sample_resources(self):
        return [
            {"external_id": "sf-account-1", "name": "Acme Corp", "type": "account", "attributes": {"sensitivity": "medium"}},
            {"external_id": "sf-case-1", "name": "Support Case 1201", "type": "case", "attributes": {"sensitivity": "high"}},
        ]


register_connector(SalesforceConnector())
