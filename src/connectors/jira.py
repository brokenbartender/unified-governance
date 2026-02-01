from __future__ import annotations

from .base import ConnectorBase, ConnectorMeta, register_connector


class JiraConnector(ConnectorBase):
    meta = ConnectorMeta(
        name="jira",
        version="0.1",
        description="Jira connector (mock)",
        capabilities=["projects", "issues"],
    )

    def sample_resources(self):
        return [
            {"external_id": "jira-issue-1", "name": "SEC-401", "type": "issue", "attributes": {"sensitivity": "medium"}},
            {"external_id": "jira-project-1", "name": "Security", "type": "project", "attributes": {"sensitivity": "low"}},
        ]


register_connector(JiraConnector())
