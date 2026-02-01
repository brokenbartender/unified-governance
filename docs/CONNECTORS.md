# Connector SDK

## Purpose
Provide a simple pattern for adding connector metadata and sample resources.

## Structure
- `src/connectors/base.py` registry + base class
- `src/connectors/snowflake.py` sample warehouse connector
- `src/connectors/google_drive.py` sample file connector
- `src/connectors/okta.py` sample identity connector
- `src/connectors/aws_cloudtrail.py` sample audit connector
- `src/connectors/box.py` sample file connector
- `src/connectors/salesforce.py` sample CRM connector
- `src/connectors/slack.py` sample collaboration connector
- `src/connectors/jira.py` sample ticketing connector

## API
- `GET /connectors` list connector metadata
- `GET /connectors/{name}/sample` return sample resources

## Next Steps
- Add real credentials and ingestion
- Add webhook or polling support
- Add sync loop that uses `source_system` + `external_id`
