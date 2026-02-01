# Connector SDK

## Purpose
Provide a simple pattern for adding connector metadata and sample resources.

## Structure
- `src/connectors/base.py` registry + base class
- `src/connectors/snowflake.py` sample warehouse connector
- `src/connectors/google_drive.py` sample file connector

## API
- `GET /connectors` list connector metadata
- `GET /connectors/{name}/sample` return sample resources

## Next Steps
- Add real credentials and ingestion
- Add webhook or polling support
