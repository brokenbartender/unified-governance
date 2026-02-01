# Alembic

This directory is pre-scaffolded for manual SQL migrations.

## Usage
1. Create a revision directory in `migrations/versions/`.
2. Write SQL in the revision file.
3. Apply with Alembic (offline or online).

The `env.py` uses `DB_URL` when provided, otherwise it falls back to `DB_PATH`.
