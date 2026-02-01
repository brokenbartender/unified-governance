from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from src.settings import settings

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

url = settings.db_url
if not url:
    db_path = settings.db_path
    if db_path.startswith("./"):
        db_path = os.path.abspath(db_path)
    url = f"sqlite:///{db_path}"


target_metadata = None


def run_migrations_offline() -> None:
    context.configure(
        url=url,
        literal_binds=True,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(url)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
