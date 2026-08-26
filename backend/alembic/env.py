from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

from app.core.config import DATABASE_URL
from app.database.base import Base

# Import the models package so all SQLAlchemy models are registered
# with Base.metadata before Alembic compares the database schema.
import app.models  # noqa: F401


# ============================================================
# ALEMBIC CONFIGURATION
# ============================================================

config = context.config


# ============================================================
# LOGGING
# ============================================================

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


# ============================================================
# DATABASE URL
# ============================================================

# Use the same DATABASE_URL already used by the FastAPI application.
config.set_main_option(
    "sqlalchemy.url",
    DATABASE_URL,
)


# ============================================================
# SQLALCHEMY METADATA
# ============================================================

# Alembic uses this to detect model changes automatically.
target_metadata = Base.metadata


# ============================================================
# OFFLINE MIGRATIONS
# ============================================================

def run_migrations_offline() -> None:
    """
    Run migrations without creating a live database connection.
    """

    url = config.get_main_option(
        "sqlalchemy.url"
    )

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={
            "paramstyle": "named"
        },
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ============================================================
# ONLINE MIGRATIONS
# ============================================================

def run_migrations_online() -> None:
    """
    Run migrations using a live database connection.
    """

    configuration = config.get_section(
        config.config_ini_section,
    )

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


# ============================================================
# ENTRY POINT
# ============================================================

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()