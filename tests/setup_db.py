"""Cria o banco de teste + roda migrations. Idempotente.

Uso: poetry run python tests/setup_db.py
"""
import asyncio
import os
import sys
from pathlib import Path

# Load .env.test first — MUST happen before app.* imports
_env_file = Path(__file__).parent / ".env.test"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        stripped = line.strip()
        if "=" in stripped and not stripped.startswith("#"):
            k, v = stripped.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"'))


async def ensure_database_exists() -> None:
    import asyncpg

    target = os.environ["POSTGRES_DB"]
    conn = await asyncpg.connect(
        host=os.environ["POSTGRES_HOST"],
        port=int(os.environ["POSTGRES_PORT"]),
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        database="postgres",
    )
    exists = await conn.fetchval(
        "SELECT 1 FROM pg_database WHERE datname=$1", target,
    )
    if not exists:
        await conn.execute(f'CREATE DATABASE "{target}"')
        print(f"Created database: {target}")
    else:
        print(f"Database already exists: {target}")
    await conn.close()


def run_migrations() -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
    print("Migrations applied.")


if __name__ == "__main__":
    asyncio.run(ensure_database_exists())
    run_migrations()
    print("Test DB ready.")
    sys.exit(0)
