from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool, text

from alembic import context

from app.core.config import settings
from app.core.database import Base


# Statement-timeout defensivo em produção: impede que um DDL ruim segure
# locks por horas e derrube o serviço. 60s cobre qualquer migration
# razoável (CREATE INDEX CONCURRENTLY, ADD COLUMN, etc); queries além
# disso são provavelmente "ALTER TABLE rewriting 100M rows" e devem
# bloquear na PR review, não em produção. Offline mode não precisa
# porque o SQL é só impresso.
_STATEMENT_TIMEOUT_MS = 60_000

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", settings.database_url_sync)

target_metadata = Base.metadata


# compare_type + compare_server_default: autogenerate detecta mudança de
# tipo (String(120) → String(200), Integer → BigInteger) e de server_default.
# Sem isso, alterações silenciosas no ORM não geram migration — schema drifta
# entre dev e prod e só aparece em query errors ou no `alembic check`.


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        # SET LOCAL statement_timeout: aplica só para a transação atual;
        # não afeta outras sessões nem persiste depois do commit. Em
        # produção com banco gerenciado (RDS, Cloud SQL) protege contra
        # DDL que segura locks por horas e causa incident response.
        # Migrations individuais podem override com `op.execute(
        # "SET LOCAL statement_timeout = '300s'")` quando sabem que vão
        # rodar operação legítima mais longa (ex: backfill em grande tabela).
        if settings.is_production:
            connection.execute(text(
                f"SET LOCAL statement_timeout = '{_STATEMENT_TIMEOUT_MS}ms'"
            ))

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
