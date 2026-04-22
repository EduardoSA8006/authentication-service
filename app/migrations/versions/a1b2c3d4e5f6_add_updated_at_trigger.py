"""add updated_at trigger to users

Revision ID: a1b2c3d4e5f6
Revises: 7f2e9a8b3c4d
Create Date: 2026-04-20
"""

from alembic import op

revision = "a1b2c3d4e5f6"
down_revision = "7f2e9a8b3c4d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = now();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER users_updated_at
        BEFORE UPDATE ON users
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at();
    """)


def downgrade() -> None:
    # Só o trigger é dropado. A função update_updated_at() tem nome genérico
    # e pode estar sendo usada por triggers em outras tabelas criadas por
    # migrations posteriores — dropá-la quebraria aqueles triggers em cascata.
    # Migration seguinte pode dropá-la explicitamente se for a última usuária.
    op.execute("DROP TRIGGER IF EXISTS users_updated_at ON users;")
