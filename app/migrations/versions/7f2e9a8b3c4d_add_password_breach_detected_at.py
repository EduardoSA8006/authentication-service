"""add password_breach_detected_at to users (N-5)

Revision ID: 7f2e9a8b3c4d
Revises: daaf0c9e1d69
Create Date: 2026-04-18
"""

import sqlalchemy as sa
from alembic import op

revision = "7f2e9a8b3c4d"
down_revision = "daaf0c9e1d69"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "password_breach_detected_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "password_breach_detected_at")
