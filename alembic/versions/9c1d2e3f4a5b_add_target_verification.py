"""add target verification

Revision ID: 9c1d2e3f4a5b
Revises: f23a8ad783b2
Create Date: 2026-10-28 22:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "9c1d2e3f4a5b"
down_revision: str | Sequence[str] | None = "f23a8ad783b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("targets") as batch:
        batch.add_column(sa.Column("verification_token", sa.String(64), nullable=True))
        batch.add_column(sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("targets") as batch:
        batch.drop_column("verified_at")
        batch.drop_column("verification_token")
