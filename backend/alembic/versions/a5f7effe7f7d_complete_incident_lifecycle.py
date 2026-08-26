"""
complete incident lifecycle

Revision ID: a5f7effe7f7d
Revises:
Create Date: 2026-08-26 20:22:30.484745
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a5f7effe7f7d"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Add the new Incident lifecycle fields safely to the
    already-existing incidents table.
    """

    op.add_column(
        "incidents",
        sa.Column(
            "status",
            sa.String(length=50),
            nullable=True,
        ),
    )

    op.add_column(
        "incidents",
        sa.Column(
            "analysis_category",
            sa.String(length=100),
            nullable=True,
        ),
    )

    op.add_column(
        "incidents",
        sa.Column(
            "analysis_risk_level",
            sa.String(length=50),
            nullable=True,
        ),
    )

    op.add_column(
        "incidents",
        sa.Column(
            "analysis_summary",
            sa.Text(),
            nullable=True,
        ),
    )

    op.add_column(
        "incidents",
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=True,
        ),
    )

    op.execute(
        """
        UPDATE incidents
        SET status = 'draft'
        WHERE status IS NULL
        """
    )

    op.execute(
        """
        UPDATE incidents
        SET updated_at = created_at
        WHERE updated_at IS NULL
        """
    )

    op.alter_column(
        "incidents",
        "status",
        existing_type=sa.String(length=50),
        nullable=False,
    )

    op.alter_column(
        "incidents",
        "updated_at",
        existing_type=sa.DateTime(),
        nullable=False,
    )

    op.create_index(
        "ix_incidents_status",
        "incidents",
        ["status"],
        unique=False,
    )

    op.drop_constraint(
        "incidents_user_id_fkey",
        "incidents",
        type_="foreignkey",
    )

    op.create_foreign_key(
        "incidents_user_id_fkey",
        "incidents",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    """
    Reverse the Incident lifecycle migration.
    """

    op.drop_constraint(
        "incidents_user_id_fkey",
        "incidents",
        type_="foreignkey",
    )

    op.create_foreign_key(
        "incidents_user_id_fkey",
        "incidents",
        "users",
        ["user_id"],
        ["id"],
    )

    op.drop_index(
        "ix_incidents_status",
        table_name="incidents",
    )

    op.drop_column(
        "incidents",
        "updated_at",
    )

    op.drop_column(
        "incidents",
        "analysis_summary",
    )

    op.drop_column(
        "incidents",
        "analysis_risk_level",
    )

    op.drop_column(
        "incidents",
        "analysis_category",
    )

    op.drop_column(
        "incidents",
        "status",
    )