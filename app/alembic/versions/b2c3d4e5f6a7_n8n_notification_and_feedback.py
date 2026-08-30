"""n8n notification and feedback tables (Phase 2B)

Revision ID: b2c3d4e5f6a7
Revises: 9ec2a1b4b3bf
Create Date: 2026-08-30

Phase 2B — n8n SOAR Workflow Integration:
* notification_attempts — outbound webhook attempts, duplicate prevention, audit
* analyst_feedback — analyst acknowledgement/feedback via n8n callback
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "b2c3d4e5f6a7"
down_revision = "9ec2a1b4b3bf"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_attempts",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("error_type", sa.String(length=128), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("webhook_host", sa.String(length=255), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.alert_id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("notification_attempts", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_notification_attempts_alert_id"), ["alert_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_notification_attempts_attempted_at"), ["attempted_at"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_notification_attempts_status"), ["status"], unique=False
        )

    op.create_table(
        "analyst_feedback",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("verdict", sa.String(length=64), nullable=False),
        sa.Column("notes", sa.String(length=2000), nullable=True),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.alert_id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("analyst_feedback", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_analyst_feedback_alert_id"), ["alert_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_analyst_feedback_received_at"), ["received_at"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_analyst_feedback_verdict"), ["verdict"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("analyst_feedback", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_analyst_feedback_verdict"))
        batch_op.drop_index(batch_op.f("ix_analyst_feedback_received_at"))
        batch_op.drop_index(batch_op.f("ix_analyst_feedback_alert_id"))
    op.drop_table("analyst_feedback")

    with op.batch_alter_table("notification_attempts", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_notification_attempts_status"))
        batch_op.drop_index(batch_op.f("ix_notification_attempts_attempted_at"))
        batch_op.drop_index(batch_op.f("ix_notification_attempts_alert_id"))
    op.drop_table("notification_attempts")
