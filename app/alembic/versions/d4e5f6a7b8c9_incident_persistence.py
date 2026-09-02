"""incident persistence (Phase 3.1)

Revision ID: d4e5f6a7b8c9
Revises: b2c3d4e5f6a7
Create Date: 2026-09-02

Phase 3.1 — first-class incident persistence and automatic incident creation:

* ``incidents`` — one row per open incident: human-readable
  ``INC-YYYY-MM-DD-NNNN`` id (PK, sequential per UTC date), severity
  (SEV1/SEV2), status (``open``), FK to the primary alert that opened it, the
  dedupe group it belongs to, and UTC timestamps. Indexes support the
  "existing open incident for a group" lookup used for recurrence linking.
* ``alerts.incident_id`` — nullable FK from alerts to incidents so each alert
  references the incident it belongs to (recurring/deduplicated alerts attach
  to the existing open incident instead of creating duplicates).

Timestamps are timezone-aware (UTC). Batch mode keeps the same DDL runnable on
SQLite and PostgreSQL later (ARCHITECTURE.md §19). Existing databases upgrade
cleanly: pre-existing alerts simply keep ``incident_id = NULL``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "d4e5f6a7b8c9"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=8), nullable=False),
        sa.Column("primary_alert_id", sa.Uuid(), nullable=False),
        sa.Column("dedupe_group_key", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["primary_alert_id"], ["alerts.alert_id"]),
        sa.PrimaryKeyConstraint("incident_id"),
    )
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_incidents_created_at"), ["created_at"], unique=False)
        batch_op.create_index(
            batch_op.f("ix_incidents_dedupe_group_key"),
            ["dedupe_group_key"],
            unique=False,
        )
        batch_op.create_index(
            "ix_incidents_group_status", ["dedupe_group_key", "status"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_incidents_primary_alert_id"),
            ["primary_alert_id"],
            unique=True,
        )
        batch_op.create_index(batch_op.f("ix_incidents_severity"), ["severity"], unique=False)
        batch_op.create_index(batch_op.f("ix_incidents_status"), ["status"], unique=False)

    with op.batch_alter_table("alerts", schema=None) as batch_op:
        batch_op.add_column(sa.Column("incident_id", sa.String(length=32), nullable=True))
        batch_op.create_foreign_key(
            "fk_alerts_incident_id",
            "incidents",
            ["incident_id"],
            ["incident_id"],
        )
        batch_op.create_index(batch_op.f("ix_alerts_incident_id"), ["incident_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("alerts", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_alerts_incident_id"))
        batch_op.drop_constraint("fk_alerts_incident_id", type_="foreignkey")
        batch_op.drop_column("incident_id")

    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_incidents_status"))
        batch_op.drop_index(batch_op.f("ix_incidents_severity"))
        batch_op.drop_index(batch_op.f("ix_incidents_primary_alert_id"))
        batch_op.drop_index("ix_incidents_group_status")
        batch_op.drop_index(batch_op.f("ix_incidents_dedupe_group_key"))
        batch_op.drop_index(batch_op.f("ix_incidents_created_at"))

    op.drop_table("incidents")
