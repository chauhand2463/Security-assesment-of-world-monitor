"""phase12_schedules (additive)

Adds the Phase 12 continuous-assessment schema:

  * ``scan_schedules``: one operator-defined recurrence (cadence, interval,
    enabled, next/last run bookkeeping).  A schedule is a definition, not a
    scan; each due execution creates a fresh ``scans`` row.
  * ``scans.source_schedule_id``: links a scan to the schedule that produced it.
    NULL for interactive/retried scans -- a scan that was never scheduled stays
    honest.

Additive only: no existing rows or columns change; scheduled scans reuse the
existing scan lifecycle and attempt ledger verbatim.

Revision ID: b2a9c4e5f6d8
Revises: e6f8a1c3d5b7
Create Date: 2026-09-24 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b2a9c4e5f6d8'
down_revision: Union[str, Sequence[str], None] = 'e6f8a1c3d5b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'scan_schedules',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.String(length=255), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('project_id', sa.Integer(), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('target', sa.String(length=255), nullable=False),
        sa.Column('cadence', sa.String(length=50), nullable=False, server_default='daily'),
        sa.Column('interval', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('next_run_at', sa.DateTime(), nullable=False),
        sa.Column('last_run_at', sa.DateTime(), nullable=True),
        sa.Column('last_run_status', sa.String(length=50), nullable=True),
        sa.Column('last_scan_id', sa.Integer(), nullable=True),
        sa.Column('config', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_scan_schedules_user_id', 'scan_schedules', ['user_id'])
    op.create_index('ix_scan_schedules_project_id', 'scan_schedules', ['project_id'])
    # SQLite cannot ALTER a table to add a ForeignKey constraint; the column is
    # added without an inline FK and indexed.  The ORM model keeps the FK for
    # ordinary (non-SQLite) backends; referential integrity here is enforced by
    # application logic (lookups), matching the existing additive migrations.
    op.add_column(
        'scans',
        sa.Column('source_schedule_id', sa.Integer(), nullable=True),
    )
    op.create_index('ix_scans_source_schedule_id', 'scans', ['source_schedule_id'])


def downgrade() -> None:
    op.drop_index('ix_scans_source_schedule_id', table_name='scans')
    op.drop_column('scans', 'source_schedule_id')
    op.drop_index('ix_scan_schedules_project_id', table_name='scan_schedules')
    op.drop_index('ix_scan_schedules_user_id', table_name='scan_schedules')
    op.drop_table('scan_schedules')