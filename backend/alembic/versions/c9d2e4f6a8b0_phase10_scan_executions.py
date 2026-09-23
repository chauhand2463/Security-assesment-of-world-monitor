"""Phase 10.3 scan execution batching (additive)

Adds ``scan_executions`` -- the Phase 10.3 parallel-scheduler record of how a
scan's plan was really executed.  One row per real execution of a scan plan
records the scheduling decision (sequential vs parallel), the bounded
concurrency that was applied, the ordered plan, and honest started/completed/
failed/skipped counters observed from tool results.

Revision ID: c9d2e4f6a8b0
Revises: 72835b10a97e
Create Date: 2026-09-23 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c9d2e4f6a8b0'
down_revision: Union[str, Sequence[str], None] = '72835b10a97e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema (additive only)."""
    op.create_table(
        'scan_executions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('strategy', sa.String(length=20), nullable=False),
        sa.Column('max_parallel_tools', sa.Integer(), nullable=False),
        sa.Column('plan', sa.JSON(), nullable=True),
        sa.Column('planned_tools', sa.Integer(), nullable=False),
        sa.Column('started_tools', sa.Integer(), nullable=False),
        sa.Column('completed_tools', sa.Integer(), nullable=False),
        sa.Column('failed_tools', sa.Integer(), nullable=False),
        sa.Column('skipped_tools', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], name='fk_scan_executions_scan_id'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_scan_executions_scan_id', 'scan_executions', ['scan_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_scan_executions_scan_id', table_name='scan_executions')
    op.drop_table('scan_executions')