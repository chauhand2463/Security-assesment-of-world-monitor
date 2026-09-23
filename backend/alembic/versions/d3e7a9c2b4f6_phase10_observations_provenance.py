"""phase10_observations_provenance (additive)

Adds ``observations.tool_execution_id`` -- the Phase 10.4 provenance link from
each persisted observation back to the exact ``tool_executions`` row that
created it.  Additive only: the column is nullable, existing uploads keep
working, and the backfill below is explicitly best-effort.

Backfill: for every observation, attach the matching execution row (same scan
+ tool) that actually parsed observations (``parsed_observations > 0``) or
completed; when none exists the link stays NULL.  This is honest -- a NULL
provenance means "no ToolExecution row produced this", which is the real state
for Phase 5 engine-native observations that predate tool_executions.

Revision ID: d3e7a9c2b4f6
Revises: c9d2e4f6a8b0
Create Date: 2026-09-23 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd3e7a9c2b4f6'
down_revision: Union[str, Sequence[str], None] = 'c9d2e4f6a8b0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'observations',
        sa.Column('tool_execution_id', sa.Integer(), nullable=True),
    )
    op.create_index('ix_observations_tool_execution_id', 'observations',
                    ['tool_execution_id'], unique=False)

    # Best-effort backfill for pre-Provenance observation rows.
    op.execute("""
        UPDATE observations
        SET tool_execution_id = (
            SELECT te.id FROM tool_executions te
            WHERE te.scan_id = observations.scan_id
              AND te.tool = observations.tool_name
            ORDER BY (CASE WHEN te.parsed_observations > 0 OR te.status = 'completed'
                           THEN 0 ELSE 1 END),
                     te.id DESC
            LIMIT 1
        )
    """)


def downgrade() -> None:
    op.drop_index('ix_observations_tool_execution_id', table_name='observations')
    op.drop_column('observations', 'tool_execution_id')