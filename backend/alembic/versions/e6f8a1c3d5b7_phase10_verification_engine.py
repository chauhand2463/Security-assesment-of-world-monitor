"""phase10_verification_engine (additive)

Adds the Phase 10.6 verification engine schema:

  * ``vulnerabilities.verification_state`` (default ``unverified``) which only
    flips to ``verified``/``failed``/``not_applicable`` after the deterministic
    re-check re-ran over persisted observations,
  * a new ``verifications`` table: one append-only row per re-check run.

Additive only: both the column and the table are new; existing findings keep a
default ``unverified`` state (honest -- they predate the engine), and no
existing rows or behaviour change.

Revision ID: e6f8a1c3d5b7
Revises: d3e7a9c2b4f6
Create Date: 2026-09-23 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e6f8a1c3d5b7'
down_revision: Union[str, Sequence[str], None] = 'd3e7a9c2b4f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'vulnerabilities',
        sa.Column('verification_state',
                  sa.String(length=30), nullable=False, server_default='unverified'),
    )
    op.create_table(
        'verifications',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('scan_id', sa.Integer(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('finding_id', sa.Integer(), sa.ForeignKey('vulnerabilities.id'), nullable=True),
        sa.Column('method', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('rule_id', sa.String(length=100), nullable=True),
        sa.Column('condition', sa.Text(), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('observation_ids', sa.JSON(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_verifications_scan_id', 'verifications', ['scan_id'])
    op.create_index('ix_verifications_finding_id', 'verifications', ['finding_id'])


def downgrade() -> None:
    op.drop_index('ix_verifications_finding_id', table_name='verifications')
    op.drop_index('ix_verifications_scan_id', table_name='verifications')
    op.drop_table('verifications')
    op.drop_column('vulnerabilities', 'verification_state')