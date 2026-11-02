"""HOD approval links and support groups

Revision ID: c8d9e0f1a2b3
Revises: b7c1d2e3f4a5
Create Date: 2026-11-02 14:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c8d9e0f1a2b3'
down_revision = 'b7c1d2e3f4a5'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('support_group',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('group_member',
    sa.Column('group_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['group_id'], ['support_group.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('group_id', 'user_id')
    )
    # Plain ADD COLUMNs only: SQLite can't rebuild form/ticket while the app's PRAGMA foreign_keys=ON is in force.
    op.execute('ALTER TABLE ticket ADD COLUMN group_id INTEGER REFERENCES support_group (id)')
    op.execute('ALTER TABLE form ADD COLUMN default_group_id INTEGER REFERENCES support_group (id)')
    op.add_column('form', sa.Column('auto_submit', sa.Boolean(), server_default='0', nullable=False))
    op.add_column('ticket_approval', sa.Column('via_email', sa.Boolean(), server_default='0', nullable=False))
    op.add_column('ticket_approval', sa.Column('token_hash', sa.String(length=64), nullable=True))
    op.add_column('ticket_approval', sa.Column('link_sent_at', sa.DateTime(), nullable=True))
    op.add_column('ticket_approval', sa.Column('link_expires', sa.DateTime(), nullable=True))
    op.create_index('ix_ticket_approval_token_hash', 'ticket_approval', ['token_hash'])
    op.add_column('user', sa.Column('hod_email', sa.String(length=255), nullable=True))


def downgrade():
    # ponytail: batch rebuild like the older migrations; on SQLite it needs PRAGMA foreign_keys=OFF to drop form
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('hod_email')
    op.drop_index('ix_ticket_approval_token_hash', table_name='ticket_approval')
    with op.batch_alter_table('ticket_approval', schema=None) as batch_op:
        for col in ('link_expires', 'link_sent_at', 'token_hash', 'via_email'):
            batch_op.drop_column(col)
    with op.batch_alter_table('form', schema=None) as batch_op:
        batch_op.drop_column('auto_submit')
        batch_op.drop_column('default_group_id')
    with op.batch_alter_table('ticket', schema=None) as batch_op:
        batch_op.drop_column('group_id')
    op.drop_table('group_member')
    op.drop_table('support_group')
