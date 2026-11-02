"""SLA rules, automatic priority, raise change from tickets

Revision ID: d1e2f3a4b5c6
Revises: c8d9e0f1a2b3
Create Date: 2026-11-02 18:00:00.000000

"""
import json

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd1e2f3a4b5c6'
down_revision = 'c8d9e0f1a2b3'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('sla_rule',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('section_id', sa.Integer(), nullable=True),
    sa.Column('form_id', sa.Integer(), nullable=True),
    sa.Column('priority', sa.String(length=20), nullable=True),
    sa.Column('respond_minutes', sa.Integer(), nullable=True),
    sa.Column('resolve_minutes', sa.Integer(), nullable=True),
    sa.Column('round_the_clock', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['form_id'], ['form.id'], ),
    sa.ForeignKeyConstraint(['section_id'], ['section.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # Plain ADD COLUMNs only: SQLite can't rebuild form/ticket while the app's PRAGMA foreign_keys=ON is in force.
    op.add_column('ticket', sa.Column('responded_at', sa.DateTime(), nullable=True))
    op.add_column('ticket', sa.Column('sla_alerts', sa.JSON(), server_default='[]', nullable=False))
    op.add_column('form', sa.Column('priority_rules', sa.JSON(), server_default='[]', nullable=False))
    op.add_column('section', sa.Column('raise_from_tickets', sa.Boolean(), server_default='0', nullable=False))

    # New permission sla.escalate: give it to every profile that can already manage users (the admins).
    conn = op.get_bind()
    for pid, perms in conn.execute(sa.text("SELECT id, permissions FROM permission_profile")).fetchall():
        perms = json.loads(perms) if isinstance(perms, str) else perms
        if "user.manage" in perms and "sla.escalate" not in perms:
            conn.execute(sa.text("UPDATE permission_profile SET permissions = :p WHERE id = :id"),
                         {"p": json.dumps(perms + ["sla.escalate"]), "id": pid})


def downgrade():
    # ponytail: batch rebuild like the older migrations; on SQLite it needs PRAGMA foreign_keys=OFF to drop form
    with op.batch_alter_table('section', schema=None) as batch_op:
        batch_op.drop_column('raise_from_tickets')
    with op.batch_alter_table('form', schema=None) as batch_op:
        batch_op.drop_column('priority_rules')
    with op.batch_alter_table('ticket', schema=None) as batch_op:
        batch_op.drop_column('sla_alerts')
        batch_op.drop_column('responded_at')
    op.drop_table('sla_rule')
