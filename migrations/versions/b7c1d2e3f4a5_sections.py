"""sections: home page tiles grouping forms (IT Requests, IT Incidents, Change Management)

Revision ID: b7c1d2e3f4a5
Revises: a48b55b124bf
Create Date: 2026-11-02 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b7c1d2e3f4a5'
down_revision = 'a48b55b124bf'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('section',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=False),
    sa.Column('prefix', sa.String(length=5), nullable=False),
    sa.Column('color', sa.String(length=20), nullable=False),
    sa.Column('icon', sa.String(length=20), nullable=False),
    sa.Column('position', sa.Integer(), nullable=False),
    sa.Column('core_only', sa.Boolean(), nullable=False),
    sa.Column('closed_label', sa.String(length=30), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    # Raw ADD COLUMN ... REFERENCES: SQLite allows it without rebuilding the table. A batch rebuild would have to
    # DROP TABLE form, which the app's PRAGMA foreign_keys=ON refuses while form_version rows point at it.
    for table in ('form', 'ticket'):
        op.execute(f'ALTER TABLE {table} ADD COLUMN section_id INTEGER REFERENCES section (id)')
    with op.batch_alter_table('form', schema=None) as batch_op:  # plain ADD COLUMN, no rebuild
        batch_op.add_column(sa.Column('position', sa.Integer(), server_default='0', nullable=False))


def downgrade():
    # ponytail: batch rebuild like the older migrations; on SQLite it needs PRAGMA foreign_keys=OFF to drop form
    with op.batch_alter_table('ticket', schema=None) as batch_op:
        batch_op.drop_constraint('fk_ticket_section_id', type_='foreignkey')
        batch_op.drop_column('section_id')

    with op.batch_alter_table('form', schema=None) as batch_op:
        batch_op.drop_constraint('fk_form_section_id', type_='foreignkey')
        batch_op.drop_column('section_id')
        batch_op.drop_column('position')

    op.drop_table('section')
