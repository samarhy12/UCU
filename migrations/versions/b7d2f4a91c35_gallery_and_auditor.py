"""Gallery photos, the Auditor on the executive list, and better executive details

Revision ID: b7d2f4a91c35
Revises: a7c3e91d2b40
Create Date: 2026-09-24 09:00:00.000000

* creates the gallery_photo table and adds the first two photos
* adds Mr. Frederick Budu as Auditor (only when that position is still empty)
* adds the area each leader looks after to the short descriptions and uses "Madam" as in the
  by-laws. Only descriptions and titles that still have the original text are changed, so
  anything the administrator has edited is left alone.
"""
from alembic import op
import sqlalchemy as sa


revision = 'b7d2f4a91c35'
down_revision = 'a7c3e91d2b40'
branch_labels = None
depends_on = None

OLD_BIOS = {
    'Agyare Emmanuel': ('Leads the union and guides its vision and direction.',
                        'Chairman of the union. Zone leader for overseas and isolated areas.'),
    'Theresa Oppong': ("Keeps the union's records and looks after communication with members.",
                       'Secretary of the union. Zone leader for Bepong, Asakraka, Tafo and its environs.'),
    'Patricia Konadu': ('Handles loan requests with fairness and care for every member.',
                        'Loan Officer. Zone leader for Atibie, Mpraeso and Obo.'),
    'Felix Boakye': ("Looks after the union's money and financial planning.",
                     'Finance Director. Zone leader for Accra.'),
}


def upgrade():
    bind = op.get_bind()

    op.create_table(
        'gallery_photo',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=120), nullable=False),
        sa.Column('caption', sa.String(length=300), nullable=True),
        sa.Column('photo', sa.String(length=255), nullable=False),
        sa.Column('display_order', sa.Integer(), server_default='0', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    gallery = sa.table('gallery_photo', sa.column('title', sa.String), sa.column('caption', sa.String),
                       sa.column('photo', sa.String), sa.column('display_order', sa.Integer))
    op.bulk_insert(gallery, [
        {'title': 'Trustees visit Rock City', 'caption': 'Our trustees on a visit to Rock City.',
         'photo': 'trustees-rock-city.jpg', 'display_order': 1},
        {'title': 'Executives in an online meeting', 'caption': 'The executive board meeting online.',
         'photo': 'executives-online-meeting.jpg', 'display_order': 2},
    ])

    executive = sa.table('executive', sa.column('position', sa.String), sa.column('full_name', sa.String),
                         sa.column('title', sa.String), sa.column('bio', sa.String),
                         sa.column('photo', sa.String), sa.column('display_order', sa.Integer))
    has_auditor = bind.execute(sa.text("SELECT COUNT(*) FROM executive WHERE position = 'Auditor'")).scalar()
    if not has_auditor:
        op.bulk_insert(executive, [{
            'position': 'Auditor', 'title': 'Mr.', 'full_name': 'Frederick Budu',
            'bio': 'Auditor of the union. Zone leader for Kumasi.',
            'photo': 'auditor.jpg', 'display_order': 5}])

    for name, (old, new) in OLD_BIOS.items():
        bind.execute(sa.text('UPDATE executive SET bio = :new WHERE full_name = :n AND bio = :old'),
                     {'new': new, 'n': name, 'old': old})
    bind.execute(sa.text("UPDATE executive SET title = 'Madam' WHERE title = 'Mrs.' "
                         "AND full_name IN ('Theresa Oppong', 'Patricia Konadu')"))


def downgrade():
    op.execute(sa.text("DELETE FROM executive WHERE full_name = 'Frederick Budu' AND photo = 'auditor.jpg'"))
    op.drop_table('gallery_photo')
