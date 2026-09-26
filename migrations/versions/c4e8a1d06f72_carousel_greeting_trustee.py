"""Home page carousel, season greeting, Mr. Amofa Debrah (Trustee) and a new photo for Mr. Boakye

Revision ID: c4e8a1d06f72
Revises: b7d2f4a91c35
Create Date: 2026-09-24 12:00:00.000000

* creates the home_slide table and adds the first three slides
* stores the season greeting (text and poster) as settings, without replacing one that already exists
* adds Mr. Amofa Debrah as Trustee (only when he is not on the list yet)
* points Mr. Felix Boakye to his new photo
"""
from alembic import op
import sqlalchemy as sa


revision = 'c4e8a1d06f72'
down_revision = 'b7d2f4a91c35'
branch_labels = None
depends_on = None

GREETING = {
    'greeting_active': '1',
    'greeting_title': 'A Season of Gratitude & Accomplishment',
    'greeting_intro': ('Thank you to all members of Unity Credit Union for your outstanding cooperation, and '
                       'understanding exhibited throughout the season. Your continued support and trust in us '
                       'have been truly invaluable.'),
    'greeting_callout': ('The Executives of UCU are happy to inform you that all persons have been served except '
                         'for one or two individuals who have abandoned our instructions.'),
    'greeting_closing': ('Thank you all for your wonderful time and membership. We look forward to meeting you '
                         'next season on'),
    'greeting_date': '24th September 2026',
    'greeting_signoff': 'From the Executives, UNITY....!!!',
    'greeting_image': 'season-greetings.jpg',
}


def upgrade():
    bind = op.get_bind()

    op.create_table(
        'home_slide',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=120), nullable=False),
        sa.Column('caption', sa.String(length=200), nullable=True),
        sa.Column('image', sa.String(length=255), nullable=False),
        sa.Column('link_url', sa.String(length=255), nullable=True),
        sa.Column('display_order', sa.Integer(), server_default='0', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    slides = sa.table('home_slide', sa.column('title', sa.String), sa.column('caption', sa.String),
                      sa.column('image', sa.String), sa.column('display_order', sa.Integer))
    op.bulk_insert(slides, [
        {'title': 'Another savings year completed', 'caption': 'Unity Credit Union has ended its annual savings.',
         'image': 'annual-savings-ended.jpg', 'display_order': 1},
        {'title': 'Celebrating 10 years of Unity', 'caption': 'A decade of saving and growing together.',
         'image': 'tenth-anniversary.jpg', 'display_order': 2},
        {'title': 'Unity Credit Union', 'caption': 'Your membership, our proud concern.',
         'image': 'unity-logo.jpg', 'display_order': 3},
    ])

    for key, value in GREETING.items():
        exists = bind.execute(sa.text('SELECT COUNT(*) FROM app_setting WHERE key = :k'), {'k': key}).scalar()
        if not exists:
            bind.execute(sa.text('INSERT INTO app_setting (key, value) VALUES (:k, :v)'), {'k': key, 'v': value})

    executive = sa.table('executive', sa.column('position', sa.String), sa.column('full_name', sa.String),
                         sa.column('title', sa.String), sa.column('bio', sa.String),
                         sa.column('photo', sa.String), sa.column('display_order', sa.Integer))
    has = bind.execute(sa.text("SELECT COUNT(*) FROM executive WHERE full_name = 'Amofa Debrah'")).scalar()
    if not has:
        op.bulk_insert(executive, [{
            'position': 'Trustee', 'title': 'Mr.', 'full_name': 'Amofa Debrah',
            'bio': 'Unity Trustee. Zone leader for Kwahu Praso and its environs.',
            'photo': 'amofa-debrah.jpg', 'display_order': 6}])

    bind.execute(sa.text("UPDATE executive SET photo = 'felix-boakye.jpg' "
                         "WHERE full_name = 'Felix Boakye' AND photo = 'finance-director.jpg'"))


def downgrade():
    op.execute(sa.text("DELETE FROM executive WHERE full_name = 'Amofa Debrah' AND photo = 'amofa-debrah.jpg'"))
    op.execute(sa.text("UPDATE executive SET photo = 'finance-director.jpg' WHERE photo = 'felix-boakye.jpg'"))
    op.execute(sa.text("DELETE FROM app_setting WHERE key LIKE 'greeting_%'"))
    op.drop_table('home_slide')
