"""UCU v2: annual cycles, dividends, loan types, executives, adverts, audit log

Revision ID: a7c3e91d2b40
Revises: 869f0fbcf447
Create Date: 2026-09-23 12:00:00.000000

This migration keeps every existing row. It only adds columns and tables, then fills the new
columns for the rows that are already there:

* user.is_guest / is_admin / is_verified - empty (NULL) values on old rows become False
* user.member_number   - numbered 1, 2, 3 ... in order of sign-up for verified members
* loan.loan_type       - worked out from the number of days (and whether the applicant is a
                         non-member). 47-day loans are labelled DS when they were applied for in
                         Nov-Jan and ECA when applied for in Feb-May.
* loan.reference       - LN + year + loan number, for example LN240012
* executive            - the four leaders that were shown on the old About page

The stored interest rates, totals and balances of existing loans are not changed.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a7c3e91d2b40'
down_revision = '869f0fbcf447'
branch_labels = None
depends_on = None


def _legacy_loan_type(term_days, is_guest, month):
    if is_guest:
        return 'nm_installment' if term_days and term_days >= 100 else 'nm_emergency'
    if term_days and term_days >= 100:
        return 'installment'
    if term_days and term_days <= 35:
        return 'emergency'
    return 'eca' if month in (2, 3, 4, 5) else 'ds'


def upgrade():
    bind = op.get_bind()

    # ------------------------------------------------------------------ new tables
    op.create_table(
        'cycle',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('start_year', sa.Integer(), nullable=False),
        sa.Column('label', sa.String(length=9), nullable=False),
        sa.Column('start_date', sa.Date(), nullable=False),
        sa.Column('end_date', sa.Date(), nullable=False),
        sa.Column('status', sa.String(length=10), nullable=False),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
        sa.Column('dividend_rate', sa.Float(), nullable=True),
        sa.Column('dividend_declared_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('label'),
        sa.UniqueConstraint('start_year'),
    )
    op.create_table(
        'dividend',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('cycle_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('contribution_total', sa.Float(), nullable=False),
        sa.Column('rate', sa.Float(), nullable=False),
        sa.Column('amount', sa.Float(), nullable=False),
        sa.Column('status', sa.String(length=10), nullable=False),
        sa.Column('paid_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['cycle_id'], ['cycle.id']),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cycle_id', 'user_id', name='uq_dividend_cycle_user'),
    )
    with op.batch_alter_table('dividend', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_dividend_cycle_id'), ['cycle_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_dividend_user_id'), ['user_id'], unique=False)

    op.create_table(
        'executive',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('position', sa.String(length=60), nullable=False),
        sa.Column('full_name', sa.String(length=120), nullable=False),
        sa.Column('title', sa.String(length=20), nullable=True),
        sa.Column('bio', sa.String(length=300), nullable=True),
        sa.Column('phone', sa.String(length=30), nullable=True),
        sa.Column('email', sa.String(length=120), nullable=True),
        sa.Column('photo', sa.String(length=255), nullable=True),
        sa.Column('display_order', sa.Integer(), server_default='0', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'advert',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=120), nullable=False),
        sa.Column('body', sa.String(length=500), nullable=True),
        sa.Column('image', sa.String(length=255), nullable=True),
        sa.Column('link_url', sa.String(length=255), nullable=True),
        sa.Column('start_date', sa.Date(), nullable=True),
        sa.Column('end_date', sa.Date(), nullable=True),
        sa.Column('is_active', sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column('display_order', sa.Integer(), server_default='0', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'app_setting',
        sa.Column('key', sa.String(length=50), nullable=False),
        sa.Column('value', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('key'),
    )
    op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('actor_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('target', sa.String(length=120), nullable=True),
        sa.Column('detail', sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(['actor_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_log_created_at'), ['created_at'], unique=False)

    op.create_table(
        'loan_payment',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('loan_id', sa.Integer(), nullable=False),
        sa.Column('amount', sa.Float(), nullable=False),
        sa.Column('date', sa.DateTime(), nullable=True),
        sa.Column('receipt_no', sa.String(length=30), nullable=True),
        sa.Column('recorded_by', sa.Integer(), nullable=True),
        sa.Column('note', sa.String(length=200), nullable=True),
        sa.Column('is_reversed', sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column('reversed_at', sa.DateTime(), nullable=True),
        sa.Column('reversed_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['loan_id'], ['loan.id']),
        sa.ForeignKeyConstraint(['recorded_by'], ['user.id']),
        sa.ForeignKeyConstraint(['reversed_by'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('loan_payment', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_loan_payment_loan_id'), ['loan_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_loan_payment_receipt_no'), ['receipt_no'], unique=True)

    # ------------------------------------------------------------------ user
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_active', sa.Boolean(), server_default=sa.true(), nullable=False))
        batch_op.add_column(sa.Column('hometown', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('introducer', sa.String(length=150), nullable=True))
        batch_op.add_column(sa.Column('nok_name', sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column('nok_phone', sa.String(length=30), nullable=True))
        batch_op.add_column(sa.Column('nok_relationship', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('member_number', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('created_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('verified_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('deactivated_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('must_change_password', sa.Boolean(), server_default=sa.false(), nullable=False))
        batch_op.add_column(sa.Column('failed_login_attempts', sa.Integer(), server_default='0', nullable=False))
        batch_op.add_column(sa.Column('locked_until', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('last_login_at', sa.DateTime(), nullable=True))
        # Newer password hashing methods can produce hashes longer than 128 characters.
        batch_op.alter_column('password_hash', existing_type=sa.String(length=128),
                              type_=sa.String(length=255), existing_nullable=True)
        batch_op.create_index(batch_op.f('ix_user_member_number'), ['member_number'], unique=True)

    # ------------------------------------------------------------------ contribution
    with op.batch_alter_table('contribution', schema=None) as batch_op:
        batch_op.add_column(sa.Column('receipt_no', sa.String(length=30), nullable=True))
        batch_op.add_column(sa.Column('recorded_by', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('note', sa.String(length=200), nullable=True))
        batch_op.create_foreign_key('fk_contribution_recorded_by_user', 'user', ['recorded_by'], ['id'])
        batch_op.create_index(batch_op.f('ix_contribution_receipt_no'), ['receipt_no'], unique=True)

    # ------------------------------------------------------------------ loan
    with op.batch_alter_table('loan', schema=None) as batch_op:
        batch_op.add_column(sa.Column('loan_type', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('reference', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('guarantor_earnings', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('guarantor2_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('guarantor2_earnings', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('cancelled_date', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('decision_note', sa.String(length=255), nullable=True))
        # A guarantor who has died can be removed from the system without deleting the loan.
        batch_op.alter_column('guarantor_id', existing_type=sa.Integer(), nullable=True)
        batch_op.create_foreign_key('fk_loan_guarantor2_user', 'user', ['guarantor2_id'], ['id'])
        batch_op.create_index(batch_op.f('ix_loan_reference'), ['reference'], unique=True)

    # ------------------------------------------------------------------ fill new columns for existing rows
    # Rows created before the guest feature have NULL in these yes/no columns; make them plain False
    # so that "is this a guest / admin / verified" questions always get a clear answer.
    for column in ('is_guest', 'is_admin', 'is_verified'):
        bind.execute(sa.text(f'UPDATE "user" SET {column} = 0 WHERE {column} IS NULL'))
    bind.execute(sa.text("UPDATE monthly_savings_target SET is_active = 0 WHERE is_active IS NULL"))

    # Members are numbered in the order they signed up.
    member_ids = [r[0] for r in bind.execute(sa.text(
        'SELECT id FROM "user" WHERE is_verified = 1 AND COALESCE(is_guest, 0) = 0 '
        'AND COALESCE(is_admin, 0) = 0 ORDER BY id')).fetchall()]
    for number, user_id in enumerate(member_ids, start=1):
        bind.execute(sa.text('UPDATE "user" SET member_number = :n WHERE id = :i'),
                     {'n': number, 'i': user_id})

    loans = bind.execute(sa.text(
        'SELECT l.id, l.term, COALESCE(u.is_guest, 0), l.application_date '
        'FROM loan l JOIN "user" u ON u.id = l.user_id ORDER BY l.id')).fetchall()
    for loan_id, term, is_guest, applied in loans:
        applied_text = str(applied) if applied else ''
        month = int(applied_text[5:7]) if len(applied_text) >= 7 and applied_text[5:7].isdigit() else 12
        year2 = applied_text[2:4] if len(applied_text) >= 4 and applied_text[2:4].isdigit() else '00'
        bind.execute(
            sa.text('UPDATE loan SET loan_type = :t, reference = :r WHERE id = :i'),
            {'t': _legacy_loan_type(term, bool(is_guest), month), 'r': f'LN{year2}{loan_id:04d}', 'i': loan_id})

    # ------------------------------------------------------------------ starting content
    executive = sa.table(
        'executive',
        sa.column('position', sa.String), sa.column('full_name', sa.String), sa.column('title', sa.String),
        sa.column('bio', sa.String), sa.column('photo', sa.String), sa.column('display_order', sa.Integer))
    already = bind.execute(sa.text('SELECT COUNT(*) FROM executive')).scalar()
    if not already:
        op.bulk_insert(executive, [
            {'position': 'Chairman', 'title': 'Mr.', 'full_name': 'Agyare Emmanuel',
             'bio': 'Leads the union and guides its vision and direction.',
             'photo': 'chairman.jpg', 'display_order': 1},
            {'position': 'Secretary', 'title': 'Mrs.', 'full_name': 'Theresa Oppong',
             'bio': 'Keeps the union\'s records and looks after communication with members.',
             'photo': 'secretary.jpg', 'display_order': 2},
            {'position': 'Loan Officer', 'title': 'Mrs.', 'full_name': 'Patricia Konadu',
             'bio': 'Handles loan requests with fairness and care for every member.',
             'photo': 'loan-officer.jpg', 'display_order': 3},
            {'position': 'Finance Director', 'title': 'Mr.', 'full_name': 'Felix Boakye',
             'bio': 'Looks after the union\'s money and financial planning.',
             'photo': 'finance-director.jpg', 'display_order': 4},
        ])

    op.execute(sa.text("INSERT INTO app_setting (key, value) VALUES ('loan_open_ds', '0'), ('loan_open_eca', '0')"))


def downgrade():
    with op.batch_alter_table('loan', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_loan_reference'))
        batch_op.drop_constraint('fk_loan_guarantor2_user', type_='foreignkey')
        batch_op.alter_column('guarantor_id', existing_type=sa.Integer(), nullable=False)
        batch_op.drop_column('decision_note')
        batch_op.drop_column('cancelled_date')
        batch_op.drop_column('guarantor2_earnings')
        batch_op.drop_column('guarantor2_id')
        batch_op.drop_column('guarantor_earnings')
        batch_op.drop_column('reference')
        batch_op.drop_column('loan_type')

    with op.batch_alter_table('contribution', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_contribution_receipt_no'))
        batch_op.drop_constraint('fk_contribution_recorded_by_user', type_='foreignkey')
        batch_op.drop_column('note')
        batch_op.drop_column('recorded_by')
        batch_op.drop_column('receipt_no')

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_member_number'))
        batch_op.alter_column('password_hash', existing_type=sa.String(length=255),
                              type_=sa.String(length=128), existing_nullable=True)
        batch_op.drop_column('last_login_at')
        batch_op.drop_column('locked_until')
        batch_op.drop_column('failed_login_attempts')
        batch_op.drop_column('must_change_password')
        batch_op.drop_column('deactivated_at')
        batch_op.drop_column('verified_at')
        batch_op.drop_column('created_at')
        batch_op.drop_column('member_number')
        batch_op.drop_column('nok_relationship')
        batch_op.drop_column('nok_phone')
        batch_op.drop_column('nok_name')
        batch_op.drop_column('introducer')
        batch_op.drop_column('hometown')
        batch_op.drop_column('is_active')

    with op.batch_alter_table('loan_payment', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_loan_payment_receipt_no'))
        batch_op.drop_index(batch_op.f('ix_loan_payment_loan_id'))
    op.drop_table('loan_payment')

    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_log_created_at'))
    op.drop_table('audit_log')
    op.drop_table('app_setting')
    op.drop_table('advert')
    op.drop_table('executive')

    with op.batch_alter_table('dividend', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_dividend_user_id'))
        batch_op.drop_index(batch_op.f('ix_dividend_cycle_id'))
    op.drop_table('dividend')
    op.drop_table('cycle')
