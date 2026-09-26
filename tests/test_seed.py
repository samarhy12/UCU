import pytest

from extensions import db
from models import Advert, Contribution, Dividend, Loan, User
from tests.conftest import make_member


def test_sample_data_can_be_added_and_removed(app):
    import seed_sample_data as seed
    seed.add()
    assert User.query.filter(User.email.like("%@sample.ucu")).count() == 29
    assert Loan.query.count() == 11 and Contribution.query.count() > 200 and Dividend.query.count() > 0
    assert {l.status for l in Loan.query.all()} == {"pending", "approved", "paid", "rejected", "cancelled"}
    with pytest.raises(SystemExit):
        seed.add()                                   # will not add twice
    seed.remove()
    assert User.query.count() == 0 and Loan.query.count() == 0 and Contribution.query.count() == 0
    assert Advert.query.count() == 0 and Dividend.query.count() == 0


def test_sample_data_refuses_a_database_with_real_members(app):
    import seed_sample_data as seed
    make_member("real@example.com")
    with pytest.raises(SystemExit):
        seed.add()
    assert User.query.filter(User.email.like("%@sample.ucu")).count() == 0
    seed.add(force=True)
    seed.remove()
    assert User.query.filter_by(email="real@example.com").count() == 1      # real member untouched
