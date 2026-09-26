import os
import tempfile

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask_migrate import upgrade, downgrade
from sqlalchemy import create_engine, inspect, text

from extensions import db


def test_migrations_build_the_same_schema_as_the_models(app):
    """Running every migration on an empty database must give exactly the schema the models describe."""
    path = os.path.join(tempfile.mkdtemp(), "fresh.db")
    original = app.config["SQLALCHEMY_DATABASE_URI"]
    engine = create_engine(f"sqlite:///{path}")
    # point Flask-Migrate at the scratch database for this test
    from flask_migrate import Migrate
    import alembic.command as command
    from alembic.config import Config as AlembicConfig

    cfg = AlembicConfig(os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations", "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{path}")

    # env.py of Flask-Migrate reads the engine from the app, so run the same steps manually instead
    from alembic.script import ScriptDirectory
    from alembic.runtime.migration import MigrationContext as MC
    from alembic.operations import Operations
    script = ScriptDirectory.from_config(cfg)
    revisions = list(reversed(list(script.walk_revisions())))
    assert [r.revision for r in revisions] == ["869f0fbcf447", "a7c3e91d2b40", "b7d2f4a91c35", "c4e8a1d06f72"]

    with engine.begin() as conn:
        ctx = MC.configure(conn, opts={"render_as_batch": True})
        with Operations.context(ctx):
            for rev in revisions:
                rev.module.upgrade()
        diff = compare_metadata(MC.configure(conn), db.metadata)
    assert diff == [], diff

    names = set(inspect(engine).get_table_names())
    assert {"user", "loan", "contribution", "cycle", "dividend", "executive", "advert", "loan_payment",
            "audit_log", "app_setting", "gallery_photo", "home_slide", "monthly_transaction", "monthly_savings_target"} <= names
    with engine.connect() as conn:
        assert conn.execute(text("select count(*) from executive")).scalar() == 6
        assert conn.execute(text("select count(*) from gallery_photo")).scalar() == 2
        assert conn.execute(text("select full_name from executive where position = 'Auditor'")).scalar() == "Frederick Budu"
        assert conn.execute(text("select full_name from executive where position = 'Trustee'")).scalar() == "Amofa Debrah"
        assert conn.execute(text("select photo from executive where full_name = 'Felix Boakye'")).scalar() == "felix-boakye.jpg"
        assert conn.execute(text("select count(*) from home_slide")).scalar() == 3
        assert conn.execute(text("select value from app_setting where key = 'greeting_active'")).scalar() == "1"
