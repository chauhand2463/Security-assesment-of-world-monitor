"""Schema verification: the Alembic migration must reproduce every table, and
verify_schema() must fail loudly on an unmigrated database while never itself
creating tables."""

import os
import tempfile

from sqlalchemy import create_engine, inspect, text

from database.connection import engine, verify_schema
from database.models import Base

EXPECTED_TABLES = set(Base.metadata.tables.keys())
HEAD_REVISION = "e6f8a1c3d5b7"


def test_all_models_mapped_to_tables():
    assert EXPECTED_TABLES == {
        "users",
        "projects",
        "assets",
        "scans",
        "tool_results",
        "vulnerabilities",
        "reports",
        "chat_history",
        "sessions",
        "observations",
        "assessment_tests",
        "finding_evidence",
        "finding_status_history",
        "report_exports",
        "tool_readiness",
        "tool_executions",
        "scan_stages",
        "scan_events",
        "finding_validations",
        "finding_observation_links",
        "verifications",
        "ml_inferences",
        "world_monitor_targets",
        "world_monitor_api_endpoints",
        "scan_attempts",
        "scan_executions",
    }


def test_migrated_db_has_all_tables_plus_alembic_version():
    names = set(inspect(engine).get_table_names())
    assert EXPECTED_TABLES <= names
    assert "alembic_version" in names


def test_alembic_version_is_at_head():
    with engine.connect() as conn:
        row = conn.execute(text("select version_num from alembic_version")).first()
    assert row is not None
    assert row[0] == HEAD_REVISION


def test_verify_schema_passes_on_migrated_db():
    verify_schema(engine)


def test_verify_schema_raises_on_blank_db():
    blank_path = os.path.join(tempfile.mkdtemp(prefix="cyberagent_blank_"), "blank.db")
    blank = create_engine(f"sqlite:///{blank_path.replace(os.sep, '/')}")
    try:
        verify_schema(blank)
        raise AssertionError("verify_schema should raise on an empty database")
    except RuntimeError as exc:
        assert "alembic upgrade head" in str(exc)
    finally:
        blank.dispose()
        if os.path.exists(blank_path):
            os.remove(blank_path)


def test_verify_schema_never_creates_tables():
    dirname = tempfile.mkdtemp(prefix="cyberagent_nocreate_")
    db_path = os.path.join(dirname, "nocreate.db")
    probe = create_engine(f"sqlite:///{db_path.replace(os.sep, '/')}")
    try:
        verify_schema(probe)
        raise AssertionError("expected verify_schema to raise")
    except RuntimeError:
        pass
    assert inspect(probe).get_table_names() == []
    probe.dispose()