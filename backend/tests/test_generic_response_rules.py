from __future__ import annotations

from pathlib import Path
import sqlite3
import subprocess
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DATABASE_PATH = REPOSITORY_ROOT / "data" / "argus_cti.db"
MIGRATION_PATH = (
    REPOSITORY_ROOT
    / "data"
    / "migrations"
    / "021_generic_response_rules.sql"
)


def copy_database(target: Path) -> None:
    with sqlite3.connect(DATABASE_PATH) as source, sqlite3.connect(target) as destination:
        source.backup(destination)


def test_generic_response_rules_are_reproducible(tmp_path: Path) -> None:
    database_path = tmp_path / "argus_cti.db"
    copy_database(database_path)

    with sqlite3.connect(database_path) as connection:
        connection.execute("DELETE FROM response_rules")
        connection.execute("DELETE FROM schema_migrations WHERE version = 21")
        connection.executescript(MIGRATION_PATH.read_text(encoding="utf-8"))

        rules = connection.execute(
            """
            SELECT group_label, COUNT(*)
            FROM response_rules
            WHERE match_entity_type = '*'
            GROUP BY group_label
            """
        ).fetchall()
        version = connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 21"
        ).fetchone()

    assert dict(rules) == {
        "立即遏制": 2,
        "排查狩猎": 2,
        "清除恢复": 1,
        "长期加固": 1,
    }
    assert version == ("generic_configurable_response_rules",)


def test_runtime_reset_preserves_configuration_tables(tmp_path: Path) -> None:
    database_path = tmp_path / "argus_cti.db"
    artifact_root = tmp_path / "artifacts"
    copy_database(database_path)

    subprocess.run(
        [
            sys.executable,
            str(REPOSITORY_ROOT / "scripts" / "reset_argus_runtime.py"),
            "--database",
            str(database_path),
            "--artifact-root",
            str(artifact_root),
        ],
        check=True,
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
    )

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM raw_reports").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM entities").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM response_rules").fetchone() == (6,)
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone() == (22,)
