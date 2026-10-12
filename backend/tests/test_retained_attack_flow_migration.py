from __future__ import annotations

from pathlib import Path
import sqlite3


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = (
    REPOSITORY_ROOT
    / "data"
    / "migrations"
    / "015_retained_attack_flows.sql"
)
def test_retention_migration_does_not_reapply_after_cutover(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "argus_cti.db"
    with sqlite3.connect(
        REPOSITORY_ROOT / "data" / "argus_cti.db"
    ) as source_connection, sqlite3.connect(database_path) as target_connection:
        source_connection.backup(target_connection)

    with sqlite3.connect(database_path) as connection:
        baseline_flow_ids = [
            row[0]
            for row in connection.execute(
                "SELECT id FROM activity_paths ORDER BY id"
            )
        ]
        migration = MIGRATION_PATH.read_text(encoding="utf-8")
        connection.execute(
            """
            INSERT INTO activity_paths (
                id, name, description, activity_key, path_kind,
                review_state, reviewer_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "PATH-FUTURE-PUBLISHED",
                "future reviewed flow",
                "published after migration",
                "future:published",
                "historical",
                "published",
                "human",
            ),
        )
        connection.executescript(migration)

        flow_ids = [
            row[0]
            for row in connection.execute(
                "SELECT id FROM activity_paths ORDER BY id"
            )
        ]

    assert flow_ids == sorted([*baseline_flow_ids, "PATH-FUTURE-PUBLISHED"])
