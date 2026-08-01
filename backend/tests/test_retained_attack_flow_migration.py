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
RETAINED_FLOW_IDS = [
    "PATH-ANNOCTR-APT28-ZEBROCY-2020",
    "PATH-ANNOCTR-APT29-DNC-2015",
    "PATH-ANNOCTR-LAZARUS-REDBANC-2018",
]


def test_migration_discards_legacy_flows_without_reapplying_after_cutover(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "argus_cti.db"
    with sqlite3.connect(
        REPOSITORY_ROOT / "data" / "argus_cti.db"
    ) as source_connection, sqlite3.connect(database_path) as target_connection:
        source_connection.backup(target_connection)

    with sqlite3.connect(database_path) as connection:
        connection.execute("DELETE FROM schema_migrations WHERE version = 15")
        connection.execute(
            """
            INSERT INTO activity_paths (
                id, name, description, activity_key, path_kind,
                review_state, reviewer_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "PATH-EXPERIMENT-DISCARD",
                "discarded model experiment",
                "not retained",
                "experiment:discard",
                "historical",
                "draft",
                "none",
            ),
        )
        connection.execute(
            """
            UPDATE activity_path_edges
            SET edge_type = 'branch'
            WHERE path_id = 'PATH-ANNOCTR-LAZARUS-REDBANC-2018'
              AND source_node_id = 'PATH-ANNOCTR-LAZARUS-REDBANC-2018-N-03'
            """
        )
        migration = MIGRATION_PATH.read_text(encoding="utf-8")
        connection.executescript(migration)
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
        lazarus_types = {
            row[0]
            for row in connection.execute(
                """
                SELECT edge_type
                FROM activity_path_edges
                WHERE path_id = 'PATH-ANNOCTR-LAZARUS-REDBANC-2018'
                """
            )
        }

    assert flow_ids == [*RETAINED_FLOW_IDS, "PATH-FUTURE-PUBLISHED"]
    assert "branch" not in lazarus_types
    assert "causes" in lazarus_types
