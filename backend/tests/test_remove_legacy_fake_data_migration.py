from __future__ import annotations

from pathlib import Path
import sqlite3


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = (
    REPOSITORY_ROOT
    / "data"
    / "migrations"
    / "019_remove_legacy_fake_seed_data.sql"
)
FAKE_REPORT_ID = "RPT-CORE-DEMO-INPUT-23397"


def insert_entity(
    connection: sqlite3.Connection,
    entity_id: str,
    *,
    seed_origin: str,
    created_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO entities (
            id, entity_type, canonical_key, label, normalized_value,
            created_at, updated_at, seed_origin
        ) VALUES (?, 'tool', ?, ?, ?, ?, ?, ?)
        """,
        (
            entity_id,
            f"test:{entity_id}",
            entity_id,
            entity_id.lower(),
            created_at,
            created_at,
            seed_origin,
        ),
    )


def test_migration_removes_only_legacy_fake_seed_data(tmp_path: Path) -> None:
    database_path = tmp_path / "argus_cti.db"
    with sqlite3.connect(
        REPOSITORY_ROOT / "data" / "argus_cti.db"
    ) as source_connection, sqlite3.connect(database_path) as target_connection:
        source_connection.backup(target_connection)

    migration = MIGRATION_PATH.read_text(encoding="utf-8")
    with sqlite3.connect(database_path) as connection:
        connection.executescript(migration)
        baseline_foreign_key_violations = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        baseline_flow_ids = [
            row[0]
            for row in connection.execute(
                "SELECT id FROM activity_paths ORDER BY id"
            )
        ]
        connection.execute("DELETE FROM schema_migrations WHERE version = 19")

        insert_entity(
            connection,
            "TEST-LEGACY-ENTITY-A",
            seed_origin="legacy_full_graph_v2",
            created_at="2026-07-20T17:56:32+08:00",
        )
        insert_entity(
            connection,
            "TEST-LEGACY-ENTITY-B",
            seed_origin="",
            created_at="2026-07-20T12:02:47+08:00",
        )
        insert_entity(
            connection,
            "TEST-FUTURE-BLANK-ORIGIN",
            seed_origin="",
            created_at="2026-08-02T12:00:00+08:00",
        )
        connection.execute(
            """
            INSERT INTO relationships (
                id, source_entity_id, target_entity_id, relation_type,
                canonical_key, created_at, updated_at, seed_origin
            ) VALUES (
                'TEST-LEGACY-RELATIONSHIP',
                'TEST-LEGACY-ENTITY-A',
                'TEST-LEGACY-ENTITY-B',
                'uses',
                'test:legacy:relationship',
                '2026-07-20T17:56:32+08:00',
                '2026-07-20T17:56:32+08:00',
                'legacy_full_graph_v2'
            )
            """
        )
        connection.execute(
            """
            INSERT INTO raw_reports (
                id, title, sha256, created_at
            ) VALUES (?, 'fake demo report', 'test-fake-report-sha', ?)
            """,
            (FAKE_REPORT_ID, "2026-07-26T22:00:00+08:00"),
        )
        connection.execute(
            """
            INSERT INTO import_jobs (
                id, report_id, title, created_at, updated_at
            ) VALUES (
                'TEST-LEGACY-IMPORT', ?, 'fake import',
                '2026-07-26T22:00:00+08:00',
                '2026-07-26T22:00:00+08:00'
            )
            """,
            (FAKE_REPORT_ID,),
        )
        connection.execute(
            """
            INSERT INTO evidence (
                id, relationship_id, report_id, job_id, excerpt, created_at
            ) VALUES (
                'TEST-LEGACY-EVIDENCE', 'TEST-LEGACY-RELATIONSHIP', ?,
                'TEST-LEGACY-IMPORT', 'fake evidence',
                '2026-07-26T22:00:00+08:00'
            )
            """,
            (FAKE_REPORT_ID,),
        )

        connection.executescript(migration)

        assert connection.execute(
            "SELECT COUNT(*) FROM entities WHERE id LIKE 'TEST-LEGACY-%'"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM relationships WHERE id = 'TEST-LEGACY-RELATIONSHIP'"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM raw_reports WHERE id = ?", (FAKE_REPORT_ID,)
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM import_jobs WHERE id = 'TEST-LEGACY-IMPORT'"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM evidence WHERE id = 'TEST-LEGACY-EVIDENCE'"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM entities WHERE id = 'TEST-FUTURE-BLANK-ORIGIN'"
        ).fetchone()[0] == 1

        flow_ids = [
            row[0]
            for row in connection.execute(
                "SELECT id FROM activity_paths ORDER BY id"
            )
        ]
        assert flow_ids == baseline_flow_ids
        assert (
            connection.execute("PRAGMA foreign_key_check").fetchall()
            == baseline_foreign_key_violations
        )

        insert_entity(
            connection,
            "TEST-POST-MIGRATION-LEGACY-ORIGIN",
            seed_origin="legacy_full_graph_v2",
            created_at="2026-08-02T13:00:00+08:00",
        )
        connection.executescript(migration)
        assert connection.execute(
            """
            SELECT COUNT(*) FROM entities
            WHERE id = 'TEST-POST-MIGRATION-LEGACY-ORIGIN'
            """
        ).fetchone()[0] == 1
