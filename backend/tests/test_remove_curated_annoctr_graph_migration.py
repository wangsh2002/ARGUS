from __future__ import annotations

from pathlib import Path
import sqlite3


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = (
    REPOSITORY_ROOT
    / "data"
    / "migrations"
    / "020_remove_curated_annoctr_reference_graph.sql"
)


def insert_entity(
    connection: sqlite3.Connection,
    entity_id: str,
    *,
    seed_origin: str,
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
            "2026-08-02T14:00:00+08:00",
            "2026-08-02T14:00:00+08:00",
            seed_origin,
        ),
    )


def test_migration_removes_curated_graph_but_keeps_corpus_and_model_runs(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "argus_cti.db"
    with sqlite3.connect(
        REPOSITORY_ROOT / "data" / "argus_cti.db"
    ) as source_connection, sqlite3.connect(database_path) as target_connection:
        source_connection.backup(target_connection)

    migration = MIGRATION_PATH.read_text(encoding="utf-8")
    with sqlite3.connect(database_path) as connection:
        connection.executescript(migration)
        connection.execute("DELETE FROM schema_migrations WHERE version = 20")
        preserved_counts = connection.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM raw_reports),
              (SELECT COUNT(*) FROM source_documents),
              (SELECT COUNT(*) FROM source_artifacts),
              (SELECT COUNT(*) FROM knowledge_ingestion_runs)
            """
        ).fetchone()

        insert_entity(
            connection,
            "TEST-CURATED-ENTITY-A",
            seed_origin="annoctr-curated-v1",
        )
        insert_entity(
            connection,
            "TEST-CURATED-ENTITY-B",
            seed_origin="annoctr-curated-v1",
        )
        insert_entity(
            connection,
            "TEST-MODEL-ENTITY",
            seed_origin="model-extraction-v1",
        )
        connection.execute(
            """
            INSERT INTO relationships (
                id, source_entity_id, target_entity_id, relation_type,
                canonical_key, created_at, updated_at, seed_origin
            ) VALUES (
                'TEST-CURATED-RELATIONSHIP',
                'TEST-CURATED-ENTITY-A',
                'TEST-CURATED-ENTITY-B',
                'uses',
                'test:curated:relationship',
                '2026-08-02T14:00:00+08:00',
                '2026-08-02T14:00:00+08:00',
                'annoctr-curated-v1'
            )
            """
        )
        connection.execute(
            """
            INSERT INTO activity_paths (
                id, name, description, activity_key, path_kind,
                review_state, reviewer_type, metadata_json
            ) VALUES (
                'PATH-ANNOCTR-APT28-ZEBROCY-2020',
                'curated test flow',
                'curated test flow',
                'test:curated:flow',
                'historical',
                'agent-assisted-reviewed',
                'agent-assisted',
                '{"curation_version":"annoctr-curated-v1"}'
            )
            """
        )
        connection.execute(
            """
            INSERT INTO activity_path_nodes (
                id, path_id, occurrence_key, label, node_type,
                assertion_origin, review_state, confidence
            ) VALUES (
                'TEST-CURATED-NODE',
                'PATH-ANNOCTR-APT28-ZEBROCY-2020',
                '01',
                'curated action',
                'behavior-action',
                'source-observed',
                'agent-assisted-reviewed',
                0.9
            )
            """
        )
        connection.execute(
            """
            INSERT INTO action_context_links (
                id, path_id, action_node_id, entity_id, role, direction,
                assertion_origin, review_state, confidence
            ) VALUES (
                'TEST-CURATED-CONTEXT',
                'PATH-ANNOCTR-APT28-ZEBROCY-2020',
                'TEST-CURATED-NODE',
                'TEST-CURATED-ENTITY-A',
                'uses',
                'action-to-entity',
                'source-observed',
                'agent-assisted-reviewed',
                0.9
            )
            """
        )

        connection.executescript(migration)

        assert connection.execute(
            "SELECT COUNT(*) FROM activity_paths"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM entities WHERE seed_origin = 'annoctr-curated-v1'"
        ).fetchone()[0] == 0
        assert connection.execute(
            """
            SELECT COUNT(*) FROM relationships
            WHERE seed_origin = 'annoctr-curated-v1'
            """
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM entities WHERE id = 'TEST-MODEL-ENTITY'"
        ).fetchone()[0] == 1
        assert connection.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM raw_reports),
              (SELECT COUNT(*) FROM source_documents),
              (SELECT COUNT(*) FROM source_artifacts),
              (SELECT COUNT(*) FROM knowledge_ingestion_runs)
            """
        ).fetchone() == preserved_counts

        insert_entity(
            connection,
            "TEST-POST-MIGRATION-CURATED",
            seed_origin="annoctr-curated-v1",
        )
        connection.executescript(migration)
        assert connection.execute(
            """
            SELECT COUNT(*) FROM entities
            WHERE id = 'TEST-POST-MIGRATION-CURATED'
            """
        ).fetchone()[0] == 1
