from __future__ import annotations

import json
from pathlib import Path
import shutil
import sqlite3
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.import_report_corpus import import_manifest  # noqa: E402


MANIFEST_PATH = (
    REPOSITORY_ROOT / "data" / "corpus" / "annoctr_initial_manifest.json"
)
def scalar(connection: sqlite3.Connection, sql: str) -> int:
    return int(connection.execute(sql).fetchone()[0])


def rebuild_source_root(tmp_path: Path) -> Path:
    source_root = tmp_path / "annoctr"
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    collection_id = manifest["collection"]["id"]
    for report in manifest["reports"]:
        source = (
            REPOSITORY_ROOT
            / "data"
            / "corpus"
            / "artifacts"
            / collection_id
            / f"{report['sha256'][:16]}.txt"
        )
        destination = source_root / report["source_path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    return source_root


def test_corpus_import_is_idempotent_and_does_not_mutate_graph(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "argus_cti.db"
    with sqlite3.connect(
        REPOSITORY_ROOT / "data" / "argus_cti.db"
    ) as source_connection, sqlite3.connect(database_path) as target_connection:
        source_connection.backup(target_connection)
    source_root = rebuild_source_root(tmp_path)

    with sqlite3.connect(database_path) as connection:
        relationship_count = scalar(connection, "SELECT COUNT(*) FROM relationships")
        legacy_evidence_count = scalar(connection, "SELECT COUNT(*) FROM evidence")
        provenance_counts = {
            "source_artifacts": scalar(
                connection, "SELECT COUNT(*) FROM source_artifacts"
            ),
            "source_spans": scalar(
                connection,
                "SELECT COUNT(*) FROM source_spans WHERE artifact_id IS NOT NULL",
            ),
            "activity_paths": scalar(connection, "SELECT COUNT(*) FROM activity_paths"),
            "activity_path_nodes": scalar(connection, "SELECT COUNT(*) FROM activity_path_nodes"),
            "activity_path_edges": scalar(connection, "SELECT COUNT(*) FROM activity_path_edges"),
            "path_evidence_links": scalar(connection, "SELECT COUNT(*) FROM path_evidence_links"),
        }

    first_corpus = import_manifest(
        MANIFEST_PATH,
        source_root,
        database_path,
        tmp_path / "stored",
        dry_run=False,
    )
    second_corpus = import_manifest(
        MANIFEST_PATH,
        source_root,
        database_path,
        tmp_path / "stored",
        dry_run=False,
    )
    assert first_corpus == second_corpus
    assert first_corpus["reports"] == 6
    assert first_corpus["graph_writes"] == 0

    with sqlite3.connect(database_path) as connection:
        assert scalar(
            connection, "SELECT COUNT(*) FROM source_artifacts"
        ) == provenance_counts["source_artifacts"]
        assert (
            scalar(
                connection,
                "SELECT COUNT(*) FROM source_spans WHERE artifact_id IS NOT NULL",
            )
            == provenance_counts["source_spans"]
        )
        assert scalar(
            connection, "SELECT COUNT(*) FROM activity_paths"
        ) == provenance_counts["activity_paths"]
        assert scalar(
            connection, "SELECT COUNT(*) FROM activity_path_nodes"
        ) == provenance_counts["activity_path_nodes"]
        assert scalar(
            connection, "SELECT COUNT(*) FROM activity_path_edges"
        ) == provenance_counts["activity_path_edges"]
        assert scalar(
            connection, "SELECT COUNT(*) FROM path_evidence_links"
        ) == provenance_counts["path_evidence_links"]
        assert (
            scalar(
                connection,
                """
                SELECT COUNT(*)
                FROM activity_path_nodes n
                LEFT JOIN path_evidence_links l ON l.node_id = n.id
                WHERE l.id IS NULL
                """,
            )
            == 0
        )
        assert (
            scalar(
                connection,
                """
                SELECT COUNT(*)
                FROM activity_path_edges e
                LEFT JOIN path_evidence_links l ON l.edge_id = e.id
                WHERE l.id IS NULL
                """,
            )
            == 0
        )
        assert scalar(connection, "SELECT COUNT(*) FROM relationships") == (
            relationship_count
        )
        assert scalar(connection, "SELECT COUNT(*) FROM evidence") == (
            legacy_evidence_count
        )
