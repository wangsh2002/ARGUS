#!/usr/bin/env python3
"""Verify source artifacts, evidence anchors and reviewed path provenance."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sqlite3


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database",
        type=Path,
        default=root / "data" / "argus_cti.db",
    )
    parser.add_argument("--repository-root", type=Path, default=root)
    return parser.parse_args()


def scalar(connection: sqlite3.Connection, sql: str) -> int:
    return int(connection.execute(sql).fetchone()[0])


def main() -> int:
    args = parse_args()
    errors: list[str] = []
    with sqlite3.connect(args.database.resolve()) as connection:
        connection.row_factory = sqlite3.Row
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            errors.append(f"SQLite integrity check: {integrity}")

        artifacts = connection.execute(
            """
            SELECT id, sha256, size_bytes, storage_path
            FROM source_artifacts
            ORDER BY id
            """
        ).fetchall()
        for artifact in artifacts:
            artifact_path = args.repository_root.resolve() / artifact["storage_path"]
            if not artifact_path.is_file():
                errors.append(f"{artifact['id']}: artifact file missing")
                continue
            content = artifact_path.read_bytes()
            if len(content) != artifact["size_bytes"]:
                errors.append(f"{artifact['id']}: size mismatch")
            if sha256(content).hexdigest() != artifact["sha256"]:
                errors.append(f"{artifact['id']}: SHA-256 mismatch")

        checks = {
            "documents_without_artifact": """
                SELECT COUNT(*) FROM source_documents
                WHERE id LIKE 'SRC-DOC-%'
                  AND canonical_verification_state = 'verified'
                  AND artifact_id IS NULL
            """,
            "artifact_spans_without_hash": """
                SELECT COUNT(*) FROM source_spans
                WHERE artifact_id IS NOT NULL AND quote_sha256 = ''
            """,
            "path_nodes_without_evidence": """
                SELECT COUNT(*)
                FROM activity_path_nodes n
                LEFT JOIN path_evidence_links l ON l.node_id = n.id
                WHERE l.id IS NULL
            """,
            "path_edges_without_evidence": """
                SELECT COUNT(*)
                FROM activity_path_edges e
                LEFT JOIN path_evidence_links l ON l.edge_id = e.id
                WHERE l.id IS NULL
            """,
            "evidence_quote_mismatch": """
                SELECT COUNT(*)
                FROM path_evidence_links l
                JOIN source_spans s ON s.id = l.source_span_id
                WHERE l.quote <> s.text
            """,
            "generated_claims_inside_historical_paths": """
                SELECT COUNT(*)
                FROM (
                  SELECT n.assertion_origin
                  FROM activity_path_nodes n
                  JOIN activity_paths p ON p.id = n.path_id
                  WHERE p.path_kind = 'historical'
                  UNION ALL
                  SELECT e.assertion_origin
                  FROM activity_path_edges e
                  JOIN activity_paths p ON p.id = e.path_id
                  WHERE p.path_kind = 'historical'
                )
                WHERE assertion_origin LIKE 'algorithm-%'
            """,
        }
        violations = {}
        for label, sql in checks.items():
            value = scalar(connection, sql)
            violations[label] = value
            if value:
                errors.append(f"{label}: {value}")

        summary = {
            "integrity": integrity,
            "collections": scalar(
                connection, "SELECT COUNT(*) FROM corpus_collections"
            ),
            "artifacts": len(artifacts),
            "source_spans": scalar(
                connection,
                "SELECT COUNT(*) FROM source_spans WHERE artifact_id IS NOT NULL",
            ),
            "reviewed_paths": scalar(
                connection,
                """
                SELECT COUNT(*) FROM activity_paths
                WHERE review_state = 'agent-assisted-reviewed'
                """,
            ),
            "path_nodes": scalar(
                connection, "SELECT COUNT(*) FROM activity_path_nodes"
            ),
            "path_edges": scalar(
                connection, "SELECT COUNT(*) FROM activity_path_edges"
            ),
            "path_evidence_links": scalar(
                connection, "SELECT COUNT(*) FROM path_evidence_links"
            ),
            "violations": violations,
            "errors": errors,
        }

    print(json.dumps(summary, ensure_ascii=False))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
