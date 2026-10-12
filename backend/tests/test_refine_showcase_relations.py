from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from scripts.refine_showcase_relations import (
    apply_showcase_relation_refinements,
)


def test_refinement_requires_evidence_and_updates_canonical_relation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "argus.db"
    spec = tmp_path / "refinements.json"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE activity_paths (id TEXT PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE activity_path_nodes (
              id TEXT PRIMARY KEY,
              path_id TEXT NOT NULL,
              label TEXT NOT NULL
            );
            CREATE TABLE activity_path_edges (
              id TEXT PRIMARY KEY,
              path_id TEXT NOT NULL,
              source_node_id TEXT NOT NULL,
              target_node_id TEXT NOT NULL,
              edge_type TEXT NOT NULL,
              v1_relation_type TEXT,
              condition_label TEXT,
              properties_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE path_evidence_links (
              id TEXT PRIMARY KEY,
              edge_id TEXT
            );
            INSERT INTO activity_paths VALUES ('FLOW-1', 'Featured flow');
            INSERT INTO activity_path_nodes VALUES
              ('NODE-1', 'FLOW-1', 'Execute loader'),
              ('NODE-2', 'FLOW-1', 'Connect to C2');
            INSERT INTO activity_path_edges VALUES
              ('EDGE-1', 'FLOW-1', 'NODE-1', 'NODE-2', 'conditional',
               'leads_to', NULL, '{}');
            INSERT INTO path_evidence_links VALUES ('EVIDENCE-1', 'EDGE-1');
            """
        )
    spec.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "flows": [
                    {
                        "title": "Featured flow",
                        "relations": [
                            {
                                "source": "Execute loader",
                                "target": "Connect to C2",
                                "type": "causes",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = apply_showcase_relation_refinements(database, spec)

    assert result["changed"] == [
        {
            "flow": "Featured flow",
            "edge_id": "EDGE-1",
            "from": "leads_to",
            "to": "causes",
        }
    ]
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT edge_type, v1_relation_type, condition_label,
                   json_extract(properties_json, '$.attack_flow_relation_type')
            FROM activity_path_edges
            WHERE id = 'EDGE-1'
            """
        ).fetchone()
    assert row == ("causes", "causes", "直接触发", "causes")
