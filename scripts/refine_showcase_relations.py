#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_RELATIONS = {
    "precedes",
    "leads_to",
    "enables",
    "causes",
    "on_success",
    "on_failure",
}
STORED_EDGE_TYPES = {
    "precedes": "sequence",
    "leads_to": "conditional",
    "enables": "enables",
    "causes": "causes",
    "on_success": "conditional",
    "on_failure": "conditional",
}
RELATION_LABELS = {
    "precedes": "明确先于",
    "leads_to": "推进至",
    "enables": "提供必要条件",
    "causes": "直接触发",
    "on_success": "成功后进入",
    "on_failure": "失败后进入",
}


def apply_showcase_relation_refinements(
    database_path: Path,
    spec_path: Path = ROOT / "data/showcase_relation_refinements.json",
    *,
    apply: bool = True,
) -> dict:
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    if spec.get("schema_version") != 1:
        raise ValueError("unsupported showcase relation refinement schema")

    changed: list[dict] = []
    skipped: list[dict] = []
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        for flow in spec["flows"]:
            path = connection.execute(
                "SELECT id FROM activity_paths WHERE name = ?",
                (flow["title"],),
            ).fetchone()
            if path is None:
                skipped.append({"flow": flow["title"], "reason": "missing-flow"})
                continue
            for relation in flow["relations"]:
                relation_type = relation["type"]
                if relation_type not in ALLOWED_RELATIONS:
                    raise ValueError(f"unsupported relation type: {relation_type}")
                rows = connection.execute(
                    """
                    SELECT edge.id,
                           COALESCE(edge.v1_relation_type, edge.edge_type) AS current_type,
                           COUNT(evidence.id) AS evidence_count
                    FROM activity_path_edges edge
                    JOIN activity_path_nodes source
                      ON source.id = edge.source_node_id
                    JOIN activity_path_nodes target
                      ON target.id = edge.target_node_id
                    LEFT JOIN path_evidence_links evidence
                      ON evidence.edge_id = edge.id
                    WHERE edge.path_id = ?
                      AND source.label = ?
                      AND target.label = ?
                    GROUP BY edge.id
                    """,
                    (path["id"], relation["source"], relation["target"]),
                ).fetchall()
                if len(rows) != 1:
                    raise ValueError(
                        f"{flow['title']}: expected one edge for "
                        f"{relation['source']} -> {relation['target']}, got {len(rows)}"
                    )
                edge = rows[0]
                if edge["evidence_count"] < 1:
                    raise ValueError(f"{edge['id']}: relation has no source evidence")
                changed.append(
                    {
                        "flow": flow["title"],
                        "edge_id": edge["id"],
                        "from": edge["current_type"],
                        "to": relation_type,
                    }
                )
                if apply:
                    connection.execute(
                        """
                        UPDATE activity_path_edges
                        SET edge_type = ?,
                            v1_relation_type = ?,
                            condition_label = ?,
                            properties_json = json_set(
                              properties_json,
                              '$.attack_flow_relation_type', ?
                            )
                        WHERE id = ?
                        """,
                        (
                            STORED_EDGE_TYPES[relation_type],
                            relation_type,
                            RELATION_LABELS[relation_type],
                            relation_type,
                            edge["id"],
                        ),
                    )
        if apply:
            connection.commit()
        else:
            connection.rollback()
    return {"changed": changed, "skipped": skipped}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database",
        type=Path,
        default=ROOT / "data/argus_cti.db",
    )
    parser.add_argument(
        "--spec",
        type=Path,
        default=ROOT / "data/showcase_relation_refinements.json",
    )
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    result = apply_showcase_relation_refinements(
        args.database,
        args.spec,
        apply=args.apply,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
