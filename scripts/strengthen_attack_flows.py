#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from argus_backend.attack_flow_publication import (  # noqa: E402
    AttackFlowPublicationService,
)
from argus_backend.models import AttackFlowDraft  # noqa: E402
from argus_backend.repository import SqliteRepository  # noqa: E402


def _published_flow(
    connection: sqlite3.Connection,
    title: str,
) -> tuple[str, str] | None:
    row = connection.execute(
        """
        SELECT p.id, kv.id
        FROM activity_paths p
        JOIN knowledge_versions kv
          ON json_extract(kv.changes_json, '$.created_attack_flow_id') = p.id
        WHERE p.name = ? AND kv.status = 'published'
        ORDER BY kv.published_at DESC
        LIMIT 1
        """,
        (title,),
    ).fetchone()
    return (str(row[0]), str(row[1])) if row else None


def _flow_exists(connection: sqlite3.Connection, title: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM activity_paths WHERE name = ?",
            (title,),
        ).fetchone()
        is not None
    )


def _evidence_quotes(candidate: dict) -> list[str]:
    quotes: list[str] = []
    for action in candidate.get("actions", []):
        quotes.extend(item["quote"] for item in action.get("evidence", []))
        for context in action.get("contexts", []):
            quotes.extend(
                item["quote"] for item in context.get("evidence", [])
            )
    for relation in candidate.get("relations", []):
        quotes.extend(item["quote"] for item in relation.get("evidence", []))
    for actor in candidate.get("reported_actors", []):
        quotes.extend(item["quote"] for item in actor.get("evidence", []))
    return list(dict.fromkeys(quotes))


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
        default=ROOT / "data/attack_flow_strengthening.json",
    )
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    spec = json.loads(args.spec.read_text(encoding="utf-8"))
    temporary_database: Path | None = None
    database_path = args.database
    if not args.apply:
        handle = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        handle.close()
        temporary_database = Path(handle.name)
        shutil.copy2(args.database, temporary_database)
        database_path = temporary_database

    repository = SqliteRepository(database_path)
    repository.ensure_schema()
    publisher = AttackFlowPublicationService(repository)
    staged: list[tuple[dict, dict]] = []
    removals: list[tuple[str, str, str]] = []

    with sqlite3.connect(database_path) as connection:
        for group in spec["groups"]:
            source_id = group["source_document_id"]
            source = repository.load_source(source_id)
            if source is None:
                raise SystemExit(f"missing source document: {source_id}")
            content = source[1]
            for title in group["remove_titles"]:
                current = _published_flow(connection, title)
                if current:
                    removals.append((title, current[0], current[1]))
            for raw_candidate in group["candidates"]:
                candidate = AttackFlowDraft.model_validate(raw_candidate)
                if _flow_exists(connection, candidate.title):
                    continue
                missing_quotes = [
                    quote
                    for quote in _evidence_quotes(raw_candidate)
                    if quote not in content
                ]
                if missing_quotes:
                    raise SystemExit(
                        f"{candidate.title}: {len(missing_quotes)} quotes not in source:\n"
                        + "\n".join(f"- {quote}" for quote in missing_quotes)
                    )
                result = publisher.stage(source_id, candidate)
                staged.append((raw_candidate, result))

    blocked = [
        result
        for _, result in staged
        if result.get("publishable") is not True
    ]
    if blocked:
        for result in blocked:
            gates = [
                gate
                for gate in result.get("quality_gates", [])
                if gate.get("status") == "block"
            ]
            print(json.dumps({"id": result["id"], "gates": gates}, ensure_ascii=False))
        raise SystemExit(f"{len(blocked)} curated flows failed publication gates")

    summary = {
        "staged": [
            {
                "title": raw_candidate["title"],
                "ingestion_id": result["id"],
                "actions": len(raw_candidate["actions"]),
                "relations": len(raw_candidate["relations"]),
            }
            for raw_candidate, result in staged
        ],
        "remove": [
            {"title": title, "flow_id": flow_id, "version_id": version_id}
            for title, flow_id, version_id in removals
        ],
    }
    if not args.apply:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        print("validation passed; rerun with --apply")
        temporary_database.unlink(missing_ok=True)
        return 0

    published = []
    for raw_candidate, result in staged:
        publication = publisher.publish(result["id"])
        published.append(
            {
                "title": raw_candidate["title"],
                "flow_id": publication["attack_flow_preview"]["flow_id"],
                "version_id": publication["version"]["id"],
            }
        )
    rolled_back = []
    for title, flow_id, version_id in removals:
        result = repository.rollback_knowledge_version(version_id)
        if result is None:
            raise RuntimeError(f"missing knowledge version: {version_id}")
        rolled_back.append({"title": title, "flow_id": flow_id})

    print(
        json.dumps(
            {"published": published, "removed": rolled_back},
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
