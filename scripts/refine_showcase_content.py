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
from argus_backend.models import AttackFlow, AttackFlowDraft  # noqa: E402
from argus_backend.repository import SqliteRepository  # noqa: E402


APT28_TITLE = (
    "APT28 Zebrocy NATO-themed campaign targeting Azerbaijan government body"
)
SCREENSHOT_ACTION = "Capture screenshots for collection"
SCREENSHOT_QUOTE = (
    "The task runs regularly and tries to POST stolen data (e.g. screenshots) "
    "to hxxp://194.32.78[.]245/protect/get-upd-id[.]php"
)


def _quotes(items: list) -> list[dict[str, str]]:
    return [
        {"quote": item.quote}
        for item in items
        if not item.id.startswith("ACE-BACKFILL-")
    ]


def _draft_from_flow(flow: AttackFlow) -> dict:
    local_id_by_action = {
        action.id: f"A{index}"
        for index, action in enumerate(flow.actions, start=1)
    }
    actions: list[dict] = []
    for action_index, action in enumerate(flow.actions, start=1):
        contexts = []
        for context_index, context in enumerate(action.contexts, start=1):
            evidence = _quotes(context.evidence)
            if not evidence:
                continue
            contexts.append(
                {
                    "id": f"C{action_index}-{context_index}",
                    "type": context.type,
                    "name": context.name,
                    "role": context.role,
                    "confidence": context.confidence,
                    "evidence": evidence,
                }
            )
        actions.append(
            {
                "id": local_id_by_action[action.id],
                "name": action.name,
                "description": action.description,
                "phase": action.phase,
                "confidence": action.confidence,
                "technique_ids": action.technique_ids,
                "contexts": contexts,
                "evidence": _quotes(action.evidence),
            }
        )
    relations = [
        {
            "id": f"R{index}",
            "source_action_id": local_id_by_action[relation.source_action_id],
            "target_action_id": local_id_by_action[relation.target_action_id],
            "type": relation.type,
            "condition": relation.condition,
            "confidence": relation.confidence,
            "evidence": _quotes(relation.evidence),
        }
        for index, relation in enumerate(flow.relations, start=1)
    ]
    return {
        "title": flow.title,
        "description": flow.description,
        "actions": actions,
        "relations": relations,
        "mainline": [local_id_by_action[action_id] for action_id in flow.mainline],
        "reported_actors": [
            {
                "id": f"ACTOR{index}",
                "reported_name": actor.reported_name,
                "confidence": actor.confidence,
                "evidence": _quotes(actor.evidence),
            }
            for index, actor in enumerate(flow.reported_actors, start=1)
        ],
    }


def _apt28_candidate(flow: AttackFlow) -> AttackFlowDraft:
    draft = _draft_from_flow(flow)
    if any(action["name"] == SCREENSHOT_ACTION for action in draft["actions"]):
        return AttackFlowDraft.model_validate(draft)

    scheduled_index = next(
        index
        for index, action in enumerate(draft["actions"])
        if action["name"] == "Create scheduled task for persistence"
    )
    exfiltration = next(
        action
        for action in draft["actions"]
        if action["name"] == "Exfiltrate data via HTTP POST"
    )
    screenshot_id = "A-SCREENSHOT"
    draft["actions"].insert(
        scheduled_index + 1,
        {
            "id": screenshot_id,
            "name": SCREENSHOT_ACTION,
            "description": (
                "Collect screenshots as an example of data prepared for "
                "exfiltration by the recurring Zebrocy task."
            ),
            "phase": "collection",
            "confidence": "medium",
            "technique_ids": ["T1113"],
            "contexts": [],
            "evidence": [{"quote": SCREENSHOT_QUOTE}],
        },
    )
    scheduled_id = draft["actions"][scheduled_index]["id"]
    exfiltration_id = exfiltration["id"]
    draft["relations"] = [
        relation
        for relation in draft["relations"]
        if not (
            relation["source_action_id"] == scheduled_id
            and relation["target_action_id"] == exfiltration_id
        )
    ]
    draft["relations"].extend(
        [
            {
                "id": "R-SCREENSHOT-1",
                "source_action_id": scheduled_id,
                "target_action_id": screenshot_id,
                "type": "leads_to",
                "condition": None,
                "confidence": "medium",
                "evidence": [{"quote": SCREENSHOT_QUOTE}],
            },
            {
                "id": "R-SCREENSHOT-2",
                "source_action_id": screenshot_id,
                "target_action_id": exfiltration_id,
                "type": "precedes",
                "condition": None,
                "confidence": "high",
                "evidence": [{"quote": SCREENSHOT_QUOTE}],
            },
        ]
    )
    mainline_index = draft["mainline"].index(scheduled_id)
    draft["mainline"].insert(mainline_index + 1, screenshot_id)
    return AttackFlowDraft.model_validate(draft)


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


def refine_showcase_content(database_path: Path) -> dict:
    repository = SqliteRepository(database_path)
    repository.ensure_schema()
    with sqlite3.connect(database_path) as connection:
        current = _published_flow(connection, APT28_TITLE)
    if current is None:
        raise ValueError(f"missing showcase flow: {APT28_TITLE}")
    current_flow = repository.find_attack_flow(current[0])
    if current_flow is None:
        raise ValueError(f"cannot project showcase flow: {current[0]}")
    if any(action.name == SCREENSHOT_ACTION for action in current_flow.actions):
        return {"status": "unchanged", "flow_id": current_flow.id}

    candidate = _apt28_candidate(current_flow)
    publication_service = AttackFlowPublicationService(repository)
    staged = publication_service.stage(
        current_flow.sources[0].id,
        candidate,
        extraction_audit={"method": "showcase-content-refinement/1.0"},
    )
    if staged.get("publishable") is not True:
        blocked = [
            gate
            for gate in staged.get("quality_gates", [])
            if gate.get("status") == "block"
        ]
        raise ValueError(json.dumps(blocked, ensure_ascii=False))
    published = publication_service.publish(staged["id"])
    repository.rollback_knowledge_version(current[1])
    return {
        "status": "replaced",
        "old_flow_id": current[0],
        "flow_id": published["attack_flow_preview"]["flow_id"],
        "actions": len(candidate.actions),
        "relations": len(candidate.relations),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database",
        type=Path,
        default=ROOT / "data/argus_cti.db",
    )
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    database_path = args.database
    temporary_database: Path | None = None
    if not args.apply:
        handle = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        handle.close()
        temporary_database = Path(handle.name)
        shutil.copy2(database_path, temporary_database)
        database_path = temporary_database
    try:
        result = refine_showcase_content(database_path)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if not args.apply:
            print("validation passed; rerun with --apply")
    finally:
        if temporary_database is not None:
            temporary_database.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
