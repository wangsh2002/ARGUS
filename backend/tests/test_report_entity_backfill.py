from scripts.backfill_report_entities import MAX_CONTEXT_DISTANCE, nearest_action


def action(action_id: str, start: int, end: int) -> dict:
    return {
        "source_document_id": "SRC-1",
        "path_id": "PATH-1",
        "action_node_id": action_id,
        "action_label": "Download payload from C2",
        "evidence_quote": "Download payload from nearby.example",
        "start_offset": start,
        "end_offset": end,
    }


def test_nearest_action_keeps_distant_report_entities_unlinked() -> None:
    candidate = {
        "source_document_id": "SRC-1",
        "start_offset": 2000,
        "end_offset": 2010,
        "value_type": "domain",
        "entity_type": "IOC/基础设施",
    }

    assert nearest_action(candidate, {"SRC-1": [action("A1", 0, 100)]}) is None


def test_nearest_action_links_nearby_entity_by_semantics() -> None:
    candidate = {
        "source_document_id": "SRC-1",
        "start_offset": MAX_CONTEXT_DISTANCE,
        "end_offset": MAX_CONTEXT_DISTANCE + 5,
        "value_type": "domain",
        "entity_type": "IOC/基础设施",
    }
    selected = nearest_action(
        candidate,
        {
            "SRC-1": [
                action("A1", 0, 5),
                {
                    **action("A2", 20, 25),
                    "action_label": "Create scheduled task",
                },
            ]
        },
    )

    assert selected is not None
    assert selected["action_node_id"] == "A1"


def test_nearest_action_does_not_attach_software_from_adjacent_section() -> None:
    candidate = {
        "source_document_id": "SRC-1",
        "start_offset": 101,
        "end_offset": 109,
        "value_type": "malware",
        "entity_type": "恶意软件/工具",
        "original_value": "OtherRAT",
    }

    assert nearest_action(candidate, {"SRC-1": [action("A1", 0, 100)]}) is None
