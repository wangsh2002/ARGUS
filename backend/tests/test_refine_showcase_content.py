from pathlib import Path
import shutil

from argus_backend.models import AttackFlow
from scripts.refine_showcase_content import (
    APT28_TITLE,
    SCREENSHOT_ACTION,
    _apt28_candidate,
    refine_showcase_content,
)


ROOT = Path(__file__).resolve().parents[2]


def evidence(quote: str) -> list[dict]:
    return [
        {
            "id": f"E-{len(quote)}",
            "source_span_id": "SPAN-1",
            "source_id": "SOURCE-1",
            "title": "APT28 report",
            "publisher": "Example",
            "canonical_url": "https://example.invalid/apt28",
            "locator": "line:1",
            "quote": quote,
            "confidence": 0.95,
        }
    ]


def flow_before_refinement() -> AttackFlow:
    action_names = [
        "Drop Zebrocy malware executable",
        "Copy malware to AppData with padding",
        "Create scheduled task for persistence",
        "Exfiltrate data via HTTP POST",
    ]
    actions = [
        {
            "id": f"A{index}",
            "name": name,
            "description": name,
            "phase": "execution",
            "confidence": "high",
            "technique_ids": [],
            "contexts": [],
            "evidence": evidence(
                "The task runs regularly and tries to POST stolen data "
                "(e.g. screenshots) to "
                "hxxp://194.32.78[.]245/protect/get-upd-id[.]php"
                if index == 4
                else name
            ),
        }
        for index, name in enumerate(action_names, start=1)
    ]
    return AttackFlow.model_validate(
        {
            "id": "FLOW-1",
            "title": APT28_TITLE,
            "description": "APT28 campaign",
            "sources": [
                {
                    "id": "SOURCE-1",
                    "title": "APT28 report",
                    "publisher": "Example",
                    "canonical_url": "https://example.invalid/apt28",
                    "published_at": "2020-09-22",
                }
            ],
            "actions": actions,
            "relations": [
                {
                    "id": "R1",
                    "source_action_id": "A3",
                    "target_action_id": "A4",
                    "type": "causes",
                    "condition": None,
                    "confidence": "high",
                    "evidence": evidence(
                        "The task runs regularly and tries to POST stolen data "
                        "(e.g. screenshots) to "
                        "hxxp://194.32.78[.]245/protect/get-upd-id[.]php"
                    ),
                }
            ],
            "mainline": ["A1", "A2", "A3", "A4"],
        }
    )


def test_candidate_adds_evidence_backed_screenshot_collection() -> None:
    candidate = _apt28_candidate(flow_before_refinement())

    screenshot = next(
        action for action in candidate.actions if action.name == SCREENSHOT_ACTION
    )
    assert screenshot.technique_ids == ["T1113"]
    assert screenshot.evidence
    assert len(candidate.mainline) == 5


def test_refinement_is_idempotent_for_current_database(tmp_path: Path) -> None:
    database = tmp_path / "argus.db"
    shutil.copy2(ROOT / "data" / "argus_cti.db", database)

    result = refine_showcase_content(database)

    assert result["status"] == "unchanged"
