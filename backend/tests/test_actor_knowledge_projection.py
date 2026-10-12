from pathlib import Path
import shutil

from fastapi.testclient import TestClient

from argus_backend.api import create_app


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def make_client(tmp_path: Path) -> TestClient:
    database_path = tmp_path / "argus_cti.db"
    shutil.copy2(REPOSITORY_ROOT / "data" / "argus_cti.db", database_path)
    return TestClient(create_app(database_path=database_path))


def test_actor_knowledge_is_projected_from_current_attack_flows(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)

    response = client.get("/v1/actor-knowledge")

    assert response.status_code == 200
    knowledge = response.json()
    assert knowledge["actors"]
    assert knowledge["reports"]
    assert knowledge["evidence"]
    assert all(actor["source_count"] > 0 for actor in knowledge["actors"])
    assert all(
        actor["profile_status"]
        in {"verified", "agent-assisted-reviewed", "partial", "internal_cluster"}
        for actor in knowledge["actors"]
    )
    activity_ids = {
        entity["id"]
        for entity in knowledge["entities"]
        if entity["entity_type"] == "历史事件"
    }
    action_ids = {
        entity["id"]
        for entity in knowledge["entities"]
        if entity["entity_type"] == "攻击步骤"
    }
    assert activity_ids
    assert action_ids
    assert any(
        relationship["source_entity_id"] in activity_ids
        and relationship["target_entity_id"] in action_ids
        for relationship in knowledge["relationships"]
    )
    evidence_relationship_ids = {
        evidence["relationship_id"] for evidence in knowledge["evidence"]
    }
    assert evidence_relationship_ids.issubset(
        {relationship["id"] for relationship in knowledge["relationships"]}
    )
    assert all(
        " and " not in alias["alias"].casefold()
        for alias in knowledge["aliases"]
        if alias["source"] == "attack-flow-claim"
    )

    catalog = client.get("/v1/runtime/catalog").json()
    assert catalog["stats"]["actors"] == len(knowledge["actors"])
    assert catalog["stats"]["evidence"] > 0
    flows = client.get("/v1/attack-flows").json()
    action_ids = {action["id"] for flow in flows for action in flow["actions"]}
    assert catalog["stats"]["attack_steps"] == len(action_ids)
