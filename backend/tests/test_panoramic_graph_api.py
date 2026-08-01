from pathlib import Path
import shutil
import sqlite3

from fastapi.testclient import TestClient

from argus_backend.api import create_app


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def make_client(tmp_path: Path) -> TestClient:
    database_path = tmp_path / "argus_cti.db"
    shutil.copy2(REPOSITORY_ROOT / "data" / "argus_cti.db", database_path)
    return TestClient(create_app(database_path=database_path))


def test_five_entry_types_share_identity_and_expand_bidirectionally(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    index_response = client.get("/v1/graph/nodes")
    assert index_response.status_code == 200
    index = index_response.json()
    index_by_kind = {
        kind: next(node for node in index["nodes"] if node["kind"] == kind)
        for kind in ["entity", "actor", "attack-flow", "action", "source"]
    }

    for kind, root in index_by_kind.items():
        response = client.get(
            f"/v1/graph/neighborhoods/{root['id']}?depth=3&limit=128"
        )
        assert response.status_code == 200, kind
        neighborhood = response.json()
        assert neighborhood["root_id"] == root["id"]
        assert neighborhood["nodes"][0]["id"] == root["id"]
        assert neighborhood["available_expansions"][root["id"]] > 0

    flow_id = index_by_kind["attack-flow"]["id"]
    flow = client.get(f"/v1/attack-flows/{flow_id}").json()
    flow_graph = client.get(
        f"/v1/graph/neighborhoods/{flow_id}?depth=2&limit=128"
    ).json()
    graph_action_ids = {
        node["id"] for node in flow_graph["nodes"] if node["kind"] == "action"
    }
    assert {action["id"] for action in flow["actions"]} <= graph_action_ids
    graph_entity_ids = {
        node["id"] for node in flow_graph["nodes"] if node["kind"] == "entity"
    }
    assert {
        context["entity_id"]
        for action in flow["actions"]
        for context in action["contexts"]
    } <= graph_entity_ids

    action = next(action for action in flow["actions"] if action["contexts"])
    entity_id = action["contexts"][0]["entity_id"]
    action_graph = client.get(
        f"/v1/graph/neighborhoods/{action['id']}?depth=1&limit=64"
    ).json()
    entity_graph = client.get(
        f"/v1/graph/neighborhoods/{entity_id}?depth=1&limit=64"
    ).json()
    assert entity_id in {node["id"] for node in action_graph["nodes"]}
    assert action["id"] in {node["id"] for node in entity_graph["nodes"]}


def test_aggregate_edges_explain_atomic_paths_and_are_not_persisted(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    database_path = tmp_path / "argus_cti.db"
    with sqlite3.connect(database_path) as connection:
        relationship_count_before = connection.execute(
            "SELECT COUNT(*) FROM relationships"
        ).fetchone()[0]
        context_count_before = connection.execute(
            "SELECT COUNT(*) FROM action_context_links"
        ).fetchone()[0]

    index = client.get("/v1/graph/nodes").json()
    actor = next(
        node
        for node in index["nodes"]
        if node["kind"] == "actor" and node["label"] == "APT28"
    )
    graph = client.get(
        f"/v1/graph/neighborhoods/{actor['id']}?depth=3&limit=128"
    ).json()
    aggregate_edges = [edge for edge in graph["edges"] if edge["aggregate"]]
    assert aggregate_edges
    for edge in aggregate_edges:
        assert edge["id"].startswith("aggregate:")
        assert len(edge["explanation"]["node_ids"]) >= 3
        assert len(edge["explanation"]["edge_ids"]) >= 2
        returned_edge_ids = {item["id"] for item in graph["edges"]}
        returned_node_ids = {item["id"] for item in graph["nodes"]}
        assert set(edge["explanation"]["edge_ids"]) <= returned_edge_ids
        assert set(edge["explanation"]["node_ids"]) <= returned_node_ids
    assert any(node["kind"] == "evidence" for node in graph["nodes"])
    assert any(node["kind"] == "source" for node in graph["nodes"])

    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM relationships"
        ).fetchone()[0] == relationship_count_before
        assert connection.execute(
            "SELECT COUNT(*) FROM action_context_links"
        ).fetchone()[0] == context_count_before
        assert connection.execute(
            "SELECT COUNT(*) FROM relationships WHERE id LIKE 'aggregate:%'"
        ).fetchone()[0] == 0


def test_newly_published_flow_appears_without_a_second_graph_write(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    source_text = "\n\n".join(
        [
            "NightFox 被报告通过钓鱼邮件投递恶意文档。",
            "受害者打开文档后执行加载器，并连接到 198.51.100.77。",
            "加载器随后创建计划任务以保持驻留。",
        ]
    )
    source = client.post(
        "/v1/sources",
        json={
            "title": "NightFox reviewed incident",
            "publisher": "Example CERT",
            "canonical_url": "https://example.invalid/nightfox-reviewed",
            "published_at": "2026-08-01",
            "mime_type": "text/plain",
            "content": source_text,
        },
    ).json()["source_document"]
    candidate = {
        "title": "NightFox 文档投递至计划任务驻留",
        "description": "经人工复核的三步历史攻击过程。",
        "actions": [
            {
                "id": "A1",
                "name": "投递恶意文档",
                "description": "通过钓鱼邮件投递文档。",
                "phase": "初始访问",
                "confidence": "high",
                "technique_ids": [],
                "contexts": [],
                "evidence": [{"quote": "NightFox 被报告通过钓鱼邮件投递恶意文档。"}],
            },
            {
                "id": "A2",
                "name": "执行加载器",
                "description": "打开文档后执行加载器。",
                "phase": "执行",
                "confidence": "high",
                "technique_ids": [],
                "contexts": [
                    {
                        "id": "C1",
                        "type": "ip",
                        "name": "198.51.100.77",
                        "role": "communicates-with",
                        "confidence": "high",
                        "evidence": [{"quote": "受害者打开文档后执行加载器，并连接到 198.51.100.77。"}],
                    }
                ],
                "evidence": [{"quote": "受害者打开文档后执行加载器，并连接到 198.51.100.77。"}],
            },
            {
                "id": "A3",
                "name": "创建计划任务",
                "description": "加载器创建计划任务以驻留。",
                "phase": "持久化",
                "confidence": "high",
                "technique_ids": [],
                "contexts": [],
                "evidence": [{"quote": "加载器随后创建计划任务以保持驻留。"}],
            },
        ],
        "relations": [
            {
                "id": "R1",
                "source_action_id": "A1",
                "target_action_id": "A2",
                "type": "causes",
                "confidence": "high",
                "evidence": [{"quote": "受害者打开文档后执行加载器，并连接到 198.51.100.77。"}],
            },
            {
                "id": "R2",
                "source_action_id": "A2",
                "target_action_id": "A3",
                "type": "enables",
                "confidence": "high",
                "evidence": [{"quote": "加载器随后创建计划任务以保持驻留。"}],
            },
        ],
        "mainline": ["A1", "A2", "A3"],
        "reported_actors": [
            {
                "id": "ACTOR-1",
                "reported_name": "NightFox",
                "confidence": "medium",
                "evidence": [{"quote": "NightFox 被报告通过钓鱼邮件投递恶意文档。"}],
            }
        ],
    }
    staged = client.post(
        "/v1/knowledge-ingestions",
        json={
            "source_document_id": source["id"],
            "attack_flow_candidate": candidate,
        },
    ).json()
    assert staged["publishable"] is True
    published = client.post(
        f"/v1/knowledge-ingestions/{staged['id']}/publish"
    ).json()
    flow_id = published["attack_flow_preview"]["flow_id"]

    index = client.get("/v1/graph/nodes").json()
    assert flow_id in {node["id"] for node in index["nodes"]}
    graph = client.get(
        f"/v1/graph/neighborhoods/{flow_id}?depth=2&limit=128"
    ).json()
    assert source["id"] in {node["id"] for node in graph["nodes"]}
    assert {node["kind"] for node in graph["nodes"]} >= {
        "attack-flow",
        "action",
        "entity",
        "actor",
        "source",
        "evidence",
    }
