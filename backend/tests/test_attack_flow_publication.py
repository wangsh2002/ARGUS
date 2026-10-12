from copy import deepcopy
from pathlib import Path
import shutil
import sqlite3

from fastapi.testclient import TestClient
import pytest

from argus_backend.api import create_app


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SOURCE_CONTENT = "\n\n".join(
    [
        "NightFox 被报告通过钓鱼邮件投递恶意文档。",
        "受害者打开文档后执行加载器，并连接到 198.51.100.77。",
        "加载器随后创建计划任务以保持驻留。",
        "加载器运行 Cobalt Strike，并写入 sample.dll。",
    ]
)


def make_client(tmp_path: Path) -> TestClient:
    return make_empty_client(tmp_path)


def make_empty_client(tmp_path: Path) -> TestClient:
    database_path = tmp_path / "argus_cti.db"
    shutil.copy2(REPOSITORY_ROOT / "data" / "argus_cti.db", database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        tables = connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table'
              AND name NOT IN ('schema_migrations', 'sqlite_sequence')
            """
        ).fetchall()
        for (table,) in tables:
            connection.execute(f'DELETE FROM "{table}"')
        connection.commit()
    return TestClient(create_app(database_path=database_path))


def archive_source(client: TestClient) -> str:
    response = client.post(
        "/v1/sources",
        json={
            "title": "NightFox reviewed incident",
            "publisher": "Example CERT",
            "canonical_url": "https://example.invalid/nightfox-reviewed",
            "published_at": "2026-08-01",
            "mime_type": "text/plain",
            "content": SOURCE_CONTENT,
        },
    )
    assert response.status_code == 200
    return response.json()["source_document"]["id"]


def candidate() -> dict:
    return {
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
                "evidence": [
                    {"quote": "NightFox 被报告通过钓鱼邮件投递恶意文档。"}
                ],
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
                        "evidence": [
                            {
                                "quote": (
                                    "受害者打开文档后执行加载器，并连接到 "
                                    "198.51.100.77。"
                                )
                            }
                        ],
                    }
                ],
                "evidence": [
                    {
                        "quote": (
                            "受害者打开文档后执行加载器，并连接到 "
                            "198.51.100.77。"
                        )
                    }
                ],
            },
            {
                "id": "A3",
                "name": "创建计划任务",
                "description": "加载器创建计划任务以驻留。",
                "phase": "持久化",
                "confidence": "high",
                "technique_ids": ["T1053.005"],
                "contexts": [],
                "evidence": [
                    {"quote": "加载器随后创建计划任务以保持驻留。"}
                ],
            },
        ],
        "relations": [
            {
                "id": "R1",
                "source_action_id": "A1",
                "target_action_id": "A2",
                "type": "causes",
                "condition": None,
                "confidence": "high",
                "evidence": [
                    {
                        "quote": (
                            "受害者打开文档后执行加载器，并连接到 "
                            "198.51.100.77。"
                        )
                    }
                ],
            },
            {
                "id": "R2",
                "source_action_id": "A2",
                "target_action_id": "A3",
                "type": "enables",
                "condition": None,
                "confidence": "high",
                "evidence": [
                    {"quote": "加载器随后创建计划任务以保持驻留。"}
                ],
            },
        ],
        "mainline": ["A1", "A2", "A3"],
        "reported_actors": [
            {
                "id": "ACTOR-1",
                "reported_name": "NightFox",
                "confidence": "medium",
                "evidence": [
                    {"quote": "NightFox 被报告通过钓鱼邮件投递恶意文档。"}
                ],
            }
        ],
    }


def stage(client: TestClient, source_document_id: str, flow_candidate: dict):
    return client.post(
        "/v1/knowledge-ingestions",
        json={
            "source_document_id": source_document_id,
            "attack_flow_candidate": flow_candidate,
        },
    )


@pytest.mark.parametrize(
    ("mutation", "gate_id"),
    [
        (lambda item: item["actions"][0].update(evidence=[]), "flow-evidence"),
        (lambda item: item["relations"][0].update(evidence=[]), "flow-evidence"),
        (
            lambda item: item["actions"][1]["contexts"][0].update(evidence=[]),
            "flow-evidence",
        ),
        (lambda item: item["relations"][0].update(type="branch"), "flow-relations"),
        (
            lambda item: item["relations"][0].update(source_action_id="OUTSIDE"),
            "flow-relations",
        ),
        (lambda item: item.update(mainline=["A1", "A1"]), "flow-mainline"),
        (lambda item: item.update(mainline=["A1", "A3"]), "flow-mainline"),
        (
            lambda item: item["actions"][0]["evidence"][0].update(
                quote="候选伪造且原文不存在的证据"
            ),
            "flow-evidence",
        ),
    ],
)
def test_invalid_flow_candidates_remain_isolated_and_blocked(
    tmp_path: Path,
    mutation,
    gate_id: str,
) -> None:
    client = make_client(tmp_path)
    initial_flow_count = len(client.get("/v1/attack-flows").json())
    source_document_id = archive_source(client)
    draft = candidate()
    mutation(draft)

    response = stage(client, source_document_id, draft)

    assert response.status_code == 200
    staged = response.json()
    assert staged["status"] == "staged"
    assert staged["publishable"] is False
    assert staged["graph_write_performed"] is False
    assert next(
        gate for gate in staged["quality_gates"] if gate["id"] == gate_id
    )["status"] == "block"
    assert len(client.get("/v1/attack-flows").json()) == initial_flow_count
    publish = client.post(f"/v1/knowledge-ingestions/{staged['id']}/publish")
    assert publish.status_code == 409
    assert len(client.get("/v1/attack-flows").json()) == initial_flow_count


def test_reviewed_attack_flow_updates_runtime_reads_and_rolls_back(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    initial_catalog = client.get("/v1/runtime/catalog")
    assert initial_catalog.status_code == 200
    assert initial_catalog.json()["stats"]["entities"] == len(
        initial_catalog.json()["entities"]
    )
    assert initial_catalog.json()["meta"]["version"]
    initial_flow_count = len(client.get("/v1/attack-flows").json())
    source_document_id = archive_source(client)
    blocked_candidate = candidate()
    blocked_candidate["relations"][0]["type"] = "branch"

    staged_response = stage(client, source_document_id, blocked_candidate)
    assert staged_response.status_code == 200
    staged = staged_response.json()
    assert staged["ingestion_kind"] == "attack-flow"
    assert staged["publishable"] is False
    assert staged["attack_flow_preview"]["flow_id"].startswith("PATH-PUB-")
    assert staged["attack_flow_preview"]["actions"][1]["contexts"][0][
        "resolution"
    ]["status"] == "create"
    assert staged["attack_flow_preview"]["actions"][1]["contexts"][0][
        "resolution"
    ]["canonical_key"] == "ipv4:198.51.100.77"
    assert staged["attack_flow_preview"]["reported_actors"][0]["actor_id"] is None
    assert len(client.get("/v1/attack-flows").json()) == initial_flow_count

    revised_response = client.put(
        f"/v1/knowledge-ingestions/{staged['id']}",
        json={"attack_flow_candidate": candidate()},
    )
    assert revised_response.status_code == 200
    revised = revised_response.json()
    assert revised["id"] == staged["id"]
    assert revised["attack_flow_preview"]["flow_id"] == staged[
        "attack_flow_preview"
    ]["flow_id"]
    assert revised["publishable"] is True
    assert all(gate["status"] != "block" for gate in revised["quality_gates"])

    published_response = client.post(
        f"/v1/knowledge-ingestions/{staged['id']}/publish"
    )
    assert published_response.status_code == 200
    published = published_response.json()
    assert published["status"] == "published"
    assert published["graph_write_performed"] is True
    flow_id = published["attack_flow_preview"]["flow_id"]
    assert published["version"]["changes"]["created_attack_flow_id"] == flow_id

    flow_response = client.get(f"/v1/attack-flows/{flow_id}")
    assert flow_response.status_code == 200
    flow = flow_response.json()
    assert flow["title"] == candidate()["title"]
    assert [action["name"] for action in flow["actions"]] == [
        "投递恶意文档",
        "执行加载器",
        "创建计划任务",
    ]
    assert flow["mainline"] == [action["id"] for action in flow["actions"]]
    assert [relation["type"] for relation in flow["relations"]] == [
        "causes",
        "enables",
    ]
    context = flow["actions"][1]["contexts"][0]
    assert context["name"] == "198.51.100.77"
    assert context["type"] == "ip"
    assert context["entity_id"].startswith("ENT-CANON-")
    assert context["evidence"][0]["quote"] in SOURCE_CONTENT
    runtime_catalog = client.get("/v1/runtime/catalog").json()
    assert context["entity_id"] in {
        entity["id"] for entity in runtime_catalog["entities"]
    }
    runtime_detail_response = client.get(
        f"/v1/runtime/entities/{context['entity_id']}"
    )
    assert runtime_detail_response.status_code == 200
    runtime_detail = runtime_detail_response.json()
    assert runtime_detail["entity"]["id"] == context["entity_id"]
    assert flow_id in {
        item["id"] for item in runtime_detail["attack_flows"]
    }
    assert flow["reported_actors"] == [
        {
            "id": published["attack_flow_preview"]["reported_actors"][0]["id"],
            "reported_name": "NightFox",
            "actor_id": None,
            "confidence": "medium",
            "evidence": [
                {
                    **flow["reported_actors"][0]["evidence"][0],
                    "quote": "NightFox 被报告通过钓鱼邮件投递恶意文档。",
                }
            ],
        }
    ]
    assert len(client.get("/v1/attack-flows").json()) == initial_flow_count + 1

    duplicate = client.post(f"/v1/knowledge-ingestions/{staged['id']}/publish")
    assert duplicate.status_code == 200
    assert duplicate.json()["version"]["id"] == published["version"]["id"]

    rollback = client.post(
        f"/v1/knowledge-versions/{published['version']['id']}/rollback"
    )
    assert rollback.status_code == 200
    assert rollback.json()["status"] == "rolled_back"
    assert rollback.json()["changes"]["removed_attack_flow_id"] == flow_id
    assert client.get(f"/v1/attack-flows/{flow_id}").status_code == 404
    rolled_back_catalog = client.get("/v1/runtime/catalog").json()
    assert context["entity_id"] not in {
        entity["id"] for entity in rolled_back_catalog["entities"]
    }
    assert (
        client.get(f"/v1/runtime/entities/{context['entity_id']}").status_code
        == 404
    )
    assert len(client.get("/v1/attack-flows").json()) == initial_flow_count
    replay = client.get(f"/v1/knowledge-ingestions/{staged['id']}")
    assert replay.json()["status"] == "rolled_back"
    with sqlite3.connect(tmp_path / "argus_cti.db") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM entities WHERE canonical_key = ?",
            ("ipv4:198.51.100.77",),
        ).fetchone()[0] == 0


def test_unresolved_context_does_not_block_empty_graph_publication(
    tmp_path: Path,
) -> None:
    client = make_empty_client(tmp_path)
    source_document_id = archive_source(client)
    draft = candidate()
    context_quote = "加载器运行 Cobalt Strike，并写入 sample.dll。"
    draft["actions"][1]["contexts"] = [
        {
            "id": "C1",
            "type": "malware",
            "name": "Cobalt Strike",
            "role": "uses",
            "confidence": "high",
            "evidence": [{"quote": context_quote}],
        },
        {
            "id": "C2",
            "type": "file",
            "name": "sample.dll",
            "role": "creates",
            "confidence": "high",
            "evidence": [{"quote": context_quote}],
        },
    ]

    staged = stage(client, source_document_id, draft).json()

    assert staged["publishable"] is True
    context_gate = next(
        gate for gate in staged["quality_gates"] if gate["id"] == "flow-context"
    )
    assert context_gate["status"] == "warn"

    published = client.post(
        f"/v1/knowledge-ingestions/{staged['id']}/publish"
    )
    assert published.status_code == 200
    flow_id = published.json()["attack_flow_preview"]["flow_id"]
    flow = client.get(f"/v1/attack-flows/{flow_id}").json()
    contexts = flow["actions"][1]["contexts"]
    assert [item["name"] for item in contexts] == [
        "Cobalt Strike",
        "sample.dll",
    ]
    assert contexts[0]["entity_id"] is not None
    assert contexts[1]["entity_id"] is None


def test_contiguous_cross_paragraph_quote_gets_a_precise_source_span(
    tmp_path: Path,
) -> None:
    client = make_empty_client(tmp_path)
    source_document_id = archive_source(client)
    draft = candidate()
    quote = (
        "NightFox 被报告通过钓鱼邮件投递恶意文档。\n\n"
        "受害者打开文档后执行加载器，并连接到 198.51.100.77。"
    )
    draft["actions"][0]["evidence"] = [{"quote": quote}]

    staged = stage(client, source_document_id, draft).json()

    assert staged["publishable"] is True
    evidence = staged["attack_flow_preview"]["actions"][0]["evidence"][0]
    assert evidence["quote"] == quote
    assert evidence["locator"].startswith("offset:")
