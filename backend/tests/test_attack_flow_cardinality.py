from copy import deepcopy
from pathlib import Path
import shutil

from fastapi.testclient import TestClient

from argus_backend.api import create_app


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def make_client(tmp_path: Path) -> TestClient:
    database_path = tmp_path / "argus_cti.db"
    shutil.copy2(REPOSITORY_ROOT / "data" / "argus_cti.db", database_path)
    return TestClient(create_app(database_path=database_path))


def archive(client: TestClient, title: str, content: str) -> str:
    response = client.post(
        "/v1/sources",
        json={
            "title": title,
            "publisher": "Example CERT",
            "canonical_url": f"https://example.invalid/{title.lower().replace(' ', '-')}",
            "published_at": "2026-08-01",
            "mime_type": "text/plain",
            "content": content,
        },
    )
    assert response.status_code == 200
    return response.json()["source_document"]["id"]


def two_step_candidate(
    *,
    prefix: str,
    first_quote: str,
    second_quote: str,
    first_name: str,
    second_name: str,
    ip: str | None = None,
    actor: str | None = None,
    technique_id: str | None = None,
) -> dict:
    contexts = []
    if ip:
        contexts = [
            {
                "id": f"{prefix}-C1",
                "type": "ip",
                "name": ip,
                "role": "communicates-with",
                "confidence": "high",
                "evidence": [{"quote": first_quote}],
            }
        ]
    reported_actors = []
    if actor:
        reported_actors = [
            {
                "id": f"{prefix}-ACTOR",
                "reported_name": actor,
                "confidence": "medium",
                "evidence": [{"quote": first_quote}],
            }
        ]
    return {
        "title": f"{first_name}至{second_name}",
        "description": "两步人工复核攻击活动。",
        "actions": [
            {
                "id": f"{prefix}-A1",
                "name": first_name,
                "description": first_name,
                "phase": "初始访问",
                "confidence": "high",
                "technique_ids": [technique_id] if technique_id else [],
                "contexts": contexts,
                "evidence": [{"quote": first_quote}],
            },
            {
                "id": f"{prefix}-A2",
                "name": second_name,
                "description": second_name,
                "phase": "执行",
                "confidence": "high",
                "technique_ids": [],
                "contexts": [],
                "evidence": [{"quote": second_quote}],
            },
        ],
        "relations": [
            {
                "id": f"{prefix}-R1",
                "source_action_id": f"{prefix}-A1",
                "target_action_id": f"{prefix}-A2",
                "type": "enables",
                "condition": None,
                "confidence": "high",
                "evidence": [{"quote": second_quote}],
            }
        ],
        "mainline": [f"{prefix}-A1", f"{prefix}-A2"],
        "reported_actors": reported_actors,
    }


def test_empty_candidate_list_produces_no_flow_and_keeps_entity_ingestion(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    baseline_flow_count = len(client.get("/v1/attack-flows").json())
    source_id = archive(
        client,
        "IOC only",
        "IP: 198.51.100.44\nDOMAIN: Example[.]COM.",
    )

    staged_response = client.post(
        "/v1/knowledge-ingestions",
        json={
            "source_document_id": source_id,
            "attack_flow_candidates": [],
        },
    )

    assert staged_response.status_code == 200
    staged = staged_response.json()
    assert staged["flow_candidate_summary"] == {
        "status": "no-flow",
        "candidate_count": 0,
        "recommendation": "no-flow",
        "merge_target_flow_id": None,
        "reason": "来源没有形成可发布的攻击活动候选。",
    }
    assert staged["path_outcome"]["status"] == "no-path"
    assert staged["canonical_delta"]["create_entities"] == 2
    published = client.post(
        f"/v1/knowledge-ingestions/{staged['id']}/publish"
    )
    assert published.status_code == 200
    assert len(client.get("/v1/attack-flows").json()) == baseline_flow_count


def test_multiple_candidates_are_isolated_and_independently_reviewed(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    baseline_flow_count = len(client.get("/v1/attack-flows").json())
    content = "\n\n".join(
        [
            "NightFox 投递文档并连接 198.51.100.77。",
            "文档随后创建计划任务。",
            "BlueBird 发送恶意链接。",
            "用户点击链接后启动命令行。",
        ]
    )
    source_id = archive(client, "Two independent activities", content)
    first = two_step_candidate(
        prefix="NF",
        first_quote="NightFox 投递文档并连接 198.51.100.77。",
        second_quote="文档随后创建计划任务。",
        first_name="投递恶意文档",
        second_name="创建计划任务",
        ip="198.51.100.77",
        actor="NightFox",
    )
    second = two_step_candidate(
        prefix="BB",
        first_quote="BlueBird 发送恶意链接。",
        second_quote="用户点击链接后启动命令行。",
        first_name="发送恶意链接",
        second_name="启动命令行",
        actor="BlueBird",
    )
    second["relations"][0]["type"] = "branch"

    response = client.post(
        "/v1/knowledge-ingestions",
        json={
            "source_document_id": source_id,
            "attack_flow_candidates": [first, second],
        },
    )

    assert response.status_code == 200
    batch = response.json()
    assert batch["ingestion_kind"] == "attack-flow-batch"
    assert batch["flow_candidate_summary"]["status"] == "multiple"
    assert batch["flow_candidate_summary"]["candidate_count"] == 2
    assert len(batch["candidates"]) == 2
    first_run, second_run = batch["candidates"]
    assert first_run["id"] != second_run["id"]
    assert first_run["attack_flow_preview"]["flow_id"] != second_run[
        "attack_flow_preview"
    ]["flow_id"]
    assert first_run["publishable"] is True
    assert second_run["publishable"] is False

    published = client.post(
        f"/v1/knowledge-ingestions/{first_run['id']}/publish"
    )
    assert published.status_code == 200
    blocked = client.post(
        f"/v1/knowledge-ingestions/{second_run['id']}/publish"
    )
    assert blocked.status_code == 409
    rejected = client.post(
        f"/v1/knowledge-ingestions/{second_run['id']}/reject"
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
    assert len(client.get("/v1/attack-flows").json()) == baseline_flow_count + 1


def test_new_source_can_explicitly_support_existing_flow_idempotently(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    baseline_flow_count = len(client.get("/v1/attack-flows").json())
    first_quote = "NightFox 投递文档并连接 198.51.100.88。"
    first_second_quote = "文档随后创建计划任务。"
    first_source = archive(
        client,
        "Primary activity source",
        f"{first_quote}\n\n{first_second_quote}",
    )
    first_candidate = two_step_candidate(
        prefix="NF1",
        first_quote=first_quote,
        second_quote=first_second_quote,
        first_name="投递恶意文档",
        second_name="创建计划任务",
        ip="198.51.100.88",
        actor="NightFox",
        technique_id="T1053.005",
    )
    first_staged = client.post(
        "/v1/knowledge-ingestions",
        json={
            "source_document_id": first_source,
            "attack_flow_candidate": first_candidate,
        },
    ).json()
    first_published = client.post(
        f"/v1/knowledge-ingestions/{first_staged['id']}/publish"
    ).json()
    flow_id = first_published["attack_flow_preview"]["flow_id"]
    flow = client.get(f"/v1/attack-flows/{flow_id}").json()

    repeated_stage = client.post(
        "/v1/knowledge-ingestions",
        json={
            "source_document_id": first_source,
            "attack_flow_candidate": first_candidate,
        },
    ).json()
    repeated = client.post(
        f"/v1/knowledge-ingestions/{repeated_stage['id']}/publish"
    ).json()
    assert repeated["version"]["changes"]["support_already_present"] is True
    assert repeated["attack_flow_preview"]["flow_id"] == flow_id
    assert len(client.get("/v1/attack-flows").json()) == baseline_flow_count + 1

    second_quote = "另一报告确认 NightFox 投递文档并连接 198.51.100.88。"
    second_second_quote = "该文档同样创建计划任务。"
    second_source = archive(
        client,
        "Corroborating activity source",
        f"{second_quote}\n\n{second_second_quote}",
    )
    second_candidate = two_step_candidate(
        prefix="NF2",
        first_quote=second_quote,
        second_quote=second_second_quote,
        first_name="投递恶意文档",
        second_name="创建计划任务",
        ip="198.51.100.88",
        actor="NightFox",
        technique_id="T1053.005",
    )

    suggested = client.post(
        "/v1/knowledge-ingestions",
        json={
            "source_document_id": second_source,
            "attack_flow_candidate": second_candidate,
        },
    ).json()
    assert suggested["flow_candidate_summary"]["recommendation"] == "merge"
    assert suggested["flow_candidate_summary"]["merge_target_flow_id"] == flow_id
    assert suggested["publish_mode"] == "create"

    merge_review = {
        "target_flow_id": flow_id,
        "confirmed": True,
        "action_map": {
            "NF2-A1": flow["actions"][0]["id"],
            "NF2-A2": flow["actions"][1]["id"],
        },
    }
    merged_stage = client.post(
        "/v1/knowledge-ingestions",
        json={
            "source_document_id": second_source,
            "attack_flow_candidate": second_candidate,
            "merge_review": merge_review,
        },
    ).json()
    assert merged_stage["publishable"] is True
    assert merged_stage["publish_mode"] == "merge"
    merged = client.post(
        f"/v1/knowledge-ingestions/{merged_stage['id']}/publish"
    ).json()
    assert merged["version"]["changes"]["supported_attack_flow_id"] == flow_id
    assert len(client.get("/v1/attack-flows").json()) == baseline_flow_count + 1
    merged_flow = client.get(f"/v1/attack-flows/{flow_id}").json()
    assert {source["id"] for source in merged_flow["sources"]} == {
        first_source,
        second_source,
    }
    assert len(merged_flow["reported_actors"]) == 2

    duplicate_stage = client.post(
        "/v1/knowledge-ingestions",
        json={
            "source_document_id": second_source,
            "attack_flow_candidate": second_candidate,
            "merge_review": merge_review,
        },
    ).json()
    duplicate = client.post(
        f"/v1/knowledge-ingestions/{duplicate_stage['id']}/publish"
    ).json()
    assert duplicate["version"]["changes"]["support_already_present"] is True
    duplicate_flow = client.get(f"/v1/attack-flows/{flow_id}").json()
    assert len(duplicate_flow["sources"]) == 2
    assert len(duplicate_flow["reported_actors"]) == 2

    rollback = client.post(
        f"/v1/knowledge-versions/{merged['version']['id']}/rollback"
    ).json()
    assert rollback["status"] == "rolled_back"
    rolled_back_flow = client.get(f"/v1/attack-flows/{flow_id}").json()
    assert {source["id"] for source in rolled_back_flow["sources"]} == {
        first_source
    }


def test_actor_or_attack_technique_alone_cannot_merge_flows(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    first_quote = "NightFox 发送恶意链接。"
    second_quote = "用户点击链接后启动命令行。"
    source_id = archive(
        client,
        "Actor technique only",
        f"{first_quote}\n\n{second_quote}",
    )
    candidate = two_step_candidate(
        prefix="WEAK",
        first_quote=first_quote,
        second_quote=second_quote,
        first_name="发送恶意链接",
        second_name="启动命令行",
        actor="APT28",
        technique_id="T1053.005",
    )
    target = client.get("/v1/attack-flows").json()[0]
    merge_review = {
        "target_flow_id": target["id"],
        "confirmed": True,
        "action_map": {
            "WEAK-A1": target["actions"][0]["id"],
            "WEAK-A2": target["actions"][1]["id"],
        },
    }

    staged = client.post(
        "/v1/knowledge-ingestions",
        json={
            "source_document_id": source_id,
            "attack_flow_candidate": candidate,
            "merge_review": merge_review,
        },
    ).json()

    assert staged["publishable"] is False
    merge_gate = next(
        gate for gate in staged["quality_gates"] if gate["id"] == "flow-merge"
    )
    assert merge_gate["status"] == "block"
    assert "Actor 或 ATT&CK" in merge_gate["detail"]
    assert client.post(
        f"/v1/knowledge-ingestions/{staged['id']}/publish"
    ).status_code == 409
