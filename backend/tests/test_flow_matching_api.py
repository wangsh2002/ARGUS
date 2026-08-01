from pathlib import Path
import shutil
import sqlite3

from fastapi.testclient import TestClient

from argus_backend.api import create_app


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
APT28_FLOW_ID = "PATH-ANNOCTR-APT28-ZEBROCY-2020"
LAZARUS_FLOW_ID = "PATH-ANNOCTR-LAZARUS-REDBANC-2018"


def make_client(tmp_path: Path) -> TestClient:
    database_path = tmp_path / "argus_cti.db"
    shutil.copy2(REPOSITORY_ROOT / "data" / "argus_cti.db", database_path)
    return TestClient(create_app(database_path=database_path))


def match(client: TestClient, inputs: list[dict[str, str]]):
    return client.post(
        "/v1/flow-matches",
        json={
            "query_text": "；".join(item["value"] for item in inputs),
            "inputs": inputs,
        },
    )


def test_partial_clues_match_a_flow_and_overlay_mainline_progress(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)

    response = match(
        client,
        [
            {"value": "打开 ZIPX 诱饵", "kind": "behavior"},
            {"value": "Zebrocy Delphi", "kind": "malware"},
            {"value": "创建计划任务", "kind": "behavior"},
        ],
    )

    assert response.status_code == 200
    run = response.json()
    assert run["status"] == "completed"
    assert run["algorithm_version"].startswith("attack-flow-matcher/")
    assert len(run["knowledge_snapshot"]) == 64
    assert run["normalized_inputs"] == [
        {
            "value": "打开 ZIPX 诱饵",
            "kind": "behavior",
            "normalized_value": "打开zipx诱饵",
        },
        {
            "value": "Zebrocy Delphi",
            "kind": "malware",
            "normalized_value": "zebrocydelphi",
        },
        {
            "value": "创建计划任务",
            "kind": "behavior",
            "normalized_value": "创建计划任务",
        },
    ]
    candidate = run["candidates"][0]
    assert candidate["flow_id"] == APT28_FLOW_ID
    assert candidate["unmatched_inputs"] == []
    assert candidate["mainline_frontier_action_id"] == f"{APT28_FLOW_ID}-N-05"
    assert candidate["mainline_frontier_index"] == 4
    assert [item["match_kind"] for item in candidate["matches"]] == [
        "behavior",
        "context",
        "behavior",
    ]
    assert [item["action_id"] for item in candidate["matches"]] == [
        f"{APT28_FLOW_ID}-N-01",
        f"{APT28_FLOW_ID}-N-03",
        f"{APT28_FLOW_ID}-N-05",
    ]
    assert [item["state"] for item in candidate["action_states"]] == [
        "input_hit",
        "reconstructed",
        "input_hit",
        "reconstructed",
        "input_hit",
        "predicted",
        "predicted",
    ]
    context_match = candidate["matches"][1]
    assert context_match["matched_value"] == "Zebrocy Delphi"
    assert "Context" in context_match["explanation"]
    assert "直接观测到行为" not in context_match["explanation"]


def test_context_hit_at_the_end_reconstructs_the_known_prefix(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)

    response = match(
        client,
        [{"value": "194.32.78.245", "kind": "ioc"}],
    )

    assert response.status_code == 200
    candidate = response.json()["candidates"][0]
    assert candidate["flow_id"] == APT28_FLOW_ID
    assert candidate["mainline_frontier_index"] == 6
    assert [item["state"] for item in candidate["action_states"]] == [
        "reconstructed",
        "reconstructed",
        "reconstructed",
        "reconstructed",
        "reconstructed",
        "reconstructed",
        "input_hit",
    ]


def test_attack_annotation_is_supporting_only_and_scores_below_context(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)

    attack_only = match(
        client,
        [{"value": "T1053.005", "kind": "attack"}],
    )
    mixed = match(
        client,
        [
            {
                "value": "Course 5 – 16 October 2020.zipx",
                "kind": "file",
            },
            {"value": "T1053.005", "kind": "attack"},
        ],
    )

    assert attack_only.status_code == 200
    assert attack_only.json()["candidates"] == []
    assert mixed.status_code == 200
    candidate = mixed.json()["candidates"][0]
    assert [item["match_kind"] for item in candidate["matches"]] == [
        "context",
        "attack",
    ]
    assert candidate["matches"][0]["confidence"] > candidate["matches"][1][
        "confidence"
    ]
    assert candidate["mainline_frontier_action_id"] == f"{APT28_FLOW_ID}-N-01"


def test_returns_multiple_candidates_with_deterministic_tie_breaking(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    with sqlite3.connect(tmp_path / "argus_cti.db") as connection:
        connection.execute(
            "UPDATE activity_path_nodes SET label = ? WHERE id IN (?, ?)",
            (
                "收集主机信息",
                f"{APT28_FLOW_ID}-N-06",
                f"{LAZARUS_FLOW_ID}-N-07",
            ),
        )

    first = match(client, [{"value": "收集主机信息", "kind": "behavior"}])
    second = match(client, [{"value": "收集主机信息", "kind": "behavior"}])

    assert first.status_code == 200
    assert second.status_code == 200
    assert [item["flow_id"] for item in first.json()["candidates"]] == [
        APT28_FLOW_ID,
        LAZARUS_FLOW_ID,
    ]
    assert [
        (item["flow_id"], item["score"])
        for item in first.json()["candidates"]
    ] == [
        (item["flow_id"], item["score"])
        for item in second.json()["candidates"]
    ]


def test_unrelated_inputs_return_no_candidate_instead_of_forcing_a_flow(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)

    response = match(
        client,
        [{"value": "完全无关的量子卫星攻击步骤", "kind": "behavior"}],
    )

    assert response.status_code == 200
    assert response.json()["candidates"] == []


def test_non_mainline_context_hit_does_not_predict_every_branch(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)

    response = match(
        client,
        [{"value": "#ApplicantsName#.pdf", "kind": "file"}],
    )

    assert response.status_code == 200
    candidate = response.json()["candidates"][0]
    assert candidate["flow_id"] == LAZARUS_FLOW_ID
    assert candidate["mainline_frontier_action_id"] is None
    states = {item["action_id"]: item["state"] for item in candidate["action_states"]}
    assert states[f"{LAZARUS_FLOW_ID}-N-04"] == "input_hit"
    assert all(
        states[action_id] == "reference"
        for action_id in [
            f"{LAZARUS_FLOW_ID}-N-01",
            f"{LAZARUS_FLOW_ID}-N-02",
            f"{LAZARUS_FLOW_ID}-N-03",
            f"{LAZARUS_FLOW_ID}-N-05",
            f"{LAZARUS_FLOW_ID}-N-06",
            f"{LAZARUS_FLOW_ID}-N-07",
        ]
    )


def test_flow_match_run_can_be_replayed_by_identity(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    response = match(
        client,
        [{"value": "PowerRatankba", "kind": "tool"}],
    )

    assert response.status_code == 200
    created = response.json()
    replay = client.get(f"/v1/flow-matches/{created['id']}")

    assert replay.status_code == 200
    assert replay.json() == created
    with sqlite3.connect(tmp_path / "argus_cti.db") as connection:
        stored = connection.execute(
            """
            SELECT normalized_inputs_json, algorithm_version, knowledge_snapshot
            FROM flow_match_runs
            WHERE id = ?
            """,
            (created["id"],),
        ).fetchone()
    assert stored is not None
    assert stored[0]
    assert stored[1] == created["algorithm_version"]
    assert stored[2] == created["knowledge_snapshot"]
