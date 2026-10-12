from pathlib import Path
import json
import shutil

from fastapi.testclient import TestClient

from argus_backend.api import create_app
from argus_backend.attack_flow_extraction import (
    DeepSeekAttackFlowExtractor,
    _consolidated_activity_slices,
    _expand_single_activity_span,
    _is_concise_action_name,
    _merge_raw_relations,
    _normalize_action_name,
    _validated_activity_groups,
    _validated_activity_slices,
    _validated_variant_plan,
    extract_attack_flow_candidates,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SOURCE_TEXT = "\n\n".join(
    [
        "NightFox 通过钓鱼邮件投递恶意文档。",
        "受害者打开文档后执行 PowerShell，并下载 Cobalt Strike。",
        "PowerShell 成功后创建计划任务。",
        "报告称该活动由 NightFox 实施。",
        "另一组研究者仅评估 BlueBird 可能相关。",
        "恶意文档打开成功或 PowerShell 执行成功后都会创建计划任务。",
        "计划任务随后回传数据。",
    ]
)


class FixedAttackFlowModel:
    model = "attack-flow-schema-test"

    def __init__(self, result: dict) -> None:
        self.result = result
        self.calls = 0

    def extract_attack_flows(self, report, source_text):
        self.calls += 1
        assert report["sha256"]
        assert source_text == SOURCE_TEXT
        return self.result


def action(action_id: str, name: str, quote: str, **extra) -> dict:
    return {
        "id": action_id,
        "name": name,
        "description": quote,
        "confidence": "high",
        "technique_ids": [],
        "contexts": [],
        "evidence": [{"quote": quote}],
        **extra,
    }


def valid_candidate(prefix: str = "GLOBAL") -> dict:
    first_quote = "NightFox 通过钓鱼邮件投递恶意文档。"
    second_quote = "受害者打开文档后执行 PowerShell，并下载 Cobalt Strike。"
    return {
        "title": "NightFox 文档投递活动",
        "description": "报告中的两步攻击活动。",
        "actions": [
            action(f"{prefix}-ACTION-99", "投递恶意文档", first_quote),
            action(f"{prefix}-ACTION-100", "执行 PowerShell", second_quote),
        ],
        "relations": [
            {
                "id": f"{prefix}-RELATION-99",
                "source_action_id": f"{prefix}-ACTION-99",
                "target_action_id": f"{prefix}-ACTION-100",
                "type": "enables",
                "condition": None,
                "confidence": "high",
                "evidence": [{"quote": second_quote}],
            }
        ],
        "mainline": [f"{prefix}-ACTION-99", f"{prefix}-ACTION-100"],
        "reported_actors": [
            {
                "id": f"{prefix}-ACTOR-99",
                "reported_name": "NightFox",
                "confidence": "medium",
                "evidence": [
                    {"quote": "报告称该活动由 NightFox 实施。"}
                ],
            }
        ],
    }


def archive(client: TestClient) -> str:
    response = client.post(
        "/v1/sources",
        json={
            "title": "AnnoCTR acceptance excerpt",
            "publisher": "Acceptance CERT",
            "canonical_url": "https://example.invalid/annoctr-acceptance",
            "published_at": "2026-08-01",
            "mime_type": "text/plain",
            "content": SOURCE_TEXT,
        },
    )
    assert response.status_code == 200
    return response.json()["source_document"]["id"]


def make_client(tmp_path: Path, model: FixedAttackFlowModel) -> TestClient:
    tmp_path.mkdir(parents=True, exist_ok=True)
    database_path = tmp_path / "argus_cti.db"
    shutil.copy2(REPOSITORY_ROOT / "data" / "argus_cti.db", database_path)
    return TestClient(
        create_app(
            database_path=database_path,
            attack_flow_language_model=model,
        )
    )


def test_model_output_is_rewritten_to_local_ids_and_canonical_shape() -> None:
    raw = {
        "candidates": [valid_candidate()],
        "unassigned_evidence": [
            {
                "quote": "另一组研究者仅评估 BlueBird 可能相关。",
                "reason": "归因不足以改变活动所属",
            }
        ],
    }
    result = extract_attack_flow_candidates(
        FixedAttackFlowModel(raw),
        {"sha256": "a" * 64},
        SOURCE_TEXT,
    )

    candidate = result.candidates[0]
    assert [item.id for item in candidate.actions] == ["A1", "A2"]
    assert candidate.relations[0].id == "R1"
    assert candidate.relations[0].source_action_id == "A1"
    assert candidate.relations[0].target_action_id == "A2"
    assert candidate.mainline == ["A1", "A2"]
    assert candidate.reported_actors[0].id == "ACTOR1"
    assert result.audit["candidate_count"] == 1
    assert result.audit["unassigned_evidence"][0]["quote"] in SOURCE_TEXT


def test_valid_action_phrases_do_not_depend_on_a_fixed_verb_list() -> None:
    candidate = valid_candidate()
    candidate["actions"][0]["name"] = "Conduct document delivery"
    candidate["actions"][1]["name"] = "Monitor PowerShell execution"

    result = extract_attack_flow_candidates(
        FixedAttackFlowModel({"candidates": [candidate]}),
        {"sha256": "9" * 64},
        SOURCE_TEXT,
    )

    assert [item.name for item in result.candidates[0].actions] == [
        "Conduct document delivery",
        "Monitor PowerShell execution",
    ]


def test_organization_operations_are_not_persisted_as_attack_actions() -> None:
    candidate = valid_candidate()
    candidate["actions"].append(
        action(
            "ORG-ACTION",
            "Announce group affiliation",
            "报告称该活动由 NightFox 实施。",
            scope="organization",
        )
    )
    candidate["relations"].append(
        {
            "id": "ORG-RELATION",
            "source_action_id": "GLOBAL-ACTION-100",
            "target_action_id": "ORG-ACTION",
            "type": "precedes",
            "confidence": "medium",
            "evidence": [{"quote": "报告称该活动由 NightFox 实施。"}],
        }
    )

    result = extract_attack_flow_candidates(
        FixedAttackFlowModel({"candidates": [candidate]}),
        {"sha256": "7" * 64},
        SOURCE_TEXT,
    )

    assert [item.name for item in result.candidates[0].actions] == [
        "投递恶意文档",
        "执行 PowerShell",
    ]
    assert any(
        item["reason"] == "action-outside-cyber-operation"
        for item in result.audit["rejected_facts"]
    )


def test_invalid_facts_are_audited_and_missing_relation_stays_disconnected() -> None:
    candidate = valid_candidate()
    second_quote = "受害者打开文档后执行 PowerShell，并下载 Cobalt Strike。"
    candidate["actions"].extend(
        [
            action("MALWARE-NODE", "Cobalt Strike", second_quote, kind="malware"),
            action(
                "SENTENCE-NODE",
                "受害者打开文档后执行 PowerShell，然后下载并启动了恶意软件。",
                second_quote,
            ),
        ]
    )
    candidate["actions"][1]["contexts"] = [
        {
            "id": "GLOBAL-CONTEXT",
            "type": "malware",
            "name": "Cobalt Strike",
            "role": "downloads-from",
            "confidence": "high",
            "evidence": [{"quote": second_quote}],
        }
    ]
    candidate["relations"] = [
        {
            "id": "NO-EVIDENCE",
            "source_action_id": "GLOBAL-ACTION-99",
            "target_action_id": "GLOBAL-ACTION-100",
            "type": "enables",
            "evidence": [],
        },
        {
            "id": "UNKNOWN-TYPE",
            "source_action_id": "GLOBAL-ACTION-99",
            "target_action_id": "GLOBAL-ACTION-100",
            "type": "downloads",
            "evidence": [{"quote": second_quote}],
        },
    ]
    candidate["actions"][0]["evidence"].append(
        {"quote": "这是模型编造且原文不存在的句子。"}
    )

    result = extract_attack_flow_candidates(
        FixedAttackFlowModel({"candidates": [candidate]}),
        {"sha256": "b" * 64},
        SOURCE_TEXT,
    )

    sanitized = result.candidates[0]
    assert [item.name for item in sanitized.actions] == [
        "投递恶意文档",
        "执行 PowerShell",
    ]
    assert sanitized.actions[1].contexts[0].name == "Cobalt Strike"
    assert sanitized.relations == []
    assert sanitized.mainline == []
    reasons = {item["reason"] for item in result.audit["rejected_facts"]}
    assert "name-is-not-concise-verb-object" in reasons
    assert "unsupported-relation-type" in reasons
    assert "no-valid-source-quote" in reasons
    assert "quote-not-in-source" in reasons


def test_extracted_candidates_use_existing_staging_and_publication_pipeline(
    tmp_path: Path,
) -> None:
    model = FixedAttackFlowModel({"candidates": [valid_candidate()]})
    client = make_client(tmp_path, model)
    source_id = archive(client)

    response = client.post(
        "/v1/knowledge-ingestions",
        json={
            "source_document_id": source_id,
            "extract_attack_flows": True,
        },
    )

    assert response.status_code == 200
    staged = response.json()
    assert model.calls == 1
    assert staged["ingestion_kind"] == "attack-flow"
    assert staged["publishable"] is True
    assert staged["extraction_audit"]["method"] == (
        "schema-first-attack-flow-extraction"
    )
    assert staged["attack_flow_candidate"]["mainline"] == ["A1", "A2"]
    assert staged["attack_flow_preview"]["mainline"] == [
        staged["attack_flow_preview"]["actions"][0]["id"],
        staged["attack_flow_preview"]["actions"][1]["id"],
    ]

    published = client.post(
        f"/v1/knowledge-ingestions/{staged['id']}/publish"
    )
    assert published.status_code == 200
    flow_id = published.json()["attack_flow_preview"]["flow_id"]
    assert client.get(f"/v1/attack-flows/{flow_id}").status_code == 200


def test_zero_and_multiple_candidates_preserve_cardinality(tmp_path: Path) -> None:
    no_flow_model = FixedAttackFlowModel(
        {
            "candidates": [],
            "unassigned_evidence": [
                {
                    "quote": "另一组研究者仅评估 BlueBird 可能相关。",
                    "reason": "只有归因评估",
                }
            ],
        }
    )
    no_flow_client = make_client(tmp_path / "zero", no_flow_model)
    source_id = archive(no_flow_client)
    no_flow = no_flow_client.post(
        "/v1/knowledge-ingestions",
        json={"source_document_id": source_id, "extract_attack_flows": True},
    ).json()
    assert no_flow["ingestion_kind"] == "entity-evidence"
    assert no_flow["flow_candidate_summary"]["candidate_count"] == 0
    assert no_flow["extraction_audit"]["attack_flow_extraction"][
        "unassigned_evidence"
    ]

    multiple_model = FixedAttackFlowModel(
        {"candidates": [valid_candidate("FIRST"), valid_candidate("SECOND")]}
    )
    multiple_client = make_client(tmp_path / "multiple", multiple_model)
    source_id = archive(multiple_client)
    batch = multiple_client.post(
        "/v1/knowledge-ingestions",
        json={"source_document_id": source_id, "extract_attack_flows": True},
    ).json()
    assert batch["ingestion_kind"] == "attack-flow-batch"
    assert batch["flow_candidate_summary"]["candidate_count"] == 2
    assert len(batch["candidates"]) == 2
    assert all(
        candidate["extraction_audit"]["candidate_count"] == 2
        for candidate in batch["candidates"]
    )


def test_missing_relation_quote_blocks_mainline_without_fabricating_edge(
    tmp_path: Path,
) -> None:
    candidate = valid_candidate()
    candidate["relations"][0]["evidence"] = []
    client = make_client(
        tmp_path,
        FixedAttackFlowModel({"candidates": [candidate]}),
    )
    source_id = archive(client)

    staged = client.post(
        "/v1/knowledge-ingestions",
        json={"source_document_id": source_id, "extract_attack_flows": True},
    ).json()

    assert staged["attack_flow_candidate"]["relations"] == []
    assert staged["attack_flow_candidate"]["mainline"] == []
    assert staged["publishable"] is False
    mainline_gate = next(
        gate for gate in staged["quality_gates"] if gate["id"] == "flow-mainline"
    )
    assert mainline_gate["status"] == "block"


def test_model_mainline_does_not_override_verified_relation_graph() -> None:
    candidate = valid_candidate()
    candidate["actions"].append(
        action(
            "GLOBAL-ACTION-101",
            "创建计划任务",
            "PowerShell 成功后创建计划任务。",
        )
    )
    candidate["relations"].append(
        {
            "id": "GLOBAL-RELATION-100",
            "source_action_id": "GLOBAL-ACTION-100",
            "target_action_id": "GLOBAL-ACTION-101",
            "type": "on_success",
            "evidence": [{"quote": "PowerShell 成功后创建计划任务。"}],
        }
    )
    candidate["mainline"] = [
        "GLOBAL-ACTION-99",
        "UNKNOWN-ACTION",
        "GLOBAL-ACTION-100",
        "GLOBAL-ACTION-101",
    ]

    result = extract_attack_flow_candidates(
        FixedAttackFlowModel({"candidates": [candidate]}),
        {"sha256": "c" * 64},
        SOURCE_TEXT,
    )

    assert result.candidates[0].mainline == ["A1", "A2", "A3"]


def test_single_action_is_not_promoted_to_an_attack_flow() -> None:
    candidate = valid_candidate()
    candidate["actions"] = candidate["actions"][:1]
    candidate["relations"] = []
    candidate["mainline"] = ["GLOBAL-ACTION-99"]

    result = extract_attack_flow_candidates(
        FixedAttackFlowModel({"candidates": [candidate]}),
        {"sha256": "d" * 64},
        SOURCE_TEXT,
    )

    assert result.candidates == []
    assert "candidate-has-fewer-than-two-actions" in {
        item["reason"] for item in result.audit["rejected_facts"]
    }


def test_evidence_backed_branch_and_merge_relations_are_preserved() -> None:
    candidate = valid_candidate()
    candidate["actions"].append(
        action(
            "GLOBAL-ACTION-101",
            "创建计划任务",
            "PowerShell 成功后创建计划任务。",
        )
    )
    relation_quote = (
        "恶意文档打开成功或 PowerShell 执行成功后都会创建计划任务。"
    )
    candidate["relations"] = [
        {
            "id": "BRANCH-1",
            "source_action_id": "GLOBAL-ACTION-99",
            "target_action_id": "GLOBAL-ACTION-101",
            "type": "leads_to",
            "evidence": [{"quote": relation_quote}],
        },
        {
            "id": "MERGE-1",
            "source_action_id": "GLOBAL-ACTION-100",
            "target_action_id": "GLOBAL-ACTION-101",
            "type": "on_success",
            "evidence": [{"quote": relation_quote}],
        },
    ]
    candidate["mainline"] = ["GLOBAL-ACTION-99", "GLOBAL-ACTION-101"]

    result = extract_attack_flow_candidates(
        FixedAttackFlowModel({"candidates": [candidate]}),
        {"sha256": "e" * 64},
        SOURCE_TEXT,
    )

    assert [relation.type for relation in result.candidates[0].relations] == [
        "leads_to",
        "on_success",
    ]
    assert [
        relation.target_action_id for relation in result.candidates[0].relations
    ] == ["A3", "A3"]


def test_disconnected_component_moves_to_review_fragments() -> None:
    candidate = valid_candidate()
    candidate["actions"].extend(
        [
            action(
                "GLOBAL-ACTION-101",
                "创建计划任务",
                "PowerShell 成功后创建计划任务。",
            ),
            action(
                "GLOBAL-ACTION-102",
                "回传数据",
                "计划任务随后回传数据。",
            ),
        ]
    )
    candidate["relations"].append(
        {
            "id": "GLOBAL-RELATION-100",
            "source_action_id": "GLOBAL-ACTION-101",
            "target_action_id": "GLOBAL-ACTION-102",
            "type": "leads_to",
            "evidence": [{"quote": "计划任务随后回传数据。"}],
        }
    )

    result = extract_attack_flow_candidates(
        FixedAttackFlowModel({"candidates": [candidate]}),
        {"sha256": "f" * 64},
        SOURCE_TEXT,
    )

    assert [action.name for action in result.candidates[0].actions] == [
        "投递恶意文档",
        "执行 PowerShell",
    ]
    assert result.candidates[0].mainline == ["A1", "A2"]
    assert result.audit["review_fragments"][0]["reason"] == (
        "disconnected-from-primary-flow"
    )
    assert [
        action["name"] for action in result.audit["review_fragments"][0]["actions"]
    ] == ["创建计划任务", "回传数据"]


def test_verified_variant_components_remain_without_fabricated_edges() -> None:
    candidate = valid_candidate()
    candidate["actions"].extend(
        [
            action(
                "GLOBAL-ACTION-101",
                "创建计划任务",
                "PowerShell 成功后创建计划任务。",
            ),
            action(
                "GLOBAL-ACTION-102",
                "回传数据",
                "计划任务随后回传数据。",
            ),
        ]
    )
    candidate["relations"].append(
        {
            "id": "GLOBAL-RELATION-100",
            "source_action_id": "GLOBAL-ACTION-101",
            "target_action_id": "GLOBAL-ACTION-102",
            "type": "leads_to",
            "evidence": [{"quote": "计划任务随后回传数据。"}],
        }
    )
    candidate["_verified_variant_plan"] = {
        "variants": [
            {
                "id": "V1",
                "line_ranges": [{"start_line": 1, "end_line": 3}],
            },
            {
                "id": "V2",
                "line_ranges": [{"start_line": 5, "end_line": 13}],
            },
        ]
    }

    result = extract_attack_flow_candidates(
        FixedAttackFlowModel({"candidates": [candidate]}),
        {"sha256": "2" * 64},
        SOURCE_TEXT,
    )

    assert [action.name for action in result.candidates[0].actions] == [
        "投递恶意文档",
        "执行 PowerShell",
        "创建计划任务",
        "回传数据",
    ]
    assert len(result.candidates[0].relations) == 2
    assert result.candidates[0].mainline == ["A1", "A2"]
    assert result.audit["review_fragments"] == []


def test_activity_slices_reject_overlap_and_out_of_bounds_ranges() -> None:
    source = "title\nactivity one\nactivity one detail\nactivity two\nend"
    slices = _validated_activity_slices(
        {
            "activities": [
                {"title": "first", "start_line": 2, "end_line": 3},
                {"title": "overlap", "start_line": 3, "end_line": 4},
                {"title": "outside", "start_line": 6, "end_line": 7},
                {"title": "second", "start_line": 4, "end_line": 5},
            ]
        },
        source,
    )

    assert [(item["title"], item["start_line"], item["end_line"]) for item in slices] == [
        ("first", 2, 3),
        ("second", 4, 5),
    ]


def test_activity_slice_can_join_noncontiguous_sections_of_same_activity() -> None:
    source = "title\ndelivery\nbackground\npayload\nc2"
    slices = _validated_activity_slices(
        {
            "activities": [
                {
                    "title": "one campaign",
                    "line_ranges": [
                        {"start_line": 2, "end_line": 2},
                        {"start_line": 4, "end_line": 5},
                    ],
                }
            ]
        },
        source,
    )

    assert slices[0]["line_ranges"] == [
        {"start_line": 2, "end_line": 2},
        {"start_line": 4, "end_line": 5},
    ]
    assert slices[0]["numbered_source"] == (
        "L0002\tdelivery\nL0004\tpayload\nL0005\tc2"
    )


def test_activity_groups_require_exact_evidence_and_keep_unmerged_segments() -> None:
    source = "same campaign\nentry one\nentry two\nother campaign"
    slices = _validated_activity_slices(
        {
            "activities": [
                {"title": "entry one", "start_line": 2, "end_line": 2},
                {"title": "entry two", "start_line": 3, "end_line": 3},
                {"title": "other", "start_line": 4, "end_line": 4},
            ]
        },
        source,
    )

    groups = _validated_activity_groups(
        {
            "groups": [
                {
                    "segment_ids": ["S1", "S2"],
                    "title": "shared activity",
                    "evidence": [{"quote": "same campaign"}],
                },
                {
                    "segment_ids": ["S2", "S3"],
                    "title": "overlapping guess",
                    "evidence": [{"quote": "other campaign"}],
                },
            ]
        },
        slices,
        source,
    )

    assert groups == [
        {
            "segment_ids": ["S1", "S2"],
            "title": "shared activity",
            "evidence_quotes": ["same campaign"],
            "method": "evidence-backed-model",
        },
        {
            "segment_ids": ["S3"],
            "title": "other",
            "evidence_quotes": [],
            "method": "independent",
        },
    ]
    consolidated = _consolidated_activity_slices(slices, groups)
    assert consolidated[0]["segment_ids"] == ["S1", "S2"]
    assert consolidated[0]["numbered_source"] == (
        "L0002\tentry one\nL0003\tentry two"
    )
    assert consolidated[1]["segment_ids"] == ["S3"]


def test_bracketed_similar_segments_merge_without_merging_adjacent_activity() -> None:
    source = "\n".join(
        [
            "outer start",
            "outer detail",
            "inner entry",
            "inner detail",
            "shared payload",
            "shared c2",
            "later entry",
            "later payload",
        ]
    )
    slices = _validated_activity_slices(
        {
            "activities": [
                {
                    "title": "Example loader delivering shared payload via word document",
                    "actor_anchor": "Example actor",
                    "line_ranges": [
                        {"start_line": 1, "end_line": 2},
                        {"start_line": 5, "end_line": 6},
                    ],
                },
                {
                    "title": "Example loader delivering shared payload via excel document",
                    "actor_anchor": "Example actor",
                    "start_line": 3,
                    "end_line": 4,
                },
                {
                    "title": "Example loader later campaign",
                    "actor_anchor": "Example actor",
                    "start_line": 7,
                    "end_line": 8,
                },
            ]
        },
        source,
    )

    groups = _validated_activity_groups({}, slices, source)

    assert groups[0]["segment_ids"] == ["S1", "S2"]
    assert groups[0]["method"] == "bracketed-similar-title"
    assert groups[1]["segment_ids"] == ["S3"]
    assert groups[1]["method"] == "independent"


def test_bracketed_segments_with_different_actor_anchors_stay_independent() -> None:
    source = "outer entry\ninner entry\nouter payload"
    slices = _validated_activity_slices(
        {
            "activities": [
                {
                    "title": "Shared incident entry and payload",
                    "actor_anchor": "Actor Alpha",
                    "line_ranges": [
                        {"start_line": 1, "end_line": 1},
                        {"start_line": 3, "end_line": 3},
                    ],
                },
                {
                    "title": "Shared incident alternate entry",
                    "actor_anchor": "Actor Beta",
                    "start_line": 2,
                    "end_line": 2,
                },
            ]
        },
        source,
    )

    groups = _validated_activity_groups({}, slices, source)

    assert [group["segment_ids"] for group in groups] == [["S1"], ["S2"]]


def test_single_activity_span_keeps_internal_variant_sections() -> None:
    source = "title\nentry variant\nvariant transition\nshared payload\nappendix"
    activity = {
        "id": "G1",
        "title": "one incident",
        "start_line": 2,
        "end_line": 4,
        "line_ranges": [
            {"start_line": 2, "end_line": 2},
            {"start_line": 4, "end_line": 4},
        ],
        "numbered_source": "L0002\tentry variant\nL0004\tshared payload",
        "text": "entry variant\nshared payload",
    }

    expanded = _expand_single_activity_span(activity, source)

    assert expanded["line_ranges"] == [
        {"start_line": 2, "end_line": 4}
    ]
    assert expanded["numbered_source"] == (
        "L0002\tentry variant\n"
        "L0003\tvariant transition\n"
        "L0004\tshared payload"
    )


def test_relation_merge_keeps_existing_edges_and_adds_distinct_branches() -> None:
    existing = [
        {
            "id": "R1",
            "source_action_id": "A1",
            "target_action_id": "A3",
            "type": "leads_to",
        }
    ]
    discovered = [
        {
            "id": "R9",
            "source_action_id": "A1",
            "target_action_id": "A3",
            "type": "leads_to",
        },
        {
            "id": "R10",
            "source_action_id": "A2",
            "target_action_id": "A3",
            "type": "leads_to",
        },
    ]

    merged = _merge_raw_relations(existing, discovered)

    assert [relation["id"] for relation in merged] == ["R1", "R10"]


def test_variant_plan_requires_two_evidence_backed_paths() -> None:
    source = "variant one\nvariant two\nshared payload"
    activity = {
        "numbered_source": (
            "L0001\tvariant one\n"
            "L0002\tvariant two\n"
            "L0003\tshared payload"
        )
    }

    plan = _validated_variant_plan(
        {
            "variants": [
                {
                    "title": "one",
                    "line_ranges": [{"start_line": 1, "end_line": 1}],
                    "evidence": [{"quote": "variant one"}],
                },
                {
                    "title": "two",
                    "line_ranges": [{"start_line": 2, "end_line": 2}],
                    "evidence": [{"quote": "variant two"}],
                },
            ],
            "shared_successor_evidence": [{"quote": "shared payload"}],
        },
        activity,
        source,
    )

    assert [variant["id"] for variant in plan["variants"]] == ["V1", "V2"]
    assert plan["shared_successor_evidence"] == ["shared payload"]

    one_path = _validated_variant_plan(
        {
            "variants": [
                {
                    "title": "one",
                    "line_ranges": [{"start_line": 1, "end_line": 1}],
                    "evidence": [{"quote": "variant one"}],
                }
            ],
            "shared_successor_evidence": [{"quote": "shared payload"}],
        },
        activity,
        source,
    )
    assert one_path == {"variants": [], "shared_successor_evidence": []}


def test_generic_consolidation_and_relation_pass_preserve_merge(monkeypatch) -> None:
    source = "\n".join(
        [
            "The report states that both entry variants belong to this incident.",
            "Attackers deliver a script through a malicious document.",
            "Attackers also download the script through a malicious link.",
            "Both entry variants then execute the same payload.",
            "A separate incident occurred in another month.",
            "Attackers sent email and then installed a tool.",
        ]
    )
    responses = iter(
        [
            {
                "activities": [
                    {"title": "document entry", "start_line": 2, "end_line": 2},
                    {"title": "link entry", "start_line": 3, "end_line": 4},
                    {"title": "later incident", "start_line": 5, "end_line": 6},
                ]
            },
            {
                "groups": [
                    {
                        "segment_ids": ["S1", "S2"],
                        "title": "two entry variants",
                        "evidence": [
                            {
                                "quote": (
                                    "The report states that both entry variants "
                                    "belong to this incident."
                                )
                            }
                        ],
                    }
                ]
            },
            {
                "variants": [
                    {
                        "id": "V1",
                        "title": "document entry",
                        "path_type": "alternative-entry",
                        "line_ranges": [{"start_line": 2, "end_line": 2}],
                        "evidence": [
                            {
                                "quote": (
                                    "Attackers deliver a script through a "
                                    "malicious document."
                                )
                            }
                        ],
                    },
                    {
                        "id": "V2",
                        "title": "link entry",
                        "path_type": "alternative-entry",
                        "line_ranges": [{"start_line": 3, "end_line": 3}],
                        "evidence": [
                            {
                                "quote": (
                                    "Attackers also download the script through "
                                    "a malicious link."
                                )
                            }
                        ],
                    },
                ],
                "shared_successor_evidence": [
                    {
                        "quote": "Both entry variants then execute the same payload."
                    }
                ],
            },
            {
                "candidates": [
                    {
                        "title": "incomplete first attempt",
                        "description": "",
                        "actions": [
                            action(
                                "A1",
                                "Deliver malicious script",
                                "Attackers deliver a script through a malicious document.",
                            ),
                            action(
                                "A3",
                                "Execute shared payload",
                                "Both entry variants then execute the same payload.",
                            ),
                        ],
                        "relations": [],
                        "reported_actors": [],
                    }
                ],
                "unassigned_evidence": [],
            },
            {
                "candidates": [
                    {
                        "title": "two entry variants",
                        "description": "",
                        "actions": [
                            action(
                                "A1",
                                "Deliver malicious script",
                                "Attackers deliver a script through a malicious document.",
                            ),
                            action(
                                "A2",
                                "Download malicious script",
                                "Attackers also download the script through a malicious link.",
                            ),
                            action(
                                "A3",
                                "Execute shared payload",
                                "Both entry variants then execute the same payload.",
                            ),
                        ],
                        "relations": [],
                        "reported_actors": [],
                    }
                ],
                "unassigned_evidence": [],
            },
            {
                "actions": [
                    {"id": "A1", "decision": "keep", "actor_anchor": "Attackers"},
                    {"id": "A2", "decision": "keep", "actor_anchor": "Attackers"},
                    {"id": "A3", "decision": "keep", "actor_anchor": "Attackers"},
                ]
            },
            {
                "relations": [
                    {
                        "id": "R1",
                        "source_action_id": "A1",
                        "target_action_id": "A3",
                        "type": "leads_to",
                        "confidence": "high",
                        "evidence": [
                            {
                                "quote": (
                                    "Both entry variants then execute the same payload."
                                )
                            }
                        ],
                    },
                    {
                        "id": "R2",
                        "source_action_id": "A2",
                        "target_action_id": "A3",
                        "type": "leads_to",
                        "confidence": "high",
                        "evidence": [
                            {
                                "quote": (
                                    "Both entry variants then execute the same payload."
                                )
                            }
                        ],
                    },
                ]
            },
            {"variants": [], "shared_successor_evidence": []},
            {"candidates": [], "unassigned_evidence": []},
        ]
    )

    monkeypatch.setattr(
        DeepSeekAttackFlowExtractor,
        "_request_json",
        lambda self, prompt, **kwargs: next(responses),
    )
    extractor = DeepSeekAttackFlowExtractor(
        base_url="https://example.invalid",
        api_key="test",
        model="generic-test-model",
    )

    result = extract_attack_flow_candidates(
        extractor,
        {"sha256": "1" * 64, "title": "generic report"},
        source,
    )

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert len(candidate.actions) == 3
    assert len(candidate.relations) == 2
    assert sum(
        relation.target_action_id == "A3"
        for relation in candidate.relations
    ) == 2
    segmentation = result.audit["activity_segmentation"]
    assert len(segmentation["initial_segments"]) == 3
    assert len(segmentation["activities"]) == 2
    assert segmentation["activities"][0]["variant_coverage"] == {
        "required_variant_ids": ["V1", "V2"],
        "covered_variant_ids": ["V1", "V2"],
        "retry_performed": True,
        "complete": True,
        "selected_retry_candidate": True,
    }


def test_empty_initial_segmentation_gets_one_evidence_backed_rescue(
    monkeypatch,
) -> None:
    source = "\n".join(
        [
            "Attackers gained access to the network.",
            "They then monitored email communications.",
        ]
    )
    responses = iter(
        [
            {"activities": []},
            {"activities": []},
            {
                "activities": [
                    {
                        "title": "Network access and monitoring",
                        "start_line": 1,
                        "end_line": 2,
                    }
                ]
            },
            {"variants": [], "shared_successor_evidence": []},
            {
                "candidates": [
                    {
                        "title": "Network monitoring activity",
                        "description": "",
                        "actions": [
                            action(
                                "A1",
                                "Gain network access",
                                "Attackers gained access to the network.",
                            ),
                            action(
                                "A2",
                                "Monitor email communications",
                                "They then monitored email communications.",
                            ),
                        ],
                        "relations": [],
                        "reported_actors": [],
                    }
                ],
                "unassigned_evidence": [],
            },
            {
                "actions": [
                    {"id": "A1", "decision": "keep", "actor_anchor": "Attackers"},
                    {"id": "A2", "decision": "keep", "actor_anchor": "Attackers"},
                ]
            },
            {
                "relations": [
                    {
                        "id": "R1",
                        "source_action_id": "A1",
                        "target_action_id": "A2",
                        "type": "leads_to",
                        "confidence": "high",
                        "evidence": [
                            {"quote": "They then monitored email communications."}
                        ],
                    }
                ]
            },
        ]
    )
    monkeypatch.setattr(
        DeepSeekAttackFlowExtractor,
        "_request_json",
        lambda self, prompt, **kwargs: next(responses),
    )
    extractor = DeepSeekAttackFlowExtractor(
        base_url="https://example.invalid",
        api_key="test",
        model="generic-test-model",
    )

    result = extract_attack_flow_candidates(
        extractor,
        {"sha256": "8" * 64, "title": "generic short incident"},
        source,
    )

    assert [item.name for item in result.candidates[0].actions] == [
        "Gain network access",
        "Monitor email communications",
    ]
    assert result.audit["activity_segmentation"]["rescue_performed"] is True
    assert result.audit["activity_segmentation"]["rescue_attempts"] == 2


def test_model_transport_retries_one_truncated_json_response(monkeypatch) -> None:
    contents = iter(
        [
            '{"activities":[{"title":"truncated',
            '{"activities":[]}',
        ]
    )
    calls = []

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "choices": [
                    {"message": {"content": next(contents)}}
                ]
            }

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

        def post(self, *args, **kwargs):
            calls.append(kwargs["json"])
            return FakeResponse()

    monkeypatch.setattr(
        "argus_backend.attack_flow_extraction.httpx.Client",
        lambda **kwargs: FakeClient(),
    )
    extractor = DeepSeekAttackFlowExtractor(
        base_url="https://example.invalid",
        api_key="test",
        model="generic-test-model",
    )

    result = extractor._request_json(
        {"task": "return valid JSON"},
        max_tokens=100,
        system_message="JSON only",
    )

    assert result["activities"] == []
    assert len(calls) == 2
    assert "response_retry" in calls[1]["messages"][1]["content"]


def test_relation_pass_discards_model_edge_outside_cyber_operation(
    monkeypatch,
) -> None:
    source = "\n".join(
        [
            "The actor attempted to sell remote access.",
            "The actor then advertised the access on a forum.",
        ]
    )
    responses = iter(
        [
            {
                "activities": [
                    {
                        "title": "Access sale",
                        "actor_anchor": "the actor",
                        "start_line": 1,
                        "end_line": 2,
                    }
                ]
            },
            {"variants": [], "shared_successor_evidence": []},
            {
                "candidates": [
                    {
                        "title": "Access sale",
                        "description": "",
                        "actions": [
                            action(
                                "A1",
                                "Attempt access sale",
                                "The actor attempted to sell remote access.",
                                scope="attack",
                            ),
                            action(
                                "A2",
                                "Advertise access listing",
                                "The actor then advertised the access on a forum.",
                                scope="attack",
                            ),
                        ],
                        "relations": [
                            {
                                "id": "R1",
                                "source_action_id": "A1",
                                "target_action_id": "A2",
                                "type": "precedes",
                                "confidence": "medium",
                                "evidence": [
                                    {
                                        "quote": (
                                            "The actor then advertised the access "
                                            "on a forum."
                                        )
                                    }
                                ],
                            }
                        ],
                        "reported_actors": [],
                    }
                ],
                "unassigned_evidence": [],
            },
            {
                "actions": [
                    {"id": "A1", "decision": "keep", "actor_anchor": "the actor"},
                    {"id": "A2", "decision": "keep", "actor_anchor": "the actor"},
                ]
            },
            {"relations": []},
        ]
    )
    monkeypatch.setattr(
        DeepSeekAttackFlowExtractor,
        "_request_json",
        lambda self, prompt, **kwargs: next(responses),
    )
    extractor = DeepSeekAttackFlowExtractor(
        base_url="https://example.invalid",
        api_key="test",
        model="generic-test-model",
    )

    result = extract_attack_flow_candidates(
        extractor,
        {"sha256": "6" * 64, "title": "generic access marketplace report"},
        source,
    )

    assert result.candidates[0].relations == []
    assert result.candidates[0].mainline == []


def test_scope_review_excludes_commercial_actions_before_relation(
    monkeypatch,
) -> None:
    source = "\n".join(
        [
            "The actor offered a hosting discount.",
            "The actor then advertised the service on a forum.",
        ]
    )
    responses = iter(
        [
            {
                "activities": [
                    {
                        "title": "Hosting promotion",
                        "actor_anchor": "the actor",
                        "start_line": 1,
                        "end_line": 2,
                    }
                ]
            },
            {"variants": [], "shared_successor_evidence": []},
            {
                "candidates": [
                    {
                        "title": "Hosting promotion",
                        "description": "",
                        "actions": [
                            action(
                                "A1",
                                "Offer hosting discount",
                                "The actor offered a hosting discount.",
                                scope="attack",
                            ),
                            action(
                                "A2",
                                "Advertise hosting service",
                                "The actor then advertised the service on a forum.",
                                scope="attack",
                            ),
                        ],
                        "relations": [],
                        "reported_actors": [],
                    }
                ],
                "unassigned_evidence": [],
            },
            {
                "actions": [
                    {
                        "id": "A1",
                        "decision": "exclude",
                        "actor_anchor": "the actor",
                        "reason_category": "commercial-operation",
                    },
                    {
                        "id": "A2",
                        "decision": "exclude",
                        "actor_anchor": "the actor",
                        "reason_category": "promotion",
                    },
                ]
            },
        ]
    )
    monkeypatch.setattr(
        DeepSeekAttackFlowExtractor,
        "_request_json",
        lambda self, prompt, **kwargs: next(responses),
    )
    extractor = DeepSeekAttackFlowExtractor(
        base_url="https://example.invalid",
        api_key="test",
        model="generic-test-model",
    )

    result = extract_attack_flow_candidates(
        extractor,
        {"sha256": "5" * 64, "title": "generic hosting marketplace report"},
        source,
    )

    assert result.candidates == []
    assert sum(
        item["reason"] == "action-outside-cyber-operation"
        for item in result.audit["rejected_facts"]
    ) == 2


def test_concise_english_action_accepts_common_verb_inflections() -> None:
    assert _is_concise_action_name("Drops files for DLL sideloading")
    assert _is_concise_action_name("Executes legitimate binary")
    assert _is_concise_action_name("Decrypts PlugX configuration")
    assert _is_concise_action_name("Connects to C2 servers")
    assert _is_concise_action_name(
        "Communicate with C2 and receive second-stage payload"
    )
    assert _is_concise_action_name("Perform anti-analysis checks")
    assert not _is_concise_action_name(
        "Communicate with the remote command and control server and receive payload"
    )
    assert _normalize_action_name("payload execution") == "Execute payload"
    assert _normalize_action_name("C2 communication") == "Communicate with C2"


def test_annoctr_acceptance_set_is_fixed_and_covers_required_scenarios() -> None:
    manifest = json.loads(
        (
            REPOSITORY_ROOT
            / "data"
            / "corpus"
            / "attack_flow_extraction_acceptance.json"
        ).read_text(encoding="utf-8")
    )
    scenarios = {
        scenario
        for case in manifest["cases"]
        for scenario in case["scenarios"]
    }
    assert {
        "no-flow",
        "multiple-activities",
        "branch",
        "merge",
        "conflicting-attribution",
        "missing-relation-evidence",
        "optional-attack",
    } <= scenarios
    assert manifest["source_policy"]["forbidden_inputs"]
    assert len({case["id"] for case in manifest["cases"]}) == len(
        manifest["cases"]
    )
    for case in manifest["cases"]:
        assert case["artifact_path"].startswith("data/corpus/artifacts/")
        assert len(case["sha256"]) == 64
        assert case["cardinality"]["minimum"] <= case["cardinality"]["maximum"]
