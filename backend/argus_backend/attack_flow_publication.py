from __future__ import annotations

from hashlib import sha256
import json
from uuid import uuid4

from .entity_resolution import alias_key, canonicalize_observation
from .models import (
    AttackFlow,
    AttackFlowDraft,
    AttackFlowMergeReview,
    SourceDocument,
    SourceSpan,
)
from .repository import SqliteRepository


ALLOWED_RELATIONS = {
    "precedes",
    "leads_to",
    "enables",
    "causes",
    "on_success",
    "on_failure",
}


class AttackFlowPublicationService:
    def __init__(self, repository: SqliteRepository) -> None:
        self.repository = repository

    def stage(
        self,
        source_document_id: str,
        candidate: AttackFlowDraft,
        merge_review: AttackFlowMergeReview | None = None,
        extraction_audit: dict | None = None,
    ) -> dict:
        source = self.repository.load_source(source_document_id)
        if source is None:
            raise LookupError(f"Unknown source document: {source_document_id}")
        ingestion_id = f"KING-{uuid4().hex[:16]}"
        flow_id = f"PATH-PUB-{uuid4().hex[:12].upper()}"
        result = self._build_result(
            ingestion_id,
            flow_id,
            source,
            candidate,
            merge_review,
        )
        if extraction_audit is not None:
            result["extraction_audit"] = extraction_audit
        self.repository.save_knowledge_ingestion(
            ingestion_id,
            source_document_id,
            json.dumps(result, ensure_ascii=False),
        )
        return result

    def stage_no_flow(self, source_document_id: str, extraction_audit: dict) -> dict:
        source = self.repository.load_source(source_document_id)
        if source is None:
            raise LookupError(f"Unknown source document: {source_document_id}")
        document, _, _ = source
        ingestion_id = f"KING-{uuid4().hex[:16]}"
        result = {
            "id": ingestion_id,
            "ingestion_kind": "attack-flow-no-flow",
            "source_document_id": source_document_id,
            "status": "staged",
            "publishable": False,
            "graph_write_performed": False,
            "extraction_audit": extraction_audit,
            "quality_gates": [
                {
                    "id": "source-integrity",
                    "label": "来源完整性",
                    "status": "pass",
                    "detail": f"原文 SHA-256 已固定：{document.sha256[:16]}…",
                },
                {
                    "id": "attack-flow-cardinality",
                    "label": "AttackFlow 候选数",
                    "status": "pass",
                    "detail": "抽取结果为 0；不会为了生成图而补造攻击步骤。",
                },
            ],
            "delta": {
                "create_entities": 0,
                "merge_entities": 0,
                "create_relationships": 0,
                "reinforce_relationships": 0,
            },
            "canonical_delta": {
                "create_entities": 0,
                "merge_entities": 0,
                "mentions": 0,
            },
            "entities": [],
            "canonical_entities": [],
            "relations": [],
            "document_scope": {
                "scope": "no-attack-flow",
                "attack_path_eligible": False,
                "reason": "未抽取到符合现有数据规范的攻击活动候选。",
            },
            "path_outcome": {
                "status": "no-path",
                "path_count": 0,
                "review_path_count": 0,
                "entity_evidence_count": 0,
                "usable_as": "source-only",
                "no_path_reason": "no-attack-flow",
                "detail": "来源已归档，但未生成 AttackFlow 候选。",
            },
            "event_graph_extraction": None,
            "path_delta": None,
            "flow_candidate_summary": {
                "status": "no-flow",
                "candidate_count": 0,
                "recommendation": "no-flow",
                "merge_target_flow_id": None,
                "reason": "来源没有形成通过原文与数据规范校验的攻击活动候选。",
            },
            "version": None,
        }
        self.repository.save_knowledge_ingestion(
            ingestion_id,
            source_document_id,
            json.dumps(result, ensure_ascii=False),
        )
        return result

    def revise(
        self,
        ingestion_id: str,
        candidate: AttackFlowDraft,
        merge_review: AttackFlowMergeReview | None = None,
    ) -> dict:
        current = self.get(ingestion_id)
        if current.get("ingestion_kind") != "attack-flow":
            raise ValueError("该入库任务不是 AttackFlow 候选")
        if current["status"] != "staged":
            raise ValueError("只有待复核的 AttackFlow 候选可以修订")
        source = self.repository.load_source(current["source_document_id"])
        if source is None:
            raise LookupError(
                f"Unknown source document: {current['source_document_id']}"
            )
        result = self._build_result(
            ingestion_id,
            current["attack_flow_preview"]["flow_id"],
            source,
            candidate,
            merge_review
            or (
                AttackFlowMergeReview.model_validate(current["merge_review"])
                if current.get("merge_review")
                else None
            ),
        )
        self.repository.update_knowledge_ingestion(
            ingestion_id,
            json.dumps(result, ensure_ascii=False),
        )
        return result

    def get(self, ingestion_id: str) -> dict:
        result_json = self.repository.find_knowledge_ingestion(ingestion_id)
        if result_json is None:
            raise LookupError(f"Unknown knowledge ingestion: {ingestion_id}")
        return json.loads(result_json)

    def publish(self, ingestion_id: str) -> dict:
        current = self.get(ingestion_id)
        if current.get("ingestion_kind") != "attack-flow":
            raise ValueError("该入库任务不是 AttackFlow 候选")
        if current["status"] == "published":
            return current
        if current["status"] != "staged":
            raise ValueError("该 AttackFlow 候选已不处于待发布状态")
        source = self.repository.load_source(current["source_document_id"])
        if source is None:
            raise LookupError(
                f"Unknown source document: {current['source_document_id']}"
            )
        candidate = AttackFlowDraft.model_validate(
            current["attack_flow_candidate"]
        )
        verified = self._build_result(
            ingestion_id,
            current["attack_flow_preview"]["flow_id"],
            source,
            candidate,
            (
                AttackFlowMergeReview.model_validate(current["merge_review"])
                if current.get("merge_review")
                else None
            ),
        )
        if not verified["publishable"]:
            self.repository.update_knowledge_ingestion(
                ingestion_id,
                json.dumps(verified, ensure_ascii=False),
            )
            raise ValueError("AttackFlow 候选存在阻断项，不能发布到历史图谱")
        publisher = (
            self.repository.publish_attack_flow_support
            if verified["publish_mode"] == "merge"
            else self.repository.publish_attack_flow_ingestion
        )
        return publisher(
            ingestion_id,
            f"KVER-{uuid4().hex[:16]}",
            verified,
            source[0],
        )

    def reject(self, ingestion_id: str) -> dict:
        current = self.get(ingestion_id)
        if current.get("ingestion_kind") != "attack-flow":
            raise ValueError("该入库任务不是 AttackFlow 候选")
        if current["status"] == "rejected":
            return current
        if current["status"] != "staged":
            raise ValueError("只有待复核的 AttackFlow 候选可以拒绝")
        rejected = {**current, "status": "rejected", "publishable": False}
        self.repository.reject_knowledge_ingestion(
            ingestion_id,
            json.dumps(rejected, ensure_ascii=False),
        )
        return rejected

    def _build_result(
        self,
        ingestion_id: str,
        flow_id: str,
        source: tuple[SourceDocument, str, list[SourceSpan]],
        candidate: AttackFlowDraft,
        merge_review: AttackFlowMergeReview | None = None,
    ) -> dict:
        document, content, spans = source
        entities, aliases = self.repository.load_entity_identity_index()
        action_ids = {
            action.id: f"{flow_id}-A{index:03d}"
            for index, action in enumerate(candidate.actions, start=1)
        }
        evidence_errors: list[str] = []
        relation_errors: list[str] = []
        mainline_errors: list[str] = []
        context_errors: list[str] = []

        def evidence_for(owner_id: str, items: list) -> list[dict]:
            if not items:
                evidence_errors.append(f"{owner_id} 缺少来源证据")
                return []
            resolved: list[dict] = []
            for index, item in enumerate(items, start=1):
                evidence = self._resolve_evidence(
                    owner_id,
                    index,
                    item.quote,
                    document,
                    content,
                    spans,
                )
                if evidence is None:
                    evidence_errors.append(
                        f"{owner_id} 的引文无法在归档原文中定位：{item.quote}"
                    )
                    continue
                resolved.append(evidence)
            return resolved

        preview_actions: list[dict] = []
        for action_index, action in enumerate(candidate.actions, start=1):
            global_action_id = action_ids[action.id]
            contexts: list[dict] = []
            for context_index, context in enumerate(action.contexts, start=1):
                context_id = f"{flow_id}-C{action_index:03d}-{context_index:03d}"
                resolution = self._resolve_context(
                    context.type,
                    context.name,
                    entities,
                    aliases,
                )
                if resolution["status"] == "review":
                    context_errors.append(
                        f"{context.id} 无法确定性映射到规范实体"
                    )
                contexts.append(
                    {
                        "id": context_id,
                        "local_id": context.id,
                        "type": context.type,
                        "name": context.name,
                        "role": context.role,
                        "direction": "action-to-entity",
                        "confidence": context.confidence,
                        "resolution": resolution,
                        "evidence": evidence_for(context_id, context.evidence),
                    }
                )
            techniques: list[dict] = []
            for technique_id in dict.fromkeys(action.technique_ids):
                resolution = self._resolve_context(
                    "other",
                    technique_id,
                    entities,
                    aliases,
                    kind_override="attack",
                )
                if resolution["status"] == "review":
                    context_errors.append(
                        f"{technique_id} 不是有效的 ATT&CK 技术编号"
                    )
                techniques.append(
                    {
                        "technique_id": technique_id,
                        "resolution": resolution,
                    }
                )
            preview_actions.append(
                {
                    "id": global_action_id,
                    "local_id": action.id,
                    "name": action.name,
                    "description": action.description,
                    "phase": action.phase,
                    "confidence": action.confidence,
                    "technique_ids": list(dict.fromkeys(action.technique_ids)),
                    "techniques": techniques,
                    "contexts": contexts,
                    "evidence": evidence_for(global_action_id, action.evidence),
                }
            )

        if len(action_ids) != len(candidate.actions):
            relation_errors.append("Action id 必须唯一")
        preview_relations: list[dict] = []
        relation_pairs: set[tuple[str, str]] = set()
        relation_local_ids: set[str] = set()
        for index, relation in enumerate(candidate.relations, start=1):
            relation_id = f"{flow_id}-R{index:03d}"
            if relation.id in relation_local_ids:
                relation_errors.append(f"Relation id 重复：{relation.id}")
            relation_local_ids.add(relation.id)
            if relation.type not in ALLOWED_RELATIONS:
                relation_errors.append(f"不支持的关系类型：{relation.type}")
            if relation.source_action_id not in action_ids:
                relation_errors.append(
                    f"关系 {relation.id} 的起点不属于当前 Flow"
                )
            if relation.target_action_id not in action_ids:
                relation_errors.append(
                    f"关系 {relation.id} 的终点不属于当前 Flow"
                )
            if (
                relation.source_action_id in action_ids
                and relation.target_action_id in action_ids
            ):
                relation_pairs.add(
                    (relation.source_action_id, relation.target_action_id)
                )
            preview_relations.append(
                {
                    "id": relation_id,
                    "local_id": relation.id,
                    "source_action_id": action_ids.get(
                        relation.source_action_id, relation.source_action_id
                    ),
                    "target_action_id": action_ids.get(
                        relation.target_action_id, relation.target_action_id
                    ),
                    "type": relation.type,
                    "condition": relation.condition,
                    "confidence": relation.confidence,
                    "evidence": evidence_for(relation_id, relation.evidence),
                }
            )

        if not candidate.mainline:
            mainline_errors.append("主干不能为空")
        if len(set(candidate.mainline)) != len(candidate.mainline):
            mainline_errors.append("主干不能重复引用同一 Action")
        unknown_mainline = [
            action_id for action_id in candidate.mainline if action_id not in action_ids
        ]
        if unknown_mainline:
            mainline_errors.append("主干引用了当前 Flow 之外的 Action")
        for source_id, target_id in zip(candidate.mainline, candidate.mainline[1:]):
            if (source_id, target_id) not in relation_pairs:
                mainline_errors.append(
                    f"主干 {source_id} → {target_id} 之间缺少直接关系"
                )

        preview_actors: list[dict] = []
        actor_local_ids: set[str] = set()
        for index, claim in enumerate(candidate.reported_actors, start=1):
            claim_id = f"{flow_id}-ACTOR{index:03d}"
            if claim.id in actor_local_ids:
                relation_errors.append(f"Reported Actor id 重复：{claim.id}")
            actor_local_ids.add(claim.id)
            preview_actors.append(
                {
                    "id": claim_id,
                    "local_id": claim.id,
                    "reported_name": claim.reported_name,
                    "actor_id": self._resolve_actor(
                        claim.reported_name, entities, aliases
                    ),
                    "confidence": claim.confidence,
                    "evidence": evidence_for(claim_id, claim.evidence),
                }
            )

        preview = {
            "flow_id": flow_id,
            "title": candidate.title,
            "description": candidate.description,
            "source": document.model_dump(),
            "actions": preview_actions,
            "relations": preview_relations,
            "mainline": [action_ids.get(item, item) for item in candidate.mainline],
            "reported_actors": preview_actors,
        }
        preview["candidate_fingerprint"] = self._candidate_fingerprint(preview)
        suggested_flow, suggested_action_map = self._suggest_merge(preview)
        merge_errors = self._validate_merge_review(preview, merge_review)
        if merge_review is not None:
            recommendation = "merge"
            merge_target_flow_id = merge_review.target_flow_id
            recommendation_reason = (
                "已显式复核目标 Flow、行为映射、强 Context 锚点和关系结构。"
                if not merge_errors
                else "显式合并决定未通过保守校验。"
            )
        elif suggested_flow is not None:
            recommendation = "merge"
            merge_target_flow_id = suggested_flow.id
            recommendation_reason = (
                "共享强 Context 身份锚点且行为与关系结构兼容，建议人工确认合并。"
            )
        else:
            recommendation = "create"
            merge_target_flow_id = None
            recommendation_reason = "未发现同时满足强身份锚点和兼容结构的现有 Flow。"

        gates = [
            self._gate("flow-evidence", "来源证据", evidence_errors),
            self._gate("flow-relations", "关系合法性", relation_errors),
            self._gate("flow-mainline", "主干完整性", mainline_errors),
            self._gate("flow-context", "规范实体映射", context_errors),
            self._gate("flow-merge", "Flow 合并复核", merge_errors),
        ]
        return {
            "id": ingestion_id,
            "ingestion_kind": "attack-flow",
            "source_document_id": document.id,
            "status": "staged",
            "publishable": all(gate["status"] != "block" for gate in gates),
            "graph_write_performed": False,
            "extraction_audit": {
                "method": "analyst-reviewed-candidate",
                "model": None,
                "cache_hit": False,
                "review_state": "reviewed",
                "warnings": [],
                "observations": [],
            },
            "quality_gates": gates,
            "delta": {
                "create_entities": sum(
                    context["resolution"]["status"] == "create"
                    for action in preview_actions
                    for context in [*action["contexts"], *action["techniques"]]
                ),
                "merge_entities": sum(
                    context["resolution"]["status"] == "reuse"
                    for action in preview_actions
                    for context in [*action["contexts"], *action["techniques"]]
                ),
                "create_relationships": len(preview_relations),
                "reinforce_relationships": 0,
            },
            "canonical_delta": {
                "create_entities": 0,
                "merge_entities": 0,
                "mentions": 0,
            },
            "entities": [],
            "canonical_entities": [],
            "relations": [],
            "document_scope": {
                "scope": "attack-lifecycle-candidate",
                "attack_path_eligible": True,
                "reason": "人工复核的 AttackFlow 发布候选。",
            },
            "path_outcome": {
                "status": "extracted",
                "path_count": 1,
                "review_path_count": 0,
                "entity_evidence_count": 0,
                "usable_as": "paths-and-entities",
                "no_path_reason": None,
                "detail": "形成 1 条待发布的人工复核攻击流。",
            },
            "event_graph_extraction": None,
            "path_delta": None,
            "publish_mode": "merge" if merge_review is not None else "create",
            "merge_review": (
                merge_review.model_dump() if merge_review is not None else None
            ),
            "flow_candidate_summary": {
                "status": "single",
                "candidate_count": 1,
                "recommendation": recommendation,
                "merge_target_flow_id": merge_target_flow_id,
                "suggested_action_map": suggested_action_map,
                "reason": recommendation_reason,
            },
            "attack_flow_candidate": candidate.model_dump(),
            "attack_flow_preview": preview,
            "version": None,
        }

    def _suggest_merge(
        self, preview: dict
    ) -> tuple[AttackFlow | None, dict[str, str]]:
        for flow in self.repository.list_attack_flows():
            target_by_name: dict[str, list[str]] = {}
            for action in flow.actions:
                target_by_name.setdefault(
                    self._normalized_name(action.name), []
                ).append(action.id)
            action_map: dict[str, str] = {}
            for action in preview["actions"]:
                matches = target_by_name.get(
                    self._normalized_name(action["name"]), []
                )
                if len(matches) != 1:
                    action_map = {}
                    break
                action_map[action["local_id"]] = matches[0]
            review = AttackFlowMergeReview(
                target_flow_id=flow.id,
                confirmed=True,
                action_map=action_map,
            )
            if action_map and not self._validate_merge_review(preview, review):
                return flow, action_map
        return None, {}

    def _validate_merge_review(
        self,
        preview: dict,
        merge_review: AttackFlowMergeReview | None,
    ) -> list[str]:
        if merge_review is None:
            return []
        target = self.repository.find_attack_flow(merge_review.target_flow_id)
        if target is None:
            return ["合并目标 Flow 不存在"]
        candidate_context_ids = {
            context["resolution"].get("entity_id")
            for action in preview["actions"]
            for context in action["contexts"]
            if context["type"]
            in {
                "ip",
                "domain",
                "url",
                "hash",
                "infrastructure",
                "vulnerability",
                "malware",
                "tool",
            }
            and context["resolution"]["status"] != "review"
        }
        target_context_ids = {
            context.entity_id
            for action in target.actions
            for context in action.contexts
        }
        if not candidate_context_ids.intersection(target_context_ids):
            return [
                "Actor 或 ATT&CK 相同不足以合并；必须共享强 Context 身份锚点"
            ]
        errors: list[str] = []
        if not merge_review.confirmed:
            errors.append("合并必须由复核人员显式确认")
        local_action_ids = {
            action["local_id"] for action in preview["actions"]
        }
        if set(merge_review.action_map) != local_action_ids:
            errors.append("合并行为映射必须覆盖候选中的全部 Action")
            return errors
        target_action_by_id = {action.id: action for action in target.actions}
        mapped_ids = list(merge_review.action_map.values())
        if len(set(mapped_ids)) != len(mapped_ids) or any(
            action_id not in target_action_by_id for action_id in mapped_ids
        ):
            errors.append("合并行为映射包含重复或 Flow 外 Action")
            return errors
        for action in preview["actions"]:
            target_action = target_action_by_id[
                merge_review.action_map[action["local_id"]]
            ]
            if self._normalized_name(action["name"]) != self._normalized_name(
                target_action.name
            ):
                errors.append(f"行为名称不兼容：{action['name']}")
        target_relations = {
            (relation.source_action_id, relation.target_action_id, relation.type)
            for relation in target.relations
        }
        global_to_local = {
            action["id"]: action["local_id"] for action in preview["actions"]
        }
        for relation in preview["relations"]:
            source_local = global_to_local.get(relation["source_action_id"])
            target_local = global_to_local.get(relation["target_action_id"])
            if not source_local or not target_local:
                continue
            mapped = (
                merge_review.action_map[source_local],
                merge_review.action_map[target_local],
                relation["type"],
            )
            if mapped not in target_relations:
                errors.append(f"关系结构不兼容：{relation['local_id']}")
        target_positions = {
            action_id: index for index, action_id in enumerate(target.mainline)
        }
        mapped_mainline = [
            merge_review.action_map[global_to_local[action_id]]
            for action_id in preview["mainline"]
            if action_id in global_to_local
        ]
        positions = [target_positions.get(action_id, -1) for action_id in mapped_mainline]
        if any(position < 0 for position in positions) or positions != sorted(
            set(positions)
        ):
            errors.append("候选主干与目标 Flow 的主干顺序不兼容")
        return errors

    @classmethod
    def _candidate_fingerprint(cls, preview: dict) -> str:
        action_index = {
            action["id"]: index for index, action in enumerate(preview["actions"])
        }
        shape = {
            "actions": [
                {
                    "name": cls._normalized_name(action["name"]),
                    "phase": cls._normalized_name(action["phase"]),
                    "contexts": sorted(
                        (
                            str(context["resolution"].get("canonical_key")),
                            context["role"],
                        )
                        for context in action["contexts"]
                    ),
                    "techniques": sorted(action["technique_ids"]),
                }
                for action in preview["actions"]
            ],
            "relations": sorted(
                (
                    action_index.get(relation["source_action_id"], -1),
                    action_index.get(relation["target_action_id"], -1),
                    relation["type"],
                )
                for relation in preview["relations"]
            ),
            "mainline": [action_index.get(item, -1) for item in preview["mainline"]],
            "reported_actors": sorted(
                cls._normalized_name(actor["reported_name"])
                for actor in preview["reported_actors"]
            ),
        }
        return sha256(
            json.dumps(shape, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _normalized_name(value: str) -> str:
        return "".join(value.casefold().split())

    @staticmethod
    def _resolve_evidence(
        owner_id: str,
        index: int,
        quote: str,
        document: SourceDocument,
        content: str,
        spans: list[SourceSpan],
    ) -> dict | None:
        if quote not in content:
            return None
        span = next((item for item in spans if quote in item.text), None)
        if span is None:
            return None
        digest = sha256(
            f"{owner_id}\0{span.id}\0{quote}\0{index}".encode("utf-8")
        ).hexdigest()[:20]
        return {
            "id": f"EVD-PUB-{digest}",
            "source_span_id": span.id,
            "source_id": document.id,
            "title": document.title,
            "publisher": document.publisher,
            "canonical_url": document.canonical_url,
            "locator": span.locator,
            "quote": quote,
            "confidence": 0.95,
        }

    @staticmethod
    def _resolve_context(
        context_type: str,
        name: str,
        entities: list[dict],
        aliases: list[dict],
        *,
        kind_override: str | None = None,
    ) -> dict:
        kind = kind_override or {
            "ip": "ioc",
            "domain": "ioc",
            "url": "ioc",
            "hash": "ioc",
            "infrastructure": "ioc",
            "vulnerability": "vulnerability",
            "malware": "malware",
            "tool": "tool",
        }.get(context_type, context_type)
        canonical = canonicalize_observation(name, kind)
        by_id = {str(entity["id"]): entity for entity in entities}
        candidates: dict[str, dict] = {}
        if canonical is not None:
            for entity in entities:
                if str(entity["canonical_key"]) == canonical.canonical_key:
                    candidates[str(entity["id"])] = entity
                elif (
                    str(entity["entity_type"]) == canonical.entity_type
                    and str(entity["normalized_value"]).casefold()
                    == canonical.canonical_value.casefold()
                ):
                    candidates[str(entity["id"])] = entity
            if canonical.value_type == "software-name":
                for item in aliases:
                    if str(item["alias_key"]) == alias_key(name):
                        entity = by_id.get(str(item["entity_id"]))
                        if entity is not None:
                            candidates[str(entity["id"])] = entity
        else:
            normalized = alias_key(name)
            for entity in entities:
                if alias_key(str(entity["label"])) == normalized:
                    candidates[str(entity["id"])] = entity
            for item in aliases:
                if str(item["alias_key"]) == normalized:
                    entity = by_id.get(str(item["entity_id"]))
                    if entity is not None:
                        candidates[str(entity["id"])] = entity
        if len(candidates) == 1:
            entity = next(iter(candidates.values()))
            return {
                "status": "reuse",
                "entity_id": str(entity["id"]),
                "canonical_key": str(entity["canonical_key"]),
                "entity_type": str(entity["entity_type"]),
                "value_type": (
                    canonical.value_type if canonical is not None else "named-entity"
                ),
                "normalized_value": str(entity["normalized_value"]),
                "label": str(entity["label"]),
            }
        if canonical is not None and canonical.auto_create:
            return {
                "status": "create",
                "entity_id": canonical.entity_id,
                "canonical_key": canonical.canonical_key,
                "entity_type": canonical.entity_type,
                "value_type": canonical.value_type,
                "normalized_value": canonical.canonical_value,
                "label": canonical.label,
            }
        return {
            "status": "review",
            "entity_id": None,
            "canonical_key": (
                canonical.canonical_key if canonical is not None else None
            ),
            "entity_type": (
                canonical.entity_type if canonical is not None else None
            ),
            "value_type": (
                canonical.value_type if canonical is not None else None
            ),
            "normalized_value": (
                canonical.canonical_value if canonical is not None else None
            ),
            "label": name,
        }

    @staticmethod
    def _resolve_actor(
        reported_name: str,
        entities: list[dict],
        aliases: list[dict],
    ) -> str | None:
        normalized = alias_key(reported_name)
        matches = {
            str(entity["id"])
            for entity in entities
            if entity["entity_type"] == "攻击组织"
            and alias_key(str(entity["label"])) == normalized
        }
        entity_types = {
            str(entity["id"]): str(entity["entity_type"]) for entity in entities
        }
        matches.update(
            str(item["entity_id"])
            for item in aliases
            if str(item["alias_key"]) == normalized
            and entity_types.get(str(item["entity_id"])) == "攻击组织"
        )
        return next(iter(matches)) if len(matches) == 1 else None

    @staticmethod
    def _gate(gate_id: str, title: str, errors: list[str]) -> dict:
        return {
            "id": gate_id,
            "label": title,
            "status": "block" if errors else "pass",
            "detail": "；".join(dict.fromkeys(errors)) if errors else "通过",
        }
