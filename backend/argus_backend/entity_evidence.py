from collections import defaultdict
from hashlib import sha256
import json
import re
from uuid import uuid4

from .entity_resolution import alias_key, canonicalize_observation
from .models import SourceSpan
from .repository import SqliteRepository


STRONG_IOC_PATTERN = re.compile(
    r"(?P<cve>\bCVE[-_\s]\d{4}[-_\s]\d{4,}\b)|"
    r"(?P<url>\b(?:https?|hxxps?)://[^\s\"'<>]+)|"
    r"(?P<hash>\b[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8})?"
    r"(?:[a-fA-F0-9]{24})?\b)|"
    r"(?P<ipv4>\b(?:\d{1,3}\.){3}\d{1,3}\b)|"
    r"(?P<domain>\b(?:[a-zA-Z0-9-]+(?:\.|\[\.\]))+"
    r"[a-zA-Z]{2,63}\b)"
)
NON_INDICATOR_FILE_SUFFIXES = {
    "bat", "cab", "cmd", "data", "dll", "doc", "docm", "docx",
    "exe", "hta", "htm", "html", "jar", "jpeg", "jpg", "js",
    "json", "lnk", "pdf", "png", "ps1", "sct", "sys", "txt",
    "vbs", "xls", "xlsm", "xlsx", "zip",
}


class EntityEvidenceIngestionService:
    def __init__(self, repository: SqliteRepository) -> None:
        self.repository = repository

    def stage(self, source_document_id: str) -> dict:
        source = self.repository.load_source(source_document_id)
        if source is None:
            raise LookupError(f"Unknown source document: {source_document_id}")
        document, _, spans = source
        observations = self._extract_observations(spans)
        entities, aliases = self.repository.load_entity_identity_index()
        canonical_entities = self._resolve_canonical_entities(
            observations,
            entities,
            aliases,
        )
        ingestion_id = f"KING-{uuid4().hex[:16]}"
        publishable = bool(canonical_entities)
        result = {
            "id": ingestion_id,
            "ingestion_kind": "entity-evidence",
            "source_document_id": source_document_id,
            "status": "staged",
            "publishable": publishable,
            "graph_write_performed": False,
            "extraction_audit": {
                "method": "deterministic-entity-evidence/1.0",
                "model": None,
                "cache_hit": False,
                "review_state": "system-verified",
                "warnings": [],
                "observations": observations,
            },
            "quality_gates": [
                {
                    "id": "source-integrity",
                    "label": "来源完整性",
                    "status": "pass",
                    "detail": f"原文 SHA-256 已固定：{document.sha256[:16]}…",
                },
                {
                    "id": "entity-evidence",
                    "label": "实体证据",
                    "status": "pass" if publishable else "block",
                    "detail": (
                        f"{len(canonical_entities)} 个强类型实体可回到原文引文。"
                        if publishable
                        else "未发现可确定性规范化的 IOC 或漏洞。"
                    ),
                },
                {
                    "id": "attack-flow-cardinality",
                    "label": "AttackFlow 候选数",
                    "status": "pass",
                    "detail": "候选数为 0；仅保留实体证据，不补造攻击步骤。",
                },
            ],
            "delta": {
                "create_entities": 0,
                "merge_entities": 0,
                "create_relationships": 0,
                "reinforce_relationships": 0,
            },
            "canonical_delta": {
                "create_entities": sum(
                    item["decision"] == "create" for item in canonical_entities
                ),
                "merge_entities": sum(
                    item["decision"] == "merge" for item in canonical_entities
                ),
                "mentions": sum(
                    len(item["source_span_ids"]) for item in canonical_entities
                ),
            },
            "entities": [],
            "canonical_entities": canonical_entities,
            "relations": [],
            "document_scope": {
                "scope": "entity-evidence",
                "attack_path_eligible": False,
                "reason": "未形成有证据的 AttackFlow，仅发布独立实体证据。",
            },
            "path_outcome": {
                "status": "no-path",
                "path_count": 0,
                "review_path_count": 0,
                "entity_evidence_count": len(canonical_entities),
                "usable_as": "entity-evidence" if publishable else "source-only",
                "no_path_reason": "no-attack-flow",
                "detail": "来源不生成攻击路径。",
            },
            "event_graph_extraction": None,
            "path_delta": None,
            "flow_candidate_summary": {
                "status": "no-flow",
                "candidate_count": 0,
                "recommendation": "no-flow",
                "merge_target_flow_id": None,
                "reason": "来源没有形成可发布的攻击活动候选。",
            },
            "version": None,
        }
        self.repository.save_knowledge_ingestion(
            ingestion_id,
            source_document_id,
            json.dumps(result, ensure_ascii=False),
        )
        return result

    def publish(self, ingestion_id: str) -> dict:
        result = self.get(ingestion_id)
        if result["status"] == "published":
            return result
        if result.get("ingestion_kind") != "entity-evidence":
            raise ValueError("该入库任务不是实体证据任务")
        if not result["publishable"]:
            raise ValueError("没有可发布的实体证据")
        source = self.repository.load_source(result["source_document_id"])
        if source is None:
            raise LookupError(
                f"Unknown source document: {result['source_document_id']}"
            )
        document, content, _ = source
        return self.repository.publish_knowledge_ingestion(
            ingestion_id,
            f"KVER-{uuid4().hex[:16]}",
            result,
            document,
            content,
        )

    def get(self, ingestion_id: str) -> dict:
        result_json = self.repository.find_knowledge_ingestion(ingestion_id)
        if result_json is None:
            raise LookupError(f"Unknown knowledge ingestion: {ingestion_id}")
        return json.loads(result_json)

    def rollback(self, version_id: str) -> dict:
        result = self.repository.rollback_knowledge_version(version_id)
        if result is None:
            raise LookupError(f"Unknown knowledge version: {version_id}")
        return result

    @staticmethod
    def _extract_observations(spans: list[SourceSpan]) -> list[dict]:
        observations: list[dict] = []
        seen: set[str] = set()
        for span in spans:
            for match in STRONG_IOC_PATTERN.finditer(span.text):
                value = match.group(0).rstrip(".,;:")
                if not EntityEvidenceIngestionService._is_indicator(
                    match.lastgroup or "", value
                ):
                    continue
                kind = "vulnerability" if match.lastgroup == "cve" else "ioc"
                canonical = canonicalize_observation(value, kind)
                if canonical is None or canonical.canonical_key in seen:
                    continue
                seen.add(canonical.canonical_key)
                observations.append(
                    {
                        "value": value,
                        "kind": kind,
                        "confidence": 1.0,
                        "source_span_ids": [span.id],
                        "quote": value,
                    }
                )
        return observations

    @staticmethod
    def _is_indicator(match_kind: str, value: str) -> bool:
        if match_kind == "url":
            lowered = value.casefold()
            if lowered.startswith(("hxxp://", "hxxps://")) or "[.]" in value:
                return True
            canonical = canonicalize_observation(value, "ioc")
            return bool(
                canonical is not None
                and canonical.value_type == "url"
                and re.match(
                    r"^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)",
                    canonical.canonical_value,
                )
            )
        if match_kind == "domain":
            suffix = value.casefold().replace("[.]", ".").rsplit(".", 1)[-1]
            return suffix not in NON_INDICATOR_FILE_SUFFIXES and value.casefold() != "form.name"
        return True

    @staticmethod
    def _resolve_canonical_entities(
        observations: list[dict],
        knowledge_entities: list[dict],
        aliases: list[dict],
    ) -> list[dict]:
        by_canonical_key: dict[str, list[dict]] = defaultdict(list)
        by_type_and_value: dict[tuple[str, str], list[dict]] = defaultdict(list)
        entity_by_id = {entity["id"]: entity for entity in knowledge_entities}
        for entity in knowledge_entities:
            by_canonical_key[str(entity["canonical_key"])].append(entity)
            by_type_and_value[
                (
                    str(entity["entity_type"]),
                    str(entity["normalized_value"]).casefold(),
                )
            ].append(entity)
        by_alias: dict[str, list[dict]] = defaultdict(list)
        for row in aliases:
            target = entity_by_id.get(str(row["entity_id"]))
            if target is not None:
                by_alias[str(row["alias_key"])].append(target)

        staged_by_key: dict[str, dict] = {}
        for observation in observations:
            canonical = canonicalize_observation(
                str(observation["value"]), str(observation["kind"])
            )
            if canonical is None:
                continue
            candidates = [
                *by_canonical_key.get(canonical.canonical_key, []),
                *by_type_and_value.get(
                    (
                        canonical.entity_type,
                        canonical.canonical_value.casefold(),
                    ),
                    [],
                ),
            ]
            if canonical.value_type == "software-name":
                candidates.extend(by_alias.get(alias_key(canonical.label), []))
            ranked = sorted(
                {item["id"]: item for item in candidates}.values(),
                key=lambda item: (-int(item.get("source_count") or 0), str(item["id"])),
            )
            target = ranked[0] if ranked else None
            if target is None and not canonical.auto_create:
                continue
            existing = staged_by_key.get(canonical.canonical_key)
            if existing is None:
                staged_by_key[canonical.canonical_key] = {
                    "stage_id": f"KCEN-{len(staged_by_key) + 1:03d}",
                    "value": observation["value"],
                    "kind": observation["kind"],
                    "label": canonical.label,
                    "entity_type": canonical.entity_type,
                    "value_type": canonical.value_type,
                    "canonical_key": canonical.canonical_key,
                    "normalized_value": canonical.canonical_value,
                    "entity_id": str(target["id"]) if target else canonical.entity_id,
                    "confidence": observation["confidence"],
                    "decision": "merge" if target else "create",
                    "merge_target_id": str(target["id"]) if target else None,
                    "merge_target_label": str(target["label"]) if target else None,
                    "duplicate_candidate_ids": [
                        str(item["id"]) for item in ranked[1:]
                    ],
                    "source_span_ids": list(observation["source_span_ids"]),
                    "quotes": [observation["quote"]],
                    "original_values": [observation["value"]],
                }
                continue
            existing["source_span_ids"] = list(
                dict.fromkeys(
                    [*existing["source_span_ids"], *observation["source_span_ids"]]
                )
            )
            existing["quotes"] = list(
                dict.fromkeys([*existing["quotes"], observation["quote"]])
            )
        return list(staged_by_key.values())
