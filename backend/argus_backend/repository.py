from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3

from .models import (
    AttackFlow,
    AttackFlowAction,
    AttackFlowContext,
    AttackFlowEvidence,
    AttackFlowRelation,
    AttackFlowReportedActor,
    AttackFlowSource,
    ConfidenceLevel,
    FlowMatchRun,
    SourceDocument,
    SourceSpan,
)


SCHEMA = """
CREATE TABLE IF NOT EXISTS source_documents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    publisher TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    published_at TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    content TEXT NOT NULL,
    content_size INTEGER NOT NULL,
    review_state TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS source_spans (
    id TEXT PRIMARY KEY,
    source_document_id TEXT NOT NULL,
    locator TEXT NOT NULL,
    start_offset INTEGER NOT NULL,
    end_offset INTEGER NOT NULL,
    text TEXT NOT NULL,
    extraction_method TEXT NOT NULL,
    FOREIGN KEY (source_document_id) REFERENCES source_documents(id)
);

CREATE INDEX IF NOT EXISTS idx_source_spans_document
    ON source_spans(source_document_id, start_offset);

CREATE TABLE IF NOT EXISTS flow_match_runs (
    id TEXT PRIMARY KEY,
    query_text TEXT NOT NULL,
    normalized_inputs_json TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    knowledge_snapshot TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS curated_extraction_baselines (
    source_sha256 TEXT PRIMARY KEY,
    profile_name TEXT NOT NULL,
    observations_json TEXT NOT NULL,
    review_note TEXT NOT NULL,
    reviewed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge_ingestion_runs (
    id TEXT PRIMARY KEY,
    source_document_id TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL,
    version_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_document_id) REFERENCES source_documents(id)
);

CREATE TABLE IF NOT EXISTS knowledge_versions (
    id TEXT PRIMARY KEY,
    ingestion_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    changes_json TEXT NOT NULL,
    published_at TEXT NOT NULL,
    rolled_back_at TEXT,
    FOREIGN KEY (ingestion_id) REFERENCES knowledge_ingestion_runs(id)
);

CREATE TABLE IF NOT EXISTS entity_mentions (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    source_document_id TEXT NOT NULL,
    source_span_id TEXT NOT NULL,
    ingestion_id TEXT NOT NULL,
    original_value TEXT NOT NULL,
    canonical_value TEXT NOT NULL,
    value_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    FOREIGN KEY (source_document_id) REFERENCES source_documents(id),
    FOREIGN KEY (source_span_id) REFERENCES source_spans(id),
    FOREIGN KEY (ingestion_id) REFERENCES knowledge_ingestion_runs(id),
    UNIQUE(entity_id, source_span_id, original_value)
);

CREATE INDEX IF NOT EXISTS idx_entity_mentions_entity
    ON entity_mentions(entity_id, created_at);

CREATE INDEX IF NOT EXISTS idx_entity_mentions_source
    ON entity_mentions(source_document_id, source_span_id);

CREATE TABLE IF NOT EXISTS review_records (
    id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL CHECK(
        target_type IN (
            'source-artifact', 'source-span', 'activity-path',
            'path-node', 'path-edge', 'evidence-link'
        )
    ),
    target_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('accept', 'revise', 'reject')),
    reviewer_type TEXT NOT NULL CHECK(
        reviewer_type IN ('agent-assisted', 'human')
    ),
    reviewer_id TEXT NOT NULL,
    note TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    previous_state TEXT NOT NULL DEFAULT '',
    resulting_state TEXT NOT NULL,
    UNIQUE(target_type, target_id, reviewer_id, reviewed_at)
);

CREATE INDEX IF NOT EXISTS idx_review_records_target
    ON review_records(target_type, target_id, reviewed_at);

INSERT OR IGNORE INTO curated_extraction_baselines (
    source_sha256, profile_name, observations_json, review_note, reviewed_at
) VALUES (
    '794045a1f5fdb454066fd876afc9ac90336515ba04baa8d7546b0a43685183a3',
    'jaguar-tooth-partial-alert-v1',
    '[
      {
        "value": "CVE-2017-6742",
        "kind": "vulnerability",
        "confidence": 1.0,
        "locators": ["paragraph:1"],
        "quote": "CVE-2017-6742"
      },
      {
        "value": "Jaguar Tooth",
        "kind": "malware",
        "confidence": 1.0,
        "locators": ["paragraph:1"],
        "quote": "Jaguar Tooth"
      },
      {
        "value": "系统信息收集",
        "kind": "behavior",
        "confidence": 0.98,
        "locators": ["paragraph:1"],
        "quote": "通过 CLI 执行 show version、show interfaces 等系统信息收集命令"
      }
    ]',
    '赛前逐项复核：三个观测均可由同一告警段落直接定位；不将补全和预测步骤伪装为输入事实。',
    '2026-07-28T16:10:00+08:00'
);
"""


class SqliteRepository:
    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)

    def ensure_schema(self) -> None:
        with self._connect() as connection:
            connection.executescript(SCHEMA)

    def find_source_by_sha256(
        self, sha256: str
    ) -> tuple[SourceDocument, list[SourceSpan]] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, title, publisher, canonical_url, published_at,
                       mime_type, sha256, content_size, review_state
                FROM source_documents
                WHERE sha256 = ?
                """,
                (sha256,),
            ).fetchone()
            if row is None:
                return None
            return self._source_document(row), self._load_spans(connection, row["id"])

    def insert_source(
        self,
        document: SourceDocument,
        content: str,
        spans: Iterable[SourceSpan],
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO source_documents (
                    id, title, publisher, canonical_url, published_at, mime_type,
                    sha256, content, content_size, review_state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    document.id,
                    document.title,
                    document.publisher,
                    document.canonical_url,
                    document.published_at,
                    document.mime_type,
                    document.sha256,
                    content,
                    document.content_size,
                    document.review_state,
                ),
            )
            connection.executemany(
                """
                INSERT INTO source_spans (
                    id, source_document_id, locator, start_offset, end_offset,
                    text, extraction_method
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        span.id,
                        span.source_document_id,
                        span.locator,
                        span.start_offset,
                        span.end_offset,
                        span.text,
                        span.extraction_method,
                    )
                    for span in spans
                ),
            )

    def source_exists(self, source_document_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM source_documents WHERE id = ?",
                (source_document_id,),
            ).fetchone()
            return row is not None

    def find_attack_flow(self, flow_id: str) -> AttackFlow | None:
        with self._connect() as connection:
            flow_row = connection.execute(
                """
                SELECT id, name, description
                FROM activity_paths
                WHERE id = ?
                """,
                (flow_id,),
            ).fetchone()
            if flow_row is None:
                return None

            projection_row = connection.execute(
                """
                SELECT mainline_action_refs_json
                FROM analysis_projections
                WHERE path_id = ?
                ORDER BY generated_at DESC, id DESC
                LIMIT 1
                """,
                (flow_id,),
            ).fetchone()
            if projection_row is None:
                raise ValueError(f"AttackFlow has no explicit mainline: {flow_id}")
            mainline = self._json_value(
                projection_row["mainline_action_refs_json"], []
            )
            if not isinstance(mainline, list) or not all(
                isinstance(action_id, str) for action_id in mainline
            ):
                raise ValueError(f"AttackFlow has an invalid mainline: {flow_id}")

            action_rows = connection.execute(
                """
                SELECT id, label, phase, confidence, properties_json
                FROM activity_path_nodes
                WHERE path_id = ?
                ORDER BY sequence_hint, id
                """,
                (flow_id,),
            ).fetchall()
            relation_rows = connection.execute(
                """
                SELECT id, source_node_id, target_node_id,
                       COALESCE(v1_relation_type, edge_type) AS edge_type,
                       condition_label, confidence
                FROM activity_path_edges
                WHERE path_id = ?
                ORDER BY id
                """,
                (flow_id,),
            ).fetchall()
            evidence_rows = connection.execute(
                """
                SELECT pel.id, pel.source_span_id, pel.node_id, pel.edge_id,
                       pel.quote,
                       pel.confidence, ss.locator, ss.line_start,
                       COALESCE(sa.id, sd.id) AS source_id,
                       COALESCE(sa.title, sd.title, '') AS source_title,
                       COALESCE(sa.publisher, sd.publisher, '') AS publisher,
                       COALESCE(sa.canonical_url, sd.canonical_url, '')
                           AS canonical_url,
                       COALESCE(sa.published_at, sd.published_at, '')
                           AS published_at
                FROM path_evidence_links pel
                JOIN source_spans ss ON ss.id = pel.source_span_id
                LEFT JOIN source_artifacts sa ON sa.id = ss.artifact_id
                LEFT JOIN source_documents sd ON sd.id = ss.source_document_id
                WHERE pel.path_id = ?
                ORDER BY COALESCE(ss.line_start, 2147483647), pel.id
                """,
                (flow_id,),
            ).fetchall()
            context_rows = connection.execute(
                """
                SELECT acl.id, acl.action_node_id, acl.entity_id, acl.role,
                       acl.direction, acl.confidence, e.entity_type, e.label,
                       e.properties_json
                FROM action_context_links acl
                JOIN entities e ON e.id = acl.entity_id
                WHERE acl.path_id = ?
                ORDER BY acl.action_node_id, acl.id
                """,
                (flow_id,),
            ).fetchall()
            context_evidence_rows = connection.execute(
                """
                SELECT acel.id, acel.source_span_id, acel.context_link_id,
                       acel.quote,
                       acel.confidence, ss.locator, ss.line_start,
                       COALESCE(sa.id, sd.id) AS source_id,
                       COALESCE(sa.title, sd.title, '') AS source_title,
                       COALESCE(sa.publisher, sd.publisher, '') AS publisher,
                       COALESCE(sa.canonical_url, sd.canonical_url, '')
                           AS canonical_url,
                       COALESCE(sa.published_at, sd.published_at, '')
                           AS published_at
                FROM action_context_evidence_links acel
                JOIN action_context_links acl ON acl.id = acel.context_link_id
                JOIN source_spans ss ON ss.id = acel.source_span_id
                LEFT JOIN source_artifacts sa ON sa.id = ss.artifact_id
                LEFT JOIN source_documents sd ON sd.id = ss.source_document_id
                WHERE acl.path_id = ?
                ORDER BY COALESCE(ss.line_start, 2147483647), acel.id
                """,
                (flow_id,),
            ).fetchall()
            actor_rows = connection.execute(
                """
                SELECT id, reported_name, actor_id, confidence
                FROM reported_actor_claims
                WHERE path_id = ?
                ORDER BY id
                """,
                (flow_id,),
            ).fetchall()
            actor_evidence_rows = connection.execute(
                """
                SELECT rael.id, rael.source_span_id,
                       rael.actor_claim_id, rael.quote, rael.confidence,
                       ss.locator, ss.line_start,
                       COALESCE(sa.id, sd.id) AS source_id,
                       COALESCE(sa.title, sd.title, '') AS source_title,
                       COALESCE(sa.publisher, sd.publisher, '') AS publisher,
                       COALESCE(sa.canonical_url, sd.canonical_url, '')
                           AS canonical_url,
                       COALESCE(sa.published_at, sd.published_at, '')
                           AS published_at
                FROM reported_actor_evidence_links rael
                JOIN reported_actor_claims rac ON rac.id = rael.actor_claim_id
                JOIN source_spans ss ON ss.id = rael.source_span_id
                LEFT JOIN source_artifacts sa ON sa.id = ss.artifact_id
                LEFT JOIN source_documents sd ON sd.id = ss.source_document_id
                WHERE rac.path_id = ?
                ORDER BY COALESCE(ss.line_start, 2147483647), rael.id
                """,
                (flow_id,),
            ).fetchall()

            evidence_by_action: dict[str, list[AttackFlowEvidence]] = defaultdict(list)
            evidence_by_relation: dict[str, list[AttackFlowEvidence]] = defaultdict(list)
            context_evidence: dict[str, list[AttackFlowEvidence]] = defaultdict(list)
            actor_evidence: dict[str, list[AttackFlowEvidence]] = defaultdict(list)
            sources: dict[str, AttackFlowSource] = {}
            for row in [
                *evidence_rows,
                *context_evidence_rows,
                *actor_evidence_rows,
            ]:
                source_id = str(row["source_id"] or "")
                if source_id:
                    sources[source_id] = AttackFlowSource(
                        id=source_id,
                        title=str(row["source_title"]),
                        publisher=str(row["publisher"]),
                        canonical_url=str(row["canonical_url"]),
                        published_at=str(row["published_at"]),
                    )
            for row in evidence_rows:
                evidence = self._attack_flow_evidence(row)
                if row["node_id"]:
                    evidence_by_action[str(row["node_id"])].append(evidence)
                if row["edge_id"]:
                    evidence_by_relation[str(row["edge_id"])].append(evidence)
            for row in context_evidence_rows:
                context_evidence[str(row["context_link_id"])].append(
                    self._attack_flow_evidence(row)
                )
            for row in actor_evidence_rows:
                actor_evidence[str(row["actor_claim_id"])].append(
                    self._attack_flow_evidence(row)
                )

            contexts_by_action: dict[str, list[AttackFlowContext]] = defaultdict(list)
            techniques_by_action: dict[str, list[str]] = defaultdict(list)
            for row in context_rows:
                properties = self._json_value(row["properties_json"], {})
                if not isinstance(properties, dict):
                    properties = {}
                action_id = str(row["action_node_id"])
                if str(row["entity_type"]) == "ATT&CK 技术":
                    techniques_by_action[action_id].append(str(row["label"]))
                    continue
                contexts_by_action[action_id].append(
                    AttackFlowContext(
                        id=str(row["id"]),
                        entity_id=str(row["entity_id"]),
                        type=self._attack_flow_context_type(
                            str(row["entity_type"]), properties
                        ),
                        name=str(row["label"]),
                        role=self._attack_flow_context_role(str(row["role"])),
                        direction=str(row["direction"]),
                        confidence=self._confidence_level(float(row["confidence"])),
                        evidence=context_evidence[str(row["id"])],
                    )
                )

            actions: list[AttackFlowAction] = []
            for row in action_rows:
                properties = self._json_value(row["properties_json"], {})
                if not isinstance(properties, dict):
                    properties = {}
                action_id = str(row["id"])
                actions.append(
                    AttackFlowAction(
                        id=action_id,
                        name=str(row["label"]),
                        description=str(properties.get("description", "")),
                        phase=str(row["phase"]),
                        confidence=self._confidence_level(float(row["confidence"])),
                        technique_ids=techniques_by_action[action_id],
                        contexts=contexts_by_action[action_id],
                        evidence=evidence_by_action[action_id],
                    )
                )

            relations = [
                AttackFlowRelation(
                    id=str(row["id"]),
                    source_action_id=str(row["source_node_id"]),
                    target_action_id=str(row["target_node_id"]),
                    type=self._attack_flow_relation_type(str(row["edge_type"])),
                    condition=str(row["condition_label"] or "") or None,
                    confidence=self._confidence_level(float(row["confidence"])),
                    evidence=evidence_by_relation[str(row["id"])],
                )
                for row in relation_rows
            ]
            reported_actors = [
                AttackFlowReportedActor(
                    id=str(row["id"]),
                    reported_name=str(row["reported_name"]),
                    actor_id=(
                        str(row["actor_id"]) if row["actor_id"] else None
                    ),
                    confidence=self._confidence_level(float(row["confidence"])),
                    evidence=actor_evidence[str(row["id"])],
                )
                for row in actor_rows
            ]
            self._validate_attack_flow_evidence(
                actions,
                relations,
                reported_actors,
            )
            self._validate_attack_flow_mainline(flow_id, mainline, actions, relations)
            return AttackFlow(
                id=str(flow_row["id"]),
                title=str(flow_row["name"]),
                description=str(flow_row["description"]),
                sources=sorted(sources.values(), key=lambda source: source.id),
                reported_actors=reported_actors,
                actions=actions,
                relations=relations,
                mainline=mainline,
            )

    def list_attack_flows(self) -> list[AttackFlow]:
        with self._connect() as connection:
            flow_ids = [
                str(row["id"])
                for row in connection.execute(
                    "SELECT id FROM activity_paths ORDER BY id"
                ).fetchall()
            ]
        return [
            flow
            for flow_id in flow_ids
            if (flow := self.find_attack_flow(flow_id)) is not None
        ]

    def load_panoramic_graph_identity_context(self) -> dict:
        with self._connect() as connection:
            entity_rows = connection.execute(
                """
                SELECT id, entity_type, label, normalized_value, description
                FROM entities
                WHERE entity_type = '攻击组织'
                   OR id IN (SELECT entity_id FROM action_context_links)
                   OR id IN (
                       SELECT actor_id FROM reported_actor_claims
                       WHERE actor_id IS NOT NULL
                   )
                ORDER BY id
                """
            ).fetchall()
            flow_rows = connection.execute(
                "SELECT id, metadata_json FROM activity_paths ORDER BY id"
            ).fetchall()
            version_row = connection.execute(
                """
                SELECT id
                FROM knowledge_versions
                WHERE status = 'published'
                ORDER BY published_at DESC, id DESC
                LIMIT 1
                """
            ).fetchone()
        return {
            "entities": [dict(row) for row in entity_rows],
            "flows": {
                str(row["id"]): self._json_value(row["metadata_json"], {})
                for row in flow_rows
            },
            "knowledge_version": (
                str(version_row["id"]) if version_row else "retained-attack-flow-v1"
            ),
        }

    def load_runtime_catalog(self) -> dict:
        with self._connect() as connection:
            entity_rows = connection.execute(
                """
                SELECT id, entity_type, canonical_key, label, normalized_value,
                       description, first_seen, last_seen, source_count,
                       properties_json
                FROM entities
                ORDER BY source_count DESC, label, id
                """
            ).fetchall()
            alias_rows = connection.execute(
                """
                SELECT id, entity_id, alias, alias_type, source, confidence
                FROM aliases
                ORDER BY entity_id, confidence DESC, id
                """
            ).fetchall()
            report_rows = connection.execute(
                """
                SELECT id, title, source, report_date, classification,
                       language, original_filename, mime_type, size_bytes,
                       sha256, extracted_text, extraction_note, created_at,
                       source_ref, reliability, external_url, assessment
                FROM raw_reports
                ORDER BY report_date DESC, created_at DESC
                """
            ).fetchall()
            rule_rows = connection.execute(
                """
                SELECT id, match_entity_type, priority, action_template,
                       rationale, source_url, title, group_label, match_event
                FROM response_rules
                ORDER BY priority, id
                """
            ).fetchall()
            algorithm_rows = connection.execute(
                """
                SELECT id, algorithm_version, weights_json, description,
                       created_at
                FROM algorithm_configs
                ORDER BY created_at DESC, id
                """
            ).fetchall()
            counts = {
                "relationships": connection.execute(
                    "SELECT COUNT(*) FROM relationships"
                ).fetchone()[0],
                "evidence": connection.execute(
                    "SELECT COUNT(*) FROM evidence"
                ).fetchone()[0],
                "actors": connection.execute(
                    "SELECT COUNT(*) FROM actor_profiles"
                ).fetchone()[0],
                "corpus_artifacts": connection.execute(
                    "SELECT COUNT(*) FROM source_artifacts"
                ).fetchone()[0],
                "reviewed_paths": connection.execute(
                    "SELECT COUNT(*) FROM activity_paths"
                ).fetchone()[0],
            }
            version_row = connection.execute(
                """
                SELECT id, published_at
                FROM knowledge_versions
                WHERE status = 'published'
                ORDER BY published_at DESC, id DESC
                LIMIT 1
                """
            ).fetchone()

        entities = [self._export_entity(row) for row in entity_rows]
        reports = [dict(row) for row in report_rows]
        version_payload = "|".join(
            [
                str(len(entities)),
                str(len(reports)),
                str(counts["relationships"]),
                str(counts["evidence"]),
                str(version_row["id"] if version_row else ""),
            ]
        )
        return {
            "meta": {
                "source": str(self.database_path),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "version": (
                    str(version_row["id"])
                    if version_row
                    else f"catalog-{sha256(version_payload.encode()).hexdigest()[:16]}"
                ),
            },
            "stats": {
                "entities": len(entities),
                "relationships": int(counts["relationships"]),
                "evidence": int(counts["evidence"]),
                "reports": len(reports),
                "actors": int(counts["actors"]),
                "iocs": sum(
                    entity["entity_type"] == "IOC/基础设施"
                    for entity in entities
                ),
                "attack_steps": sum(
                    entity["entity_type"] == "攻击步骤"
                    for entity in entities
                ),
                "corpus_artifacts": int(counts["corpus_artifacts"]),
                "reviewed_paths": int(counts["reviewed_paths"]),
            },
            "entities": entities,
            "reports": sorted(
                reports,
                key=lambda report: (
                    str(report["report_date"]),
                    str(report["created_at"]),
                ),
                reverse=True,
            ),
            "aliases": [dict(row) for row in alias_rows],
            "response_rules": [dict(row) for row in rule_rows],
            "algorithms": [
                {
                    "id": str(row["id"]),
                    "algorithm_version": str(row["algorithm_version"]),
                    "weights": self._json_value(row["weights_json"], {}),
                    "description": str(row["description"]),
                    "created_at": str(row["created_at"]),
                }
                for row in algorithm_rows
            ],
        }

    def load_entity_intelligence(self, entity_id: str) -> dict | None:
        with self._connect() as connection:
            entity_row = connection.execute(
                """
                SELECT id, entity_type, canonical_key, label, normalized_value,
                       description, first_seen, last_seen, source_count,
                       properties_json
                FROM entities
                WHERE id = ?
                """,
                (entity_id,),
            ).fetchone()
            if entity_row is None:
                return None
            relationship_rows = connection.execute(
                """
                SELECT id, source_entity_id, target_entity_id, relation_type,
                       confidence, evidence_count, first_seen, last_seen,
                       category, status, properties_json
                FROM relationships
                WHERE source_entity_id = ? OR target_entity_id = ?
                ORDER BY evidence_count DESC, confidence DESC, id
                """,
                (entity_id, entity_id),
            ).fetchall()
            neighbor_ids = {
                str(row["target_entity_id"])
                if row["source_entity_id"] == entity_id
                else str(row["source_entity_id"])
                for row in relationship_rows
            }
            related_entity_rows: list[sqlite3.Row] = []
            if neighbor_ids:
                placeholders = ",".join("?" for _ in neighbor_ids)
                related_entity_rows = connection.execute(
                    f"""
                    SELECT id, entity_type, canonical_key, label,
                           normalized_value, description, first_seen, last_seen,
                           source_count, properties_json
                    FROM entities
                    WHERE id IN ({placeholders})
                    ORDER BY source_count DESC, label, id
                    """,
                    sorted(neighbor_ids),
                ).fetchall()
            relationship_ids = [str(row["id"]) for row in relationship_rows]
            evidence_rows: list[sqlite3.Row] = []
            if relationship_ids:
                placeholders = ",".join("?" for _ in relationship_ids)
                evidence_rows = connection.execute(
                    f"""
                    SELECT ev.id, ev.relationship_id, ev.report_id,
                           ev.source_ref, ev.location, ev.excerpt,
                           ev.confidence, rr.title AS report_title,
                           rr.source AS publisher, rr.report_date
                    FROM evidence ev
                    JOIN raw_reports rr ON rr.id = ev.report_id
                    WHERE ev.relationship_id IN ({placeholders})
                    ORDER BY rr.report_date DESC, ev.id
                    """,
                    relationship_ids,
                ).fetchall()
            report_ids = sorted({str(row["report_id"]) for row in evidence_rows})
            report_rows: list[sqlite3.Row] = []
            if report_ids:
                placeholders = ",".join("?" for _ in report_ids)
                report_rows = connection.execute(
                    f"""
                    SELECT id, title, source, report_date, classification,
                           language, original_filename, mime_type, size_bytes,
                           sha256, extracted_text, extraction_note, created_at,
                           source_ref, reliability, external_url, assessment
                    FROM raw_reports
                    WHERE id IN ({placeholders})
                    ORDER BY report_date DESC, created_at DESC
                    """,
                    report_ids,
                ).fetchall()
            flow_ids = {
                str(row["path_id"])
                for row in connection.execute(
                    """
                    SELECT DISTINCT path_id
                    FROM action_context_links
                    WHERE entity_id = ?
                    UNION
                    SELECT DISTINCT path_id
                    FROM reported_actor_claims
                    WHERE actor_id = ?
                    """,
                    (entity_id, entity_id),
                ).fetchall()
            }
            if str(entity_row["entity_type"]) == "攻击组织":
                actor_name = str(entity_row["label"]).casefold()
                for row in connection.execute(
                    "SELECT id, metadata_json FROM activity_paths"
                ).fetchall():
                    metadata = self._json_value(row["metadata_json"], {})
                    if (
                        isinstance(metadata, dict)
                        and str(metadata.get("actor", "")).casefold()
                        == actor_name
                    ):
                        flow_ids.add(str(row["id"]))

        flows = [
            flow
            for flow_id in sorted(flow_ids)
            if (flow := self.find_attack_flow(flow_id)) is not None
        ]
        source_ids = {source.id for flow in flows for source in flow.sources}
        with self._connect() as connection:
            artifact_rows: list[sqlite3.Row] = []
            if source_ids:
                placeholders = ",".join("?" for _ in source_ids)
                artifact_rows = connection.execute(
                    f"""
                    SELECT id, collection_id, collection_record_id, title,
                           publisher, canonical_url, acquisition_source,
                           acquisition_url, published_at, collected_at,
                           mime_type, size_bytes, sha256, storage_path,
                           dataset_license, source_license, tlp, archive_status,
                           canonical_verification_state, canonical_verified_at,
                           review_state, metadata_json
                    FROM source_artifacts
                    WHERE id IN ({placeholders})
                    ORDER BY published_at DESC, id
                    """,
                    sorted(source_ids),
                ).fetchall()
        return {
            "entity": self._export_entity(entity_row),
            "entities": [
                self._export_entity(entity_row),
                *(self._export_entity(row) for row in related_entity_rows),
            ],
            "relationships": [
                self._export_relationship(row) for row in relationship_rows
            ],
            "evidence": [dict(row) for row in evidence_rows],
            "reports": [dict(row) for row in report_rows],
            "source_artifacts": [
                {
                    **{
                        key: row[key]
                        for key in row.keys()
                        if key != "metadata_json"
                    },
                    "metadata": self._json_value(row["metadata_json"], {}),
                }
                for row in artifact_rows
            ],
            "attack_flows": [flow.model_dump() for flow in flows],
        }

    def load_source(
        self, source_document_id: str
    ) -> tuple[SourceDocument, str, list[SourceSpan]] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, title, publisher, canonical_url, published_at,
                       mime_type, sha256, content_size, review_state, content
                FROM source_documents
                WHERE id = ?
                """,
                (source_document_id,),
            ).fetchone()
            if row is None:
                return None
            values = dict(row)
            content = str(values.pop("content"))
            document = SourceDocument(**values)
            return document, content, self._load_spans(connection, document.id)

    def find_curated_extraction(self, source_sha256: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT observations_json
                FROM curated_extraction_baselines
                WHERE source_sha256 = ?
                """,
                (source_sha256,),
            ).fetchone()
            return None if row is None else str(row["observations_json"])

    def save_knowledge_ingestion(
        self, ingestion_id: str, source_document_id: str, result_json: str
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO knowledge_ingestion_runs (
                    id, source_document_id, status, result_json
                ) VALUES (?, ?, 'staged', ?)
                """,
                (ingestion_id, source_document_id, result_json),
            )

    def update_knowledge_ingestion(
        self, ingestion_id: str, result_json: str
    ) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE knowledge_ingestion_runs
                SET status = 'staged', result_json = ?, updated_at = ?
                WHERE id = ? AND status = 'staged'
                """,
                (
                    result_json,
                    datetime.now(timezone.utc).isoformat(),
                    ingestion_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("只有待复核的入库任务可以修订")

    def reject_knowledge_ingestion(
        self, ingestion_id: str, result_json: str
    ) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE knowledge_ingestion_runs
                SET status = 'rejected', result_json = ?, updated_at = ?
                WHERE id = ? AND status = 'staged'
                """,
                (
                    result_json,
                    datetime.now(timezone.utc).isoformat(),
                    ingestion_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("只有待复核的入库任务可以拒绝")

    def find_knowledge_ingestion(self, ingestion_id: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT result_json
                FROM knowledge_ingestion_runs
                WHERE id = ?
                """,
                (ingestion_id,),
            ).fetchone()
            return None if row is None else str(row["result_json"])

    def list_knowledge_ingestions(self, status: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT result_json
                FROM knowledge_ingestion_runs
                WHERE status = ?
                ORDER BY updated_at DESC, id DESC
                """,
                (status,),
            ).fetchall()
        return [json.loads(str(row["result_json"])) for row in rows]

    def publish_knowledge_ingestion(
        self,
        ingestion_id: str,
        version_id: str,
        result: dict,
        source: SourceDocument,
        content: str,
    ) -> dict:
        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT v.id, r.result_json
                FROM knowledge_versions v
                JOIN knowledge_ingestion_runs r ON r.id = v.ingestion_id
                WHERE v.ingestion_id = ? AND v.status = 'published'
                """,
                (ingestion_id,),
            ).fetchone()
            if existing is not None:
                return json.loads(existing["result_json"])

            now = datetime.now(timezone.utc).isoformat()
            existing_report = connection.execute(
                """
                SELECT id
                FROM raw_reports
                WHERE source_ref = ?
                """,
                (source.id,),
            ).fetchone()
            report_id = (
                str(existing_report["id"])
                if existing_report is not None
                else f"RPT-KI-{version_id.removeprefix('KVER-')}"
            )
            job_id = f"JOB-KI-{version_id.removeprefix('KVER-')}"
            if existing_report is None:
                connection.execute(
                    """
                    INSERT INTO raw_reports (
                        id, title, source, report_date, classification, language,
                        original_filename, mime_type, size_bytes, sha256, raw_blob,
                        extracted_text, extraction_note, created_at, source_ref,
                        reliability, external_url, assessment
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        report_id,
                        source.title,
                        source.publisher,
                        source.published_at,
                        "入库来源",
                        "自动识别",
                        source.mime_type,
                        source.content_size,
                        source.sha256,
                        content,
                        (
                            "由可信情报入库流程发布；原文哈希和证据锚点"
                            "保留在 source_documents。"
                        ),
                        now,
                        source.id,
                        source.review_state,
                        source.canonical_url,
                        "通过入库质量门后作为历史图谱证据发布。",
                    ),
                )
            connection.execute(
                """
                INSERT INTO import_jobs (
                    id, report_id, title, status, stage, entity_count,
                    relation_count, published_entity_count,
                    published_relation_count, created_at, updated_at, published_at
                ) VALUES (?, ?, ?, '已发布', 'published', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    report_id,
                    source.title,
                    len(result["entities"]),
                    len(result["relations"]),
                    result["delta"]["merge_entities"],
                    result["delta"]["reinforce_relationships"],
                    now,
                    now,
                    now,
                ),
            )

            created_canonical_entity_ids: list[str] = []
            reinforced_canonical_entity_ids: list[str] = []
            canonical_entity_id_by_stage: dict[str, str] = {}
            for entity in result.get("canonical_entities", []):
                entity_id = str(entity["entity_id"])
                if entity["decision"] == "create":
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO entities (
                            id, entity_type, canonical_key, label,
                            normalized_value, description, first_seen,
                            last_seen, source_count, created_at, updated_at,
                            properties_json, seed_origin
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                        """,
                        (
                            entity_id,
                            entity["entity_type"],
                            entity["canonical_key"],
                            entity["label"],
                            entity["normalized_value"],
                            (
                                f"由来源证据确定性规范化的"
                                f"{entity['value_type']} 实体。"
                            ),
                            source.published_at,
                            source.published_at,
                            now,
                            now,
                            json.dumps(
                                {
                                    "ui_type": "ioc",
                                    "value_type": entity["value_type"],
                                    "canonicalization_version": "observable/1.0",
                                    "confidence": entity["confidence"],
                                },
                                ensure_ascii=False,
                            ),
                            "knowledge-ingestion",
                        ),
                    )
                    stored = connection.execute(
                        """
                        SELECT id
                        FROM entities
                        WHERE canonical_key = ?
                        """,
                        (entity["canonical_key"],),
                    ).fetchone()
                    if stored is None:
                        raise RuntimeError(
                            f"Canonical entity was not persisted: "
                            f"{entity['canonical_key']}"
                        )
                    stored_id = str(stored["id"])
                    if stored_id == entity_id:
                        created_canonical_entity_ids.append(stored_id)
                    else:
                        reinforced_canonical_entity_ids.append(stored_id)
                        connection.execute(
                            """
                            UPDATE entities
                            SET source_count = source_count + 1,
                                first_seen = CASE
                                    WHEN first_seen IS NULL OR first_seen > ?
                                    THEN ? ELSE first_seen END,
                                last_seen = CASE
                                    WHEN last_seen IS NULL OR last_seen < ?
                                    THEN ? ELSE last_seen END,
                                updated_at = ?
                            WHERE id = ?
                            """,
                            (
                                source.published_at,
                                source.published_at,
                                source.published_at,
                                source.published_at,
                                now,
                                stored_id,
                            ),
                        )
                    entity_id = stored_id
                else:
                    reinforced_canonical_entity_ids.append(entity_id)
                    connection.execute(
                        """
                        UPDATE entities
                        SET source_count = source_count + 1,
                            first_seen = CASE
                                WHEN first_seen IS NULL OR first_seen > ?
                                THEN ? ELSE first_seen END,
                            last_seen = CASE
                                WHEN last_seen IS NULL OR last_seen < ?
                                THEN ? ELSE last_seen END,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            source.published_at,
                            source.published_at,
                            source.published_at,
                            source.published_at,
                            now,
                            entity_id,
                        ),
                    )
                canonical_entity_id_by_stage[entity["stage_id"]] = entity_id

            mention_ids: list[str] = []
            for entity in result.get("canonical_entities", []):
                entity_id = canonical_entity_id_by_stage[entity["stage_id"]]
                original_values = entity.get("original_values") or [entity["value"]]
                original_value = str(original_values[0])
                for source_span_id in entity["source_span_ids"]:
                    mention_digest = sha256(
                        (
                            ingestion_id
                            + "\0"
                            + entity_id
                            + "\0"
                            + str(source_span_id)
                            + "\0"
                            + original_value
                        ).encode("utf-8")
                    ).hexdigest()[:20]
                    mention_id = f"EMN-{mention_digest}"
                    cursor = connection.execute(
                        """
                        INSERT OR IGNORE INTO entity_mentions (
                            id, entity_id, source_document_id, source_span_id,
                            ingestion_id, original_value, canonical_value,
                            value_type, confidence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            mention_id,
                            entity_id,
                            source.id,
                            source_span_id,
                            ingestion_id,
                            original_value,
                            entity["normalized_value"],
                            entity["value_type"],
                            entity["confidence"],
                        ),
                    )
                    if cursor.rowcount:
                        mention_ids.append(mention_id)

            reinforced_entity_ids = sorted(
                {
                    entity["merge_target_id"]
                    for entity in result["entities"]
                    if entity["decision"] == "merge" and entity.get("merge_target_id")
                }
            )
            for entity_id in reinforced_entity_ids:
                connection.execute(
                    """
                    UPDATE entities
                    SET source_count = source_count + 1, updated_at = ?
                    WHERE id = ?
                    """,
                    (now, entity_id),
                )

            evidence_ids: list[str] = []
            reinforced_relationship_ids: list[str] = []
            for index, relation in enumerate(result["relations"], start=1):
                if relation["decision"] != "reinforce":
                    continue
                relationship_id = relation["relationship_id"]
                evidence_id = f"EVD-KI-{version_id.removeprefix('KVER-')}-{index:03d}"
                connection.execute(
                    """
                    INSERT INTO evidence (
                        id, relationship_id, report_id, job_id, excerpt,
                        confidence, created_at, source_ref, location
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        relationship_id,
                        report_id,
                        job_id,
                        relation["excerpt"],
                        relation["confidence"],
                        now,
                        source.id,
                        relation["locator"],
                    ),
                )
                connection.execute(
                    """
                    UPDATE relationships
                    SET evidence_count = evidence_count + 1, updated_at = ?
                    WHERE id = ?
                    """,
                    (now, relationship_id),
                )
                evidence_ids.append(evidence_id)
                reinforced_relationship_ids.append(relationship_id)

            changes = {
                "report_id": report_id,
                "job_id": job_id,
                "reinforced_entity_ids": reinforced_entity_ids,
                "reinforced_relationship_ids": sorted(set(reinforced_relationship_ids)),
                "evidence_ids": evidence_ids,
                "reinforced_entities": len(reinforced_entity_ids),
                "created_evidence": len(evidence_ids),
                "created_canonical_entity_ids": sorted(
                    set(created_canonical_entity_ids)
                ),
                "reinforced_canonical_entity_ids": sorted(
                    set(reinforced_canonical_entity_ids)
                ),
                "entity_mention_ids": mention_ids,
                "created_canonical_entities": len(
                    set(created_canonical_entity_ids)
                ),
                "reinforced_canonical_entities": len(
                    set(reinforced_canonical_entity_ids)
                ),
                "created_entity_mentions": len(mention_ids),
            }
            connection.execute(
                """
                INSERT INTO knowledge_versions (
                    id, ingestion_id, status, changes_json, published_at
                ) VALUES (?, ?, 'published', ?, ?)
                """,
                (version_id, ingestion_id, json.dumps(changes), now),
            )
            version = {
                "id": version_id,
                "status": "published",
                "changes": changes,
                "published_at": now,
            }
            published = {
                **result,
                "status": "published",
                "graph_write_performed": True,
                "version": version,
            }
            connection.execute(
                """
                UPDATE knowledge_ingestion_runs
                SET status = 'published', result_json = ?, version_id = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    json.dumps(published, ensure_ascii=False),
                    version_id,
                    now,
                    ingestion_id,
                ),
            )
            return published

    def publish_attack_flow_ingestion(
        self,
        ingestion_id: str,
        version_id: str,
        result: dict,
        source: SourceDocument,
    ) -> dict:
        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT r.result_json
                FROM knowledge_versions v
                JOIN knowledge_ingestion_runs r ON r.id = v.ingestion_id
                WHERE v.ingestion_id = ? AND v.status = 'published'
                """,
                (ingestion_id,),
            ).fetchone()
            if existing is not None:
                return json.loads(existing["result_json"])

            preview = result["attack_flow_preview"]
            flow_id = str(preview["flow_id"])
            now = datetime.now(timezone.utc).isoformat()
            duplicate_support = connection.execute(
                """
                SELECT id, path_id
                FROM flow_source_supports
                WHERE source_document_id = ? AND candidate_fingerprint = ?
                """,
                (source.id, preview["candidate_fingerprint"]),
            ).fetchone()
            if duplicate_support is not None:
                existing_flow_id = str(duplicate_support["path_id"])
                duplicate_result = {
                    **result,
                    "attack_flow_preview": {
                        **preview,
                        "flow_id": existing_flow_id,
                    },
                    "flow_candidate_summary": {
                        **result["flow_candidate_summary"],
                        "recommendation": "merge",
                        "merge_target_flow_id": existing_flow_id,
                        "reason": "同一来源的相同活动已支持现有 Flow，本次发布保持幂等。",
                    },
                }
                changes = {
                    "supported_attack_flow_id": existing_flow_id,
                    "flow_source_support_id": str(duplicate_support["id"]),
                    "support_already_present": True,
                    "added_path_evidence_ids": [],
                    "added_context_evidence_ids": [],
                    "added_context_link_ids": [],
                    "added_actor_claim_ids": [],
                    "created_context_entity_ids": [],
                }
                return self._publish_attack_flow_version(
                    connection,
                    ingestion_id=ingestion_id,
                    version_id=version_id,
                    result=duplicate_result,
                    changes=changes,
                    now=now,
                )
            created_entity_ids: list[str] = []
            entity_id_by_key: dict[str, str] = {}
            resolutions = [
                context["resolution"]
                for action in preview["actions"]
                for context in [*action["contexts"], *action["techniques"]]
            ]
            for resolution in resolutions:
                canonical_key = resolution.get("canonical_key")
                if not canonical_key or resolution["status"] == "review":
                    raise ValueError("AttackFlow 包含未解决的规范实体")
                if canonical_key in entity_id_by_key:
                    continue
                entity_id = str(resolution["entity_id"])
                if resolution["status"] == "create":
                    cursor = connection.execute(
                        """
                        INSERT OR IGNORE INTO entities (
                            id, entity_type, canonical_key, label,
                            normalized_value, description, first_seen,
                            last_seen, source_count, created_at, updated_at,
                            properties_json, seed_origin
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                        """,
                        (
                            entity_id,
                            resolution["entity_type"],
                            canonical_key,
                            resolution["label"],
                            resolution["normalized_value"],
                            "由人工复核 AttackFlow 的上下文映射创建。",
                            source.published_at,
                            source.published_at,
                            now,
                            now,
                            json.dumps(
                                {
                                    "ui_type": (
                                        "ioc"
                                        if resolution["entity_type"]
                                        == "IOC/基础设施"
                                        else "attack"
                                        if resolution["entity_type"]
                                        == "ATT&CK 技术"
                                        else "context"
                                    ),
                                    "observable_type": resolution["value_type"],
                                    "canonicalization_version": "observable/1.0",
                                },
                                ensure_ascii=False,
                            ),
                            "reviewed-attack-flow",
                        ),
                    )
                    if cursor.rowcount:
                        created_entity_ids.append(entity_id)
                stored = connection.execute(
                    "SELECT id FROM entities WHERE canonical_key = ?",
                    (canonical_key,),
                ).fetchone()
                if stored is None:
                    raise RuntimeError(
                        f"Canonical entity was not persisted: {canonical_key}"
                    )
                entity_id_by_key[canonical_key] = str(stored["id"])

            connection.execute(
                """
                INSERT INTO activity_paths (
                    id, name, description, activity_key, path_kind,
                    review_state, reviewer_type, reviewer_id, reviewed_at,
                    primary_artifact_id, confidence, metadata_json,
                    created_at, updated_at
                ) VALUES (
                    ?, ?, ?, ?, 'historical', 'published', 'human',
                    'knowledge-ingestion-review', ?, NULL, 0.9, ?, ?, ?
                )
                """,
                (
                    flow_id,
                    preview["title"],
                    preview["description"],
                    f"reviewed-publication:{ingestion_id}",
                    now,
                    json.dumps(
                        {
                            "schema_version": "1.0",
                            "source_document_id": source.id,
                            "ingestion_id": ingestion_id,
                        },
                        ensure_ascii=False,
                    ),
                    now,
                    now,
                ),
            )
            for sequence, action in enumerate(preview["actions"], start=1):
                connection.execute(
                    """
                    INSERT INTO activity_path_nodes (
                        id, path_id, entity_id, occurrence_key, label,
                        node_type, phase, sequence_hint, assertion_origin,
                        review_state, confidence, properties_json, created_at
                    ) VALUES (
                        ?, ?, NULL, ?, ?, 'action', ?, ?, 'source-observed',
                        'curator-confirmed', ?, ?, ?
                    )
                    """,
                    (
                        action["id"],
                        flow_id,
                        action["local_id"],
                        action["name"],
                        action["phase"],
                        float(sequence),
                        self._confidence_number(action["confidence"]),
                        json.dumps(
                            {"description": action["description"]},
                            ensure_ascii=False,
                        ),
                        now,
                    ),
                )
                for evidence in action["evidence"]:
                    self._insert_path_evidence(
                        connection,
                        evidence,
                        flow_id=flow_id,
                        node_id=action["id"],
                        edge_id=None,
                        now=now,
                    )

            for relation in preview["relations"]:
                edge_type = self._stored_edge_type(relation["type"])
                connection.execute(
                    """
                    INSERT INTO activity_path_edges (
                        id, path_id, source_node_id, target_node_id,
                        edge_type, v1_relation_type, condition_label,
                        assertion_origin, review_state, confidence,
                        properties_json, created_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, 'source-observed',
                        'curator-confirmed', ?, '{}', ?
                    )
                    """,
                    (
                        relation["id"],
                        flow_id,
                        relation["source_action_id"],
                        relation["target_action_id"],
                        edge_type,
                        relation["type"],
                        relation["condition"],
                        self._confidence_number(relation["confidence"]),
                        now,
                    ),
                )
                for evidence in relation["evidence"]:
                    self._insert_path_evidence(
                        connection,
                        evidence,
                        flow_id=flow_id,
                        node_id=None,
                        edge_id=relation["id"],
                        now=now,
                    )

            for action in preview["actions"]:
                for context in action["contexts"]:
                    resolution = context["resolution"]
                    entity_id = entity_id_by_key[resolution["canonical_key"]]
                    connection.execute(
                        """
                        INSERT INTO action_context_links (
                            id, path_id, action_node_id, entity_id, role,
                            direction, assertion_origin, review_state,
                            confidence, properties_json, created_at
                        ) VALUES (
                            ?, ?, ?, ?, ?, ?, 'source-observed',
                            'curator-confirmed', ?, '{}', ?
                        )
                        """,
                        (
                            context["id"],
                            flow_id,
                            action["id"],
                            entity_id,
                            context["role"],
                            context["direction"],
                            self._confidence_number(context["confidence"]),
                            now,
                        ),
                    )
                    for evidence in context["evidence"]:
                        self._insert_context_evidence(
                            connection,
                            evidence,
                            context_link_id=context["id"],
                            now=now,
                        )
                for technique_index, technique in enumerate(
                    action["techniques"], start=1
                ):
                    resolution = technique["resolution"]
                    entity_id = entity_id_by_key[resolution["canonical_key"]]
                    context_link_id = (
                        f"{action['id']}-TECH{technique_index:03d}"
                    )
                    connection.execute(
                        """
                        INSERT INTO action_context_links (
                            id, path_id, action_node_id, entity_id, role,
                            direction, assertion_origin, review_state,
                            confidence, properties_json, created_at
                        ) VALUES (
                            ?, ?, ?, ?, 'uses', 'action-to-entity',
                            'source-observed', 'curator-confirmed', 0.9, '{}', ?
                        )
                        """,
                        (context_link_id, flow_id, action["id"], entity_id, now),
                    )
                    for evidence in action["evidence"]:
                        self._insert_context_evidence(
                            connection,
                            {
                                **evidence,
                                "id": f"{evidence['id']}-TECH{technique_index:03d}",
                            },
                            context_link_id=context_link_id,
                            now=now,
                        )

            for actor in preview["reported_actors"]:
                connection.execute(
                    """
                    INSERT INTO reported_actor_claims (
                        id, path_id, reported_name, actor_id, confidence,
                        review_state, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'curator-confirmed', ?)
                    """,
                    (
                        actor["id"],
                        flow_id,
                        actor["reported_name"],
                        actor["actor_id"],
                        self._confidence_number(actor["confidence"]),
                        now,
                    ),
                )
                for evidence in actor["evidence"]:
                    connection.execute(
                        """
                        INSERT INTO reported_actor_evidence_links (
                            id, actor_claim_id, source_span_id, quote,
                            confidence, review_state, created_at
                        ) VALUES (?, ?, ?, ?, ?, 'curator-confirmed', ?)
                        """,
                        (
                            evidence["id"],
                            actor["id"],
                            evidence["source_span_id"],
                            evidence["quote"],
                            evidence["confidence"],
                            now,
                        ),
                    )

            connection.execute(
                """
                INSERT INTO analysis_projections (
                    id, path_id, projection_kind, root_action_refs_json,
                    mainline_action_refs_json, mainline_dependency_refs_json,
                    branch_groups_json, key_context_by_action_json,
                    lane_assignment_json, node_state_json, selection_reason,
                    algorithm_version, generated_at
                ) VALUES (
                    ?, ?, 'incident-response', ?, ?, ?, '[]', '{}', '{}', '{}',
                    '人工复核候选的显式主干', 'reviewed-publication/1.0', ?
                )
                """,
                (
                    f"PROJ-{flow_id}",
                    flow_id,
                    json.dumps(preview["mainline"][:1], ensure_ascii=False),
                    json.dumps(preview["mainline"], ensure_ascii=False),
                    json.dumps(
                        [
                            relation["id"]
                            for relation in preview["relations"]
                            if relation["source_action_id"] in preview["mainline"]
                            and relation["target_action_id"] in preview["mainline"]
                        ],
                        ensure_ascii=False,
                    ),
                    now,
                ),
            )
            support_id = "FSUP-" + sha256(
                f"{flow_id}\0{source.id}".encode("utf-8")
            ).hexdigest()[:20]
            connection.execute(
                """
                INSERT INTO flow_source_supports (
                    id, path_id, source_document_id, ingestion_id,
                    support_kind, candidate_fingerprint, created_at
                ) VALUES (?, ?, ?, ?, 'primary', ?, ?)
                """,
                (
                    support_id,
                    flow_id,
                    source.id,
                    ingestion_id,
                    preview["candidate_fingerprint"],
                    now,
                ),
            )
            changes = {
                "created_attack_flow_id": flow_id,
                "created_context_entity_ids": sorted(set(created_entity_ids)),
                "flow_source_support_id": support_id,
            }
            connection.execute(
                """
                INSERT INTO knowledge_versions (
                    id, ingestion_id, status, changes_json, published_at
                ) VALUES (?, ?, 'published', ?, ?)
                """,
                (version_id, ingestion_id, json.dumps(changes), now),
            )
            version = {
                "id": version_id,
                "status": "published",
                "changes": changes,
                "published_at": now,
            }
            published = {
                **result,
                "status": "published",
                "graph_write_performed": True,
                "version": version,
            }
            connection.execute(
                """
                UPDATE knowledge_ingestion_runs
                SET status = 'published', result_json = ?, version_id = ?,
                    updated_at = ?
                WHERE id = ? AND status = 'staged'
                """,
                (
                    json.dumps(published, ensure_ascii=False),
                    version_id,
                    now,
                    ingestion_id,
                ),
            )
            return published

    def publish_attack_flow_support(
        self,
        ingestion_id: str,
        version_id: str,
        result: dict,
        source: SourceDocument,
    ) -> dict:
        with self._connect() as connection:
            existing_version = connection.execute(
                """
                SELECT r.result_json
                FROM knowledge_versions v
                JOIN knowledge_ingestion_runs r ON r.id = v.ingestion_id
                WHERE v.ingestion_id = ? AND v.status = 'published'
                """,
                (ingestion_id,),
            ).fetchone()
            if existing_version is not None:
                return json.loads(existing_version["result_json"])

            preview = result["attack_flow_preview"]
            merge_review = result["merge_review"]
            target_flow_id = str(merge_review["target_flow_id"])
            now = datetime.now(timezone.utc).isoformat()
            fingerprint_support = connection.execute(
                """
                SELECT id, path_id
                FROM flow_source_supports
                WHERE source_document_id = ? AND candidate_fingerprint = ?
                """,
                (source.id, preview["candidate_fingerprint"]),
            ).fetchone()
            if (
                fingerprint_support is not None
                and str(fingerprint_support["path_id"]) != target_flow_id
            ):
                raise ValueError(
                    "同一来源的相同活动已经支持另一条 Flow，拒绝重复合并"
                )
            existing_support = connection.execute(
                """
                SELECT id
                FROM flow_source_supports
                WHERE path_id = ? AND source_document_id = ?
                """,
                (target_flow_id, source.id),
            ).fetchone()
            if existing_support is not None:
                changes = {
                    "supported_attack_flow_id": target_flow_id,
                    "flow_source_support_id": str(existing_support["id"]),
                    "support_already_present": True,
                    "added_path_evidence_ids": [],
                    "added_context_evidence_ids": [],
                    "added_context_link_ids": [],
                    "added_actor_claim_ids": [],
                    "created_context_entity_ids": [],
                }
                return self._publish_attack_flow_version(
                    connection,
                    ingestion_id=ingestion_id,
                    version_id=version_id,
                    result=result,
                    changes=changes,
                    now=now,
                )

            created_entity_ids: list[str] = []
            entity_id_by_key: dict[str, str] = {}
            resolutions = [
                context["resolution"]
                for action in preview["actions"]
                for context in [*action["contexts"], *action["techniques"]]
            ]
            for resolution in resolutions:
                canonical_key = str(resolution["canonical_key"])
                if canonical_key in entity_id_by_key:
                    continue
                entity_id = str(resolution["entity_id"])
                if resolution["status"] == "create":
                    cursor = connection.execute(
                        """
                        INSERT OR IGNORE INTO entities (
                            id, entity_type, canonical_key, label,
                            normalized_value, description, first_seen,
                            last_seen, source_count, created_at, updated_at,
                            properties_json, seed_origin
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                        """,
                        (
                            entity_id,
                            resolution["entity_type"],
                            canonical_key,
                            resolution["label"],
                            resolution["normalized_value"],
                            "由合并复核来源补充的 AttackFlow Context。",
                            source.published_at,
                            source.published_at,
                            now,
                            now,
                            json.dumps(
                                {
                                    "ui_type": (
                                        "ioc"
                                        if resolution["entity_type"]
                                        == "IOC/基础设施"
                                        else "attack"
                                        if resolution["entity_type"]
                                        == "ATT&CK 技术"
                                        else "context"
                                    ),
                                    "observable_type": resolution["value_type"],
                                    "canonicalization_version": "observable/1.0",
                                },
                                ensure_ascii=False,
                            ),
                            "reviewed-attack-flow-support",
                        ),
                    )
                    if cursor.rowcount:
                        created_entity_ids.append(entity_id)
                stored = connection.execute(
                    "SELECT id FROM entities WHERE canonical_key = ?",
                    (canonical_key,),
                ).fetchone()
                if stored is None:
                    raise RuntimeError(
                        f"Canonical entity was not persisted: {canonical_key}"
                    )
                entity_id_by_key[canonical_key] = str(stored["id"])

            action_map = {
                str(local_id): str(action_id)
                for local_id, action_id in merge_review["action_map"].items()
            }
            preview_action_by_id = {
                str(action["id"]): action for action in preview["actions"]
            }
            target_action_by_preview = {
                action["id"]: action_map[action["local_id"]]
                for action in preview["actions"]
            }
            added_path_evidence_ids: list[str] = []
            for action in preview["actions"]:
                target_action_id = target_action_by_preview[action["id"]]
                for evidence in action["evidence"]:
                    if self._insert_path_evidence(
                        connection,
                        evidence,
                        flow_id=target_flow_id,
                        node_id=target_action_id,
                        edge_id=None,
                        now=now,
                    ):
                        added_path_evidence_ids.append(evidence["id"])

            for relation in preview["relations"]:
                source_action = preview_action_by_id[relation["source_action_id"]]
                target_action = preview_action_by_id[relation["target_action_id"]]
                edge = connection.execute(
                    """
                    SELECT id
                    FROM activity_path_edges
                    WHERE path_id = ? AND source_node_id = ?
                      AND target_node_id = ?
                      AND COALESCE(v1_relation_type, edge_type) = ?
                    """,
                    (
                        target_flow_id,
                        action_map[source_action["local_id"]],
                        action_map[target_action["local_id"]],
                        relation["type"],
                    ),
                ).fetchone()
                if edge is None:
                    raise ValueError("合并时目标 Flow 的 Relation 已发生变化")
                for evidence in relation["evidence"]:
                    if self._insert_path_evidence(
                        connection,
                        evidence,
                        flow_id=target_flow_id,
                        node_id=None,
                        edge_id=str(edge["id"]),
                        now=now,
                    ):
                        added_path_evidence_ids.append(evidence["id"])

            added_context_link_ids: list[str] = []
            added_context_evidence_ids: list[str] = []
            for action in preview["actions"]:
                target_action_id = target_action_by_preview[action["id"]]
                context_items = [
                    *action["contexts"],
                    *[
                        {
                            "id": f"{action['id']}-TECH{index:03d}",
                            "role": "uses",
                            "direction": "action-to-entity",
                            "confidence": "high",
                            "resolution": technique["resolution"],
                            "evidence": action["evidence"],
                        }
                        for index, technique in enumerate(
                            action["techniques"], start=1
                        )
                    ],
                ]
                for context in context_items:
                    resolution = context["resolution"]
                    entity_id = entity_id_by_key[resolution["canonical_key"]]
                    stored_link = connection.execute(
                        """
                        SELECT id
                        FROM action_context_links
                        WHERE path_id = ? AND action_node_id = ?
                          AND entity_id = ? AND role = ?
                        """,
                        (
                            target_flow_id,
                            target_action_id,
                            entity_id,
                            context["role"],
                        ),
                    ).fetchone()
                    context_link_id = (
                        str(stored_link["id"])
                        if stored_link is not None
                        else str(context["id"])
                    )
                    if stored_link is None:
                        connection.execute(
                            """
                            INSERT INTO action_context_links (
                                id, path_id, action_node_id, entity_id, role,
                                direction, assertion_origin, review_state,
                                confidence, properties_json, created_at
                            ) VALUES (
                                ?, ?, ?, ?, ?, ?, 'source-observed',
                                'curator-confirmed', ?, '{}', ?
                            )
                            """,
                            (
                                context_link_id,
                                target_flow_id,
                                target_action_id,
                                entity_id,
                                context["role"],
                                context["direction"],
                                self._confidence_number(context["confidence"]),
                                now,
                            ),
                        )
                        added_context_link_ids.append(context_link_id)
                    for evidence in context["evidence"]:
                        evidence_item = {
                            **evidence,
                            "id": "CEVD-" + sha256(
                                (
                                    context_link_id
                                    + "\0"
                                    + evidence["source_span_id"]
                                    + "\0"
                                    + evidence["quote"]
                                ).encode("utf-8")
                            ).hexdigest()[:20],
                        }
                        if self._insert_context_evidence(
                            connection,
                            evidence_item,
                            context_link_id=context_link_id,
                            now=now,
                        ):
                            added_context_evidence_ids.append(evidence_item["id"])

            added_actor_claim_ids: list[str] = []
            for actor in preview["reported_actors"]:
                connection.execute(
                    """
                    INSERT INTO reported_actor_claims (
                        id, path_id, reported_name, actor_id, confidence,
                        review_state, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'curator-confirmed', ?)
                    """,
                    (
                        actor["id"],
                        target_flow_id,
                        actor["reported_name"],
                        actor["actor_id"],
                        self._confidence_number(actor["confidence"]),
                        now,
                    ),
                )
                added_actor_claim_ids.append(actor["id"])
                for evidence in actor["evidence"]:
                    connection.execute(
                        """
                        INSERT INTO reported_actor_evidence_links (
                            id, actor_claim_id, source_span_id, quote,
                            confidence, review_state, created_at
                        ) VALUES (?, ?, ?, ?, ?, 'curator-confirmed', ?)
                        """,
                        (
                            evidence["id"],
                            actor["id"],
                            evidence["source_span_id"],
                            evidence["quote"],
                            evidence["confidence"],
                            now,
                        ),
                    )

            support_id = "FSUP-" + sha256(
                f"{target_flow_id}\0{source.id}".encode("utf-8")
            ).hexdigest()[:20]
            connection.execute(
                """
                INSERT INTO flow_source_supports (
                    id, path_id, source_document_id, ingestion_id,
                    support_kind, candidate_fingerprint, created_at
                ) VALUES (?, ?, ?, ?, 'additional', ?, ?)
                """,
                (
                    support_id,
                    target_flow_id,
                    source.id,
                    ingestion_id,
                    preview["candidate_fingerprint"],
                    now,
                ),
            )
            changes = {
                "supported_attack_flow_id": target_flow_id,
                "flow_source_support_id": support_id,
                "support_already_present": False,
                "added_path_evidence_ids": added_path_evidence_ids,
                "added_context_evidence_ids": added_context_evidence_ids,
                "added_context_link_ids": added_context_link_ids,
                "added_actor_claim_ids": added_actor_claim_ids,
                "created_context_entity_ids": sorted(set(created_entity_ids)),
            }
            return self._publish_attack_flow_version(
                connection,
                ingestion_id=ingestion_id,
                version_id=version_id,
                result=result,
                changes=changes,
                now=now,
            )

    @staticmethod
    def _publish_attack_flow_version(
        connection: sqlite3.Connection,
        *,
        ingestion_id: str,
        version_id: str,
        result: dict,
        changes: dict,
        now: str,
    ) -> dict:
        connection.execute(
            """
            INSERT INTO knowledge_versions (
                id, ingestion_id, status, changes_json, published_at
            ) VALUES (?, ?, 'published', ?, ?)
            """,
            (version_id, ingestion_id, json.dumps(changes), now),
        )
        version = {
            "id": version_id,
            "status": "published",
            "changes": changes,
            "published_at": now,
        }
        published = {
            **result,
            "status": "published",
            "graph_write_performed": not changes.get("support_already_present", False),
            "version": version,
        }
        connection.execute(
            """
            UPDATE knowledge_ingestion_runs
            SET status = 'published', result_json = ?, version_id = ?,
                updated_at = ?
            WHERE id = ? AND status = 'staged'
            """,
            (
                json.dumps(published, ensure_ascii=False),
                version_id,
                now,
                ingestion_id,
            ),
        )
        return published

    @staticmethod
    def _insert_path_evidence(
        connection: sqlite3.Connection,
        evidence: dict,
        *,
        flow_id: str,
        node_id: str | None,
        edge_id: str | None,
        now: str,
    ) -> bool:
        cursor = connection.execute(
            """
            INSERT INTO path_evidence_links (
                id, path_id, node_id, edge_id, source_span_id, support_type,
                evidence_role, quote, confidence, review_state, created_at
            ) VALUES (
                ?, ?, ?, ?, ?, 'supports', 'direct', ?, ?,
                'curator-confirmed', ?
            )
            """,
            (
                evidence["id"],
                flow_id,
                node_id,
                edge_id,
                evidence["source_span_id"],
                evidence["quote"],
                evidence["confidence"],
                now,
            ),
        )
        return bool(cursor.rowcount)

    @staticmethod
    def _insert_context_evidence(
        connection: sqlite3.Connection,
        evidence: dict,
        *,
        context_link_id: str,
        now: str,
    ) -> bool:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO action_context_evidence_links (
                id, context_link_id, source_span_id, support_type,
                evidence_role, quote, confidence, review_state, created_at
            ) VALUES (
                ?, ?, ?, 'supports', 'direct', ?, ?, 'curator-confirmed', ?
            )
            """,
            (
                evidence["id"],
                context_link_id,
                evidence["source_span_id"],
                evidence["quote"],
                evidence["confidence"],
                now,
            ),
        )
        return bool(cursor.rowcount)

    @staticmethod
    def _confidence_number(level: str) -> float:
        return {"high": 0.9, "medium": 0.65, "low": 0.35}.get(level, 0.65)

    @staticmethod
    def _stored_edge_type(relation_type: str) -> str:
        return {
            "precedes": "sequence",
            "leads_to": "conditional",
            "enables": "enables",
            "causes": "causes",
            "on_success": "conditional",
            "on_failure": "conditional",
        }[relation_type]

    def rollback_knowledge_version(self, version_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, ingestion_id, status, changes_json, published_at,
                       rolled_back_at
                FROM knowledge_versions
                WHERE id = ?
                """,
                (version_id,),
            ).fetchone()
            if row is None:
                return None
            changes = json.loads(row["changes_json"])
            if changes.get("supported_attack_flow_id"):
                if row["status"] == "rolled_back":
                    return {
                        "id": row["id"],
                        "status": "rolled_back",
                        "changes": changes,
                        "published_at": row["published_at"],
                        "rolled_back_at": row["rolled_back_at"],
                    }
                now = datetime.now(timezone.utc).isoformat()
                if not changes.get("support_already_present"):
                    for evidence_id in changes.get(
                        "added_path_evidence_ids", []
                    ):
                        connection.execute(
                            "DELETE FROM path_evidence_links WHERE id = ?",
                            (evidence_id,),
                        )
                    for evidence_id in changes.get(
                        "added_context_evidence_ids", []
                    ):
                        connection.execute(
                            "DELETE FROM action_context_evidence_links WHERE id = ?",
                            (evidence_id,),
                        )
                    for actor_claim_id in changes.get(
                        "added_actor_claim_ids", []
                    ):
                        connection.execute(
                            "DELETE FROM reported_actor_claims WHERE id = ?",
                            (actor_claim_id,),
                        )
                    for context_link_id in changes.get(
                        "added_context_link_ids", []
                    ):
                        connection.execute(
                            "DELETE FROM action_context_links WHERE id = ?",
                            (context_link_id,),
                        )
                    connection.execute(
                        "DELETE FROM flow_source_supports WHERE id = ?",
                        (changes["flow_source_support_id"],),
                    )
                    for entity_id in changes.get(
                        "created_context_entity_ids", []
                    ):
                        references = connection.execute(
                            """
                            SELECT
                                (SELECT COUNT(*) FROM entity_mentions
                                 WHERE entity_id = ?) AS mention_count,
                                (SELECT COUNT(*) FROM relationships
                                 WHERE source_entity_id = ? OR target_entity_id = ?)
                                    AS relationship_count,
                                (SELECT COUNT(*) FROM action_context_links
                                 WHERE entity_id = ?) AS context_count,
                                (SELECT COUNT(*) FROM activity_path_nodes
                                 WHERE entity_id = ?) AS path_node_count,
                                (SELECT COUNT(*) FROM reported_actor_claims
                                 WHERE actor_id = ?) AS actor_claim_count
                            """,
                            (
                                entity_id,
                                entity_id,
                                entity_id,
                                entity_id,
                                entity_id,
                                entity_id,
                            ),
                        ).fetchone()
                        if references is not None and not any(
                            int(references[key]) for key in references.keys()
                        ):
                            connection.execute(
                                "DELETE FROM entities WHERE id = ?",
                                (entity_id,),
                            )
                rolled_changes = {
                    **changes,
                    "removed_flow_source_support_id": (
                        None
                        if changes.get("support_already_present")
                        else changes["flow_source_support_id"]
                    ),
                }
                connection.execute(
                    """
                    UPDATE knowledge_versions
                    SET status = 'rolled_back', changes_json = ?, rolled_back_at = ?
                    WHERE id = ?
                    """,
                    (json.dumps(rolled_changes), now, version_id),
                )
                ingestion = connection.execute(
                    "SELECT result_json FROM knowledge_ingestion_runs WHERE id = ?",
                    (row["ingestion_id"],),
                ).fetchone()
                ingestion_result = (
                    json.loads(ingestion["result_json"])
                    if ingestion is not None
                    else {}
                )
                ingestion_result["status"] = "rolled_back"
                if isinstance(ingestion_result.get("version"), dict):
                    ingestion_result["version"] = {
                        **ingestion_result["version"],
                        "status": "rolled_back",
                        "changes": rolled_changes,
                        "rolled_back_at": now,
                    }
                connection.execute(
                    """
                    UPDATE knowledge_ingestion_runs
                    SET status = 'rolled_back', result_json = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        json.dumps(ingestion_result, ensure_ascii=False),
                        now,
                        row["ingestion_id"],
                    ),
                )
                return {
                    "id": version_id,
                    "status": "rolled_back",
                    "changes": rolled_changes,
                    "published_at": row["published_at"],
                    "rolled_back_at": now,
                }
            if changes.get("created_attack_flow_id"):
                if row["status"] == "rolled_back":
                    return {
                        "id": row["id"],
                        "status": "rolled_back",
                        "changes": changes,
                        "published_at": row["published_at"],
                        "rolled_back_at": row["rolled_back_at"],
                    }
                now = datetime.now(timezone.utc).isoformat()
                flow_id = str(changes["created_attack_flow_id"])
                connection.execute(
                    "DELETE FROM activity_paths WHERE id = ?",
                    (flow_id,),
                )
                for entity_id in changes.get("created_context_entity_ids", []):
                    references = connection.execute(
                        """
                        SELECT
                            (SELECT COUNT(*) FROM entity_mentions
                             WHERE entity_id = ?) AS mention_count,
                            (SELECT COUNT(*) FROM relationships
                             WHERE source_entity_id = ? OR target_entity_id = ?)
                                AS relationship_count,
                            (SELECT COUNT(*) FROM action_context_links
                             WHERE entity_id = ?) AS context_count,
                            (SELECT COUNT(*) FROM activity_path_nodes
                             WHERE entity_id = ?) AS path_node_count,
                            (SELECT COUNT(*) FROM reported_actor_claims
                             WHERE actor_id = ?) AS actor_claim_count
                        """,
                        (
                            entity_id,
                            entity_id,
                            entity_id,
                            entity_id,
                            entity_id,
                            entity_id,
                        ),
                    ).fetchone()
                    if references is not None and not any(
                        int(references[key])
                        for key in references.keys()
                    ):
                        connection.execute(
                            "DELETE FROM entities WHERE id = ?",
                            (entity_id,),
                        )
                rolled_changes = {
                    **changes,
                    "removed_attack_flow_id": flow_id,
                }
                connection.execute(
                    """
                    UPDATE knowledge_versions
                    SET status = 'rolled_back', changes_json = ?, rolled_back_at = ?
                    WHERE id = ?
                    """,
                    (json.dumps(rolled_changes), now, version_id),
                )
                ingestion = connection.execute(
                    "SELECT result_json FROM knowledge_ingestion_runs WHERE id = ?",
                    (row["ingestion_id"],),
                ).fetchone()
                ingestion_result = (
                    json.loads(ingestion["result_json"])
                    if ingestion is not None
                    else {}
                )
                ingestion_result["status"] = "rolled_back"
                if isinstance(ingestion_result.get("version"), dict):
                    ingestion_result["version"] = {
                        **ingestion_result["version"],
                        "status": "rolled_back",
                        "changes": rolled_changes,
                        "rolled_back_at": now,
                    }
                connection.execute(
                    """
                    UPDATE knowledge_ingestion_runs
                    SET status = 'rolled_back', result_json = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        json.dumps(ingestion_result, ensure_ascii=False),
                        now,
                        row["ingestion_id"],
                    ),
                )
                return {
                    "id": version_id,
                    "status": "rolled_back",
                    "changes": rolled_changes,
                    "published_at": row["published_at"],
                    "rolled_back_at": now,
                }
            if row["status"] == "rolled_back":
                return {
                    "id": row["id"],
                    "status": "rolled_back",
                    "changes": {
                        **changes,
                        "removed_evidence": len(changes["evidence_ids"]),
                        "removed_entity_mentions": len(
                            changes.get("entity_mention_ids", [])
                        ),
                    },
                    "published_at": row["published_at"],
                    "rolled_back_at": row["rolled_back_at"],
                }
            now = datetime.now(timezone.utc).isoformat()
            for mention_id in changes.get("entity_mention_ids", []):
                connection.execute(
                    "DELETE FROM entity_mentions WHERE id = ?",
                    (mention_id,),
                )
            for evidence_id in changes["evidence_ids"]:
                connection.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
            for relationship_id in changes["reinforced_relationship_ids"]:
                connection.execute(
                    """
                    UPDATE relationships
                    SET evidence_count = MAX(1, evidence_count - 1),
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (now, relationship_id),
                )
            for entity_id in changes["reinforced_entity_ids"]:
                connection.execute(
                    """
                    UPDATE entities
                    SET source_count = MAX(1, source_count - 1), updated_at = ?
                    WHERE id = ?
                    """,
                    (now, entity_id),
                )
            for entity_id in changes.get(
                "reinforced_canonical_entity_ids", []
            ):
                connection.execute(
                    """
                    UPDATE entities
                    SET source_count = MAX(1, source_count - 1), updated_at = ?
                    WHERE id = ?
                    """,
                    (now, entity_id),
                )
            for entity_id in changes.get("created_canonical_entity_ids", []):
                references = connection.execute(
                    """
                    SELECT
                        (SELECT COUNT(*) FROM entity_mentions
                         WHERE entity_id = ?) AS mention_count,
                        (SELECT COUNT(*) FROM relationships
                         WHERE source_entity_id = ? OR target_entity_id = ?)
                            AS relationship_count
                    """,
                    (entity_id, entity_id, entity_id),
                ).fetchone()
                if (
                    references is not None
                    and references["mention_count"] == 0
                    and references["relationship_count"] == 0
                ):
                    connection.execute(
                        "DELETE FROM entities WHERE id = ?",
                        (entity_id,),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE entities
                        SET source_count = MAX(1, source_count - 1),
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (now, entity_id),
                    )
            connection.execute(
                """
                UPDATE import_jobs
                SET status = '已回滚', stage = 'rolled_back', updated_at = ?
                WHERE id = ?
                """,
                (now, changes["job_id"]),
            )
            connection.execute(
                """
                UPDATE knowledge_versions
                SET status = 'rolled_back', rolled_back_at = ?
                WHERE id = ?
                """,
                (now, version_id),
            )
            connection.execute(
                """
                UPDATE knowledge_ingestion_runs
                SET status = 'rolled_back', updated_at = ?
                WHERE id = ?
                """,
                (now, row["ingestion_id"]),
            )
            return {
                "id": version_id,
                "status": "rolled_back",
                "changes": {
                    **changes,
                    "removed_evidence": len(changes["evidence_ids"]),
                    "removed_entity_mentions": len(
                        changes.get("entity_mention_ids", [])
                    ),
                },
                "published_at": row["published_at"],
                "rolled_back_at": now,
            }

    def load_entity_identity_index(self) -> tuple[list[dict], list[dict]]:
        with self._connect() as connection:
            entities = connection.execute(
                """
                SELECT id, entity_type, canonical_key, label, normalized_value,
                       description, source_count, properties_json
                FROM entities
                ORDER BY source_count DESC, id
                """
            ).fetchall()
            aliases = connection.execute(
                """
                SELECT entity_id, alias, alias_key, confidence
                FROM aliases
                ORDER BY confidence DESC, id
                """
            ).fetchall()
            return [dict(row) for row in entities], [dict(row) for row in aliases]

    def load_actor_knowledge_slice(self) -> dict:
        """Return the actor-centered graph projection consumed by the UI.

        The projection follows an actor's direct relationships, then walks the
        attack-step chain starting at each related historical activity. Leaf
        context such as techniques, infrastructure, tools and vulnerabilities
        is included without using those shared entities to cross into another
        activity.
        """
        with self._connect() as connection:
            entity_rows = connection.execute(
                """
                SELECT id, entity_type, canonical_key, label, normalized_value,
                       description, first_seen, last_seen, source_count,
                       properties_json, updated_at
                FROM entities
                ORDER BY entity_type, label
                """
            ).fetchall()
            relationship_rows = connection.execute(
                """
                SELECT id, source_entity_id, target_entity_id, relation_type,
                       confidence, evidence_count, first_seen, last_seen,
                       category, status, properties_json, updated_at
                FROM relationships
                ORDER BY category, source_entity_id, target_entity_id
                """
            ).fetchall()
            actor_rows = connection.execute(
                """
                SELECT e.id, e.label, e.description, e.source_count,
                       e.properties_json, ap.profile_status, ap.origin_label,
                       ap.active_from, ap.active_to, ap.public_attribution,
                       ap.motivations_json, ap.target_sectors_json,
                       ap.source_refs_json, ap.source_urls_json,
                       ap.source_grade, ap.updated_at
                FROM entities e
                JOIN actor_profiles ap ON ap.actor_id = e.id
                WHERE e.entity_type = '攻击组织'
                ORDER BY e.label
                """
            ).fetchall()

            entity_by_id = {row["id"]: row for row in entity_rows}
            adjacency: dict[str, list[sqlite3.Row]] = {}
            for row in relationship_rows:
                adjacency.setdefault(row["source_entity_id"], []).append(row)
                adjacency.setdefault(row["target_entity_id"], []).append(row)

            actor_ids = {row["id"] for row in actor_rows}
            scoped_entity_ids = set(actor_ids)
            scoped_relationship_ids: set[str] = set()
            activity_ids: set[str] = set()

            for actor_id in actor_ids:
                for relationship in adjacency.get(actor_id, []):
                    scoped_relationship_ids.add(relationship["id"])
                    neighbor_id = self._other_endpoint(relationship, actor_id)
                    scoped_entity_ids.add(neighbor_id)
                    neighbor = entity_by_id.get(neighbor_id)
                    if neighbor and neighbor["entity_type"] == "历史事件":
                        activity_ids.add(neighbor_id)

            queue = list(activity_ids)
            traversed = set(activity_ids)
            while queue:
                current_id = queue.pop(0)
                for relationship in adjacency.get(current_id, []):
                    neighbor_id = self._other_endpoint(relationship, current_id)
                    neighbor = entity_by_id.get(neighbor_id)
                    if neighbor is None:
                        continue
                    if neighbor["entity_type"] == "攻击组织":
                        continue
                    if (
                        neighbor["entity_type"] == "历史事件"
                        and neighbor_id not in activity_ids
                    ):
                        continue
                    scoped_relationship_ids.add(relationship["id"])
                    scoped_entity_ids.add(neighbor_id)
                    if (
                        neighbor["entity_type"] == "攻击步骤"
                        and neighbor_id not in traversed
                    ):
                        traversed.add(neighbor_id)
                        queue.append(neighbor_id)

            scoped_entities = [
                self._export_entity(row)
                for row in entity_rows
                if row["id"] in scoped_entity_ids
            ]
            scoped_relationships = [
                self._export_relationship(row)
                for row in relationship_rows
                if row["id"] in scoped_relationship_ids
            ]

            relationship_ids = [item["id"] for item in scoped_relationships]
            evidence_rows: list[sqlite3.Row] = []
            if relationship_ids:
                placeholders = ",".join("?" for _ in relationship_ids)
                evidence_rows = connection.execute(
                    f"""
                    SELECT ev.id, ev.relationship_id, ev.report_id,
                           ev.source_ref, ev.location, ev.excerpt,
                           ev.confidence, ev.created_at,
                           rr.title AS report_title, rr.source AS publisher,
                           rr.report_date
                    FROM evidence ev
                    JOIN raw_reports rr ON rr.id = ev.report_id
                    WHERE ev.relationship_id IN ({placeholders})
                    ORDER BY rr.report_date DESC, ev.id
                    """,
                    relationship_ids,
                ).fetchall()

            report_ids = sorted({row["report_id"] for row in evidence_rows})
            report_rows: list[sqlite3.Row] = []
            if report_ids:
                placeholders = ",".join("?" for _ in report_ids)
                report_rows = connection.execute(
                    f"""
                    SELECT id, title, source, report_date, classification,
                           language, original_filename, mime_type, size_bytes,
                           sha256, extracted_text, extraction_note, created_at,
                           source_ref, reliability, external_url, assessment
                    FROM raw_reports
                    WHERE id IN ({placeholders})
                    ORDER BY report_date DESC, created_at DESC
                    """,
                    report_ids,
                ).fetchall()

            alias_rows: list[sqlite3.Row] = []
            if actor_ids:
                ordered_actor_ids = sorted(actor_ids)
                placeholders = ",".join("?" for _ in ordered_actor_ids)
                alias_rows = connection.execute(
                    f"""
                    SELECT id, entity_id, alias, alias_type, source, confidence
                    FROM aliases
                    WHERE entity_id IN ({placeholders})
                    ORDER BY entity_id, confidence DESC
                    """,
                    ordered_actor_ids,
                ).fetchall()

            actors = [self._export_actor(row) for row in actor_rows]
            evidence = [
                {
                    key: row[key]
                    for key in (
                        "id",
                        "relationship_id",
                        "report_id",
                        "source_ref",
                        "location",
                        "excerpt",
                        "confidence",
                        "report_title",
                        "publisher",
                        "report_date",
                    )
                }
                for row in evidence_rows
            ]
            reports = [dict(row) for row in report_rows]
            aliases = [dict(row) for row in alias_rows]
            change_points = [
                *(
                    str(row["updated_at"])
                    for row in entity_rows
                    if row["id"] in scoped_entity_ids
                ),
                *(
                    str(row["updated_at"])
                    for row in relationship_rows
                    if row["id"] in scoped_relationship_ids
                ),
                *(str(row["created_at"]) for row in evidence_rows),
                *(str(row["updated_at"]) for row in actor_rows),
            ]
            generated_at = datetime.now(timezone.utc).isoformat()
            version_payload = "|".join(
                [
                    str(len(actors)),
                    str(len(scoped_entities)),
                    str(len(scoped_relationships)),
                    str(len(evidence)),
                    max(change_points, default=""),
                ]
            )
            return {
                "meta": {
                    "source": str(self.database_path),
                    "generated_at": generated_at,
                    "version": f"actor-{sha256(version_payload.encode()).hexdigest()[:16]}",
                },
                "scope": {
                    "actor_ids": sorted(actor_ids),
                    "entity_ids": sorted(scoped_entity_ids),
                    "relationship_ids": sorted(scoped_relationship_ids),
                },
                "actors": actors,
                "entities": scoped_entities,
                "relationships": scoped_relationships,
                "evidence": evidence,
                "reports": reports,
                "aliases": aliases,
            }

    def save_flow_match_run(self, run: FlowMatchRun) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO flow_match_runs (
                    id, query_text, normalized_inputs_json, algorithm_version,
                    knowledge_snapshot, result_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    run.id,
                    run.query_text,
                    json.dumps(
                        [item.model_dump() for item in run.normalized_inputs],
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    run.algorithm_version,
                    run.knowledge_snapshot,
                    run.model_dump_json(),
                ),
            )

    def find_flow_match_run(self, run_id: str) -> FlowMatchRun | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM flow_match_runs WHERE id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return FlowMatchRun.model_validate_json(str(row["result_json"]))

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _other_endpoint(relationship: sqlite3.Row, entity_id: str) -> str:
        if relationship["source_entity_id"] == entity_id:
            return str(relationship["target_entity_id"])
        return str(relationship["source_entity_id"])

    @staticmethod
    def _json_value(value: str | None, fallback: object) -> object:
        if not value:
            return fallback
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return fallback

    @classmethod
    def _export_entity(cls, row: sqlite3.Row) -> dict:
        return {
            key: row[key]
            for key in (
                "id",
                "entity_type",
                "canonical_key",
                "label",
                "normalized_value",
                "description",
                "first_seen",
                "last_seen",
                "source_count",
            )
        } | {"properties": cls._json_value(row["properties_json"], {})}

    @classmethod
    def _export_relationship(cls, row: sqlite3.Row) -> dict:
        return {
            key: row[key]
            for key in (
                "id",
                "source_entity_id",
                "target_entity_id",
                "relation_type",
                "confidence",
                "evidence_count",
                "first_seen",
                "last_seen",
                "category",
                "status",
            )
        } | {"properties": cls._json_value(row["properties_json"], {})}

    @classmethod
    def _export_actor(cls, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "label": row["label"],
            "description": row["description"],
            "source_count": row["source_count"],
            "properties": cls._json_value(row["properties_json"], {}),
            "profile_status": row["profile_status"],
            "origin_label": row["origin_label"],
            "active_from": row["active_from"],
            "active_to": row["active_to"],
            "public_attribution": row["public_attribution"],
            "motivations": cls._json_value(row["motivations_json"], []),
            "target_sectors": cls._json_value(row["target_sectors_json"], []),
            "source_refs": cls._json_value(row["source_refs_json"], []),
            "source_urls": cls._json_value(row["source_urls_json"], []),
            "source_grade": row["source_grade"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _confidence_level(confidence: float) -> ConfidenceLevel:
        if confidence >= 0.8:
            return "high"
        if confidence >= 0.5:
            return "medium"
        return "low"

    @staticmethod
    def _attack_flow_context_type(
        entity_type: str,
        properties: dict,
    ) -> str:
        observable_type = str(properties.get("observable_type", "")).lower()
        if observable_type in {"file", "url", "domain", "hash"}:
            return observable_type
        if observable_type in {"ipv4", "ipv6", "ip"}:
            return "ip"
        if entity_type == "恶意软件/工具":
            sub = str(properties.get("sub", ""))
            return "malware" if "恶意软件" in sub else "tool"
        if entity_type in {"漏洞", "CVE"}:
            return "vulnerability"
        if entity_type == "资产":
            return "asset"
        return "infrastructure" if entity_type == "IOC/基础设施" else "other"

    @staticmethod
    def _attack_flow_context_role(role: str) -> str:
        if role in {
            "uses",
            "targets",
            "communicates-with",
            "exploits",
            "downloads-from",
            "drops-on",
            "runs-on",
            "modifies",
            "creates",
            "other",
        }:
            return role
        return {
            "opens": "uses",
            "extracts": "uses",
            "identified-by": "other",
            "uses-malware": "uses",
            "copies-as": "creates",
            "exfiltrates-to": "communicates-with",
            "connects-to": "communicates-with",
            "executes-file": "uses",
            "targets-asset": "targets",
            "exploits-vulnerability": "exploits",
        }.get(role, "other")

    @staticmethod
    def _attack_flow_relation_type(edge_type: str) -> str:
        if edge_type in {
            "precedes",
            "leads_to",
            "enables",
            "causes",
            "on_success",
            "on_failure",
        }:
            return edge_type
        relation_type = {
            "sequence": "precedes",
            "enables": "enables",
            "causes": "causes",
            "conditional": "leads_to",
        }.get(edge_type)
        if relation_type is None:
            raise ValueError(f"Unsupported AttackFlow relation type: {edge_type}")
        return relation_type

    @staticmethod
    def _attack_flow_evidence(row: sqlite3.Row) -> AttackFlowEvidence:
        return AttackFlowEvidence(
            id=str(row["id"]),
            source_span_id=str(row["source_span_id"]),
            source_id=str(row["source_id"]),
            title=str(row["source_title"]),
            publisher=str(row["publisher"]),
            canonical_url=str(row["canonical_url"]),
            locator=str(row["locator"]),
            quote=str(row["quote"]),
            confidence=round(float(row["confidence"]), 3),
        )

    @staticmethod
    def _validate_attack_flow_evidence(
        actions: list[AttackFlowAction],
        relations: list[AttackFlowRelation],
        reported_actors: list[AttackFlowReportedActor],
    ) -> None:
        def verified(evidence: AttackFlowEvidence) -> bool:
            return bool(
                evidence.source_span_id
                and evidence.source_id
                and evidence.locator
                and evidence.quote
            )

        for action in actions:
            if not action.evidence or not all(verified(item) for item in action.evidence):
                raise ValueError(
                    f"AttackFlow Action has no verified Evidence: {action.id}"
                )
            for context in action.contexts:
                if not context.evidence or not all(
                    verified(item) for item in context.evidence
                ):
                    raise ValueError(
                        "AttackFlow Context has no verified Evidence: "
                        f"{context.id}"
                    )
        for relation in relations:
            if not relation.evidence or not all(
                verified(item) for item in relation.evidence
            ):
                raise ValueError(
                    "AttackFlow Relation has no verified Evidence: "
                    f"{relation.id}"
                )
        for actor in reported_actors:
            if not actor.evidence or not all(
                verified(item) for item in actor.evidence
            ):
                raise ValueError(
                    "AttackFlow reported Actor has no verified Evidence: "
                    f"{actor.id}"
                )

    @staticmethod
    def _validate_attack_flow_mainline(
        flow_id: str,
        mainline: list[str],
        actions: list[AttackFlowAction],
        relations: list[AttackFlowRelation],
    ) -> None:
        if not mainline or len(mainline) != len(set(mainline)):
            raise ValueError(f"AttackFlow has an invalid mainline: {flow_id}")
        action_ids = {action.id for action in actions}
        if any(action_id not in action_ids for action_id in mainline):
            raise ValueError(
                f"AttackFlow mainline references an unknown Action: {flow_id}"
            )
        relation_pairs = {
            (relation.source_action_id, relation.target_action_id)
            for relation in relations
        }
        if any(
            (source_id, target_id) not in relation_pairs
            for source_id, target_id in zip(mainline, mainline[1:])
        ):
            raise ValueError(
                f"AttackFlow mainline contains an unaudited gap: {flow_id}"
            )

    @staticmethod
    def _source_document(row: sqlite3.Row) -> SourceDocument:
        return SourceDocument(**dict(row))

    @staticmethod
    def _load_spans(
        connection: sqlite3.Connection, source_document_id: str
    ) -> list[SourceSpan]:
        rows = connection.execute(
            """
            SELECT id, source_document_id, locator, start_offset, end_offset,
                   text, extraction_method
            FROM source_spans
            WHERE source_document_id = ?
            ORDER BY start_offset
            """,
            (source_document_id,),
        ).fetchall()
        return [SourceSpan(**dict(row)) for row in rows]
