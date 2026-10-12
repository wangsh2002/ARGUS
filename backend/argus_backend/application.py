from hashlib import sha256
import json
import re
from uuid import uuid4

from .models import (
    AttackFlow,
    AttackFlowDraft,
    AttackFlowMergeReview,
    AttackFlowSourceDocumentView,
    FlowMatchRequest,
    FlowMatchRun,
    PanoramicGraphIndex,
    PanoramicGraphNeighborhood,
    SourceArchiveRequest,
    SourceArchiveResponse,
    SourceDocument,
    SourceSpan,
)
from .attack_flow_publication import AttackFlowPublicationService
from .attack_flow_extraction import (
    AttackFlowLanguageModel,
    extract_attack_flow_candidates,
)
from .entity_evidence import EntityEvidenceIngestionService
from .flow_matcher import AttackFlowMatcher
from .panoramic_graph import PanoramicGraphService
from .repository import SqliteRepository
from .source_annotations import AttackFlowSourceAnnotationService


class ArgusApplication:
    def __init__(
        self,
        repository: SqliteRepository,
        attack_flow_language_model: AttackFlowLanguageModel | None = None,
    ) -> None:
        self.repository = repository
        self.entity_evidence = EntityEvidenceIngestionService(repository)
        self.attack_flow_publication = AttackFlowPublicationService(repository)
        self.panoramic_graph = PanoramicGraphService(repository)
        self.source_annotations = AttackFlowSourceAnnotationService(repository)
        self.attack_flow_language_model = attack_flow_language_model

    def archive_source(self, request: SourceArchiveRequest) -> SourceArchiveResponse:
        digest = sha256(request.content.encode("utf-8")).hexdigest()
        existing = self.repository.find_source_by_sha256(digest)
        if existing is not None:
            document, spans = existing
            return SourceArchiveResponse(
                source_document=document,
                source_spans=spans,
                created=False,
            )

        document_id = f"SRC-DOC-{digest[:16]}"
        review_state = (
            "curated"
            if self.repository.find_curated_extraction(digest) is not None
            else "parsed"
        )
        document = SourceDocument(
            id=document_id,
            title=request.title,
            publisher=request.publisher,
            canonical_url=str(request.canonical_url),
            published_at=request.published_at,
            mime_type=request.mime_type,
            sha256=digest,
            content_size=len(request.content.encode("utf-8")),
            review_state=review_state,
        )
        spans = self._paragraph_spans(document_id, digest, request.content)
        self.repository.insert_source(document, request.content, spans)
        return SourceArchiveResponse(
            source_document=document,
            source_spans=spans,
            created=True,
        )

    def get_attack_flow(self, flow_id: str) -> AttackFlow:
        flow = self.repository.find_attack_flow(flow_id)
        if flow is None:
            raise LookupError(f"Unknown AttackFlow: {flow_id}")
        return flow

    def list_attack_flows(self) -> list[AttackFlow]:
        return self.repository.list_attack_flows()

    def get_attack_flow_source_documents(
        self, flow_id: str
    ) -> list[AttackFlowSourceDocumentView]:
        return self.source_annotations.documents(self.get_attack_flow(flow_id))

    def get_panoramic_graph_index(self) -> PanoramicGraphIndex:
        return self.panoramic_graph.index()

    def get_runtime_catalog(self) -> dict:
        return self.repository.load_runtime_catalog()

    def get_entity_intelligence(self, entity_id: str) -> dict:
        result = self.repository.load_entity_intelligence(entity_id)
        if result is None:
            raise LookupError(f"Unknown entity: {entity_id}")
        return result

    def get_panoramic_graph_neighborhood(
        self, node_id: str, depth: int, limit: int
    ) -> PanoramicGraphNeighborhood:
        return self.panoramic_graph.neighborhood(node_id, depth, limit)

    def match_attack_flows(self, request: FlowMatchRequest) -> FlowMatchRun:
        run = AttackFlowMatcher(self.repository.list_attack_flows()).match(
            run_id=f"FM-{uuid4().hex[:16]}",
            request=request,
        )
        self.repository.save_flow_match_run(run)
        return run

    def get_flow_match_run(self, run_id: str) -> FlowMatchRun:
        run = self.repository.find_flow_match_run(run_id)
        if run is None:
            raise LookupError(f"Unknown Flow match run: {run_id}")
        return run

    def stage_knowledge_ingestion(
        self,
        source_document_id: str,
        projection_goal: str = "incident-response",
        attack_flow_candidate: AttackFlowDraft | None = None,
        attack_flow_candidates: list[AttackFlowDraft] | None = None,
        merge_review: AttackFlowMergeReview | None = None,
        extract_attack_flows: bool = False,
    ) -> dict:
        if extract_attack_flows:
            return self._extract_and_stage_attack_flows(source_document_id)
        if attack_flow_candidates is not None:
            if attack_flow_candidates:
                candidates = [
                    self.attack_flow_publication.stage(
                        source_document_id,
                        candidate,
                    )
                    for candidate in attack_flow_candidates
                ]
                return {
                    "ingestion_kind": "attack-flow-batch",
                    "source_document_id": source_document_id,
                    "status": "staged",
                    "flow_candidate_summary": {
                        "status": (
                            "multiple" if len(candidates) > 1 else "single"
                        ),
                        "candidate_count": len(candidates),
                        "recommendation": "review",
                        "merge_target_flow_id": None,
                        "reason": "每个攻击活动候选均已隔离暂存并独立复核。",
                    },
                    "candidates": candidates,
                }
            result = self.entity_evidence.stage(source_document_id)
            result["flow_candidate_summary"] = {
                "status": "no-flow",
                "candidate_count": 0,
                "recommendation": "no-flow",
                "merge_target_flow_id": None,
                "reason": "来源没有形成可发布的攻击活动候选。",
            }
            self.repository.update_knowledge_ingestion(
                result["id"],
                json.dumps(result, ensure_ascii=False),
            )
            return result
        if attack_flow_candidate is not None:
            return self.attack_flow_publication.stage(
                source_document_id,
                attack_flow_candidate,
                merge_review,
            )
        return self.entity_evidence.stage(source_document_id)

    def _extract_and_stage_attack_flows(self, source_document_id: str) -> dict:
        if self.attack_flow_language_model is None:
            raise ValueError("AttackFlow 抽取模型未配置")
        source = self.repository.load_source(source_document_id)
        if source is None:
            raise LookupError(f"Unknown source document: {source_document_id}")
        document, content, _ = source
        extraction = extract_attack_flow_candidates(
            self.attack_flow_language_model,
            {
                "sha256": document.sha256,
                "title": document.title,
                "publisher": document.publisher,
                "published_at": document.published_at,
                "canonical_url": document.canonical_url,
            },
            content,
        )
        if not extraction.candidates:
            result = self.entity_evidence.stage(source_document_id)
            result["extraction_audit"]["attack_flow_extraction"] = extraction.audit
            self.repository.update_knowledge_ingestion(
                result["id"], json.dumps(result, ensure_ascii=False)
            )
            return result
        candidates = [
            self.attack_flow_publication.stage(
                source_document_id,
                candidate,
                extraction_audit=extraction.audit,
            )
            for candidate in extraction.candidates
        ]
        if len(candidates) == 1:
            return candidates[0]
        return {
            "ingestion_kind": "attack-flow-batch",
            "source_document_id": source_document_id,
            "status": "staged",
            "extraction_audit": extraction.audit,
            "flow_candidate_summary": {
                "status": "multiple",
                "candidate_count": len(candidates),
                "recommendation": "review",
                "merge_target_flow_id": None,
                "reason": "模型识别到多个独立攻击活动，已按现有规范分别暂存。",
            },
            "candidates": candidates,
        }

    def get_knowledge_ingestion(self, ingestion_id: str) -> dict:
        return self.entity_evidence.get(ingestion_id)

    def list_pending_attack_flow_ingestions(self) -> dict:
        items = [
            item
            for item in self.repository.list_knowledge_ingestions("staged")
            if item.get("ingestion_kind") == "attack-flow"
        ]
        return {
            "items": items,
            "summary": {
                "pending_flows": len(items),
                "publishable_flows": sum(item.get("publishable") is True for item in items),
                "blocked_flows": sum(item.get("publishable") is not True for item in items),
                "source_documents": len(
                    {item.get("source_document_id") for item in items}
                ),
            },
        }

    def revise_attack_flow_ingestion(
        self,
        ingestion_id: str,
        attack_flow_candidate: AttackFlowDraft,
        merge_review: AttackFlowMergeReview | None = None,
    ) -> dict:
        return self.attack_flow_publication.revise(
            ingestion_id,
            attack_flow_candidate,
            merge_review,
        )

    def reject_attack_flow_ingestion(self, ingestion_id: str) -> dict:
        return self.attack_flow_publication.reject(ingestion_id)

    def publish_knowledge_ingestion(self, ingestion_id: str) -> dict:
        current = self.entity_evidence.get(ingestion_id)
        if current.get("ingestion_kind") == "attack-flow":
            return self.attack_flow_publication.publish(ingestion_id)
        return self.entity_evidence.publish(ingestion_id)

    def rollback_knowledge_version(self, version_id: str) -> dict:
        return self.entity_evidence.rollback(version_id)

    def get_actor_knowledge(self) -> dict:
        return self.repository.load_actor_knowledge_slice()

    @staticmethod
    def _paragraph_spans(
        source_document_id: str, digest: str, content: str
    ) -> list[SourceSpan]:
        spans: list[SourceSpan] = []
        cursor = 0
        paragraphs = re.split(r"(?:\r?\n){2,}", content)
        for paragraph in paragraphs:
            text = paragraph.strip()
            if not text:
                cursor += len(paragraph)
                continue
            start = content.find(text, cursor)
            end = start + len(text)
            index = len(spans) + 1
            spans.append(
                SourceSpan(
                    id=f"SRC-SPAN-{digest[:12]}-{index:04d}",
                    source_document_id=source_document_id,
                    locator=f"paragraph:{index}",
                    start_offset=start,
                    end_offset=end,
                    text=text,
                    extraction_method="paragraph",
                )
            )
            cursor = end
        return spans
