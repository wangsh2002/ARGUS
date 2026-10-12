from collections import defaultdict
import re

from .models import (
    AttackFlow,
    AttackFlowEvidence,
    AttackFlowSourceAnnotation,
    AttackFlowSourceAnnotationKind,
    AttackFlowSourceDocumentView,
    SourceSpan,
)
from .repository import SqliteRepository


class AttackFlowSourceAnnotationService:
    def __init__(self, repository: SqliteRepository) -> None:
        self.repository = repository

    def documents(self, flow: AttackFlow) -> list[AttackFlowSourceDocumentView]:
        annotations_by_source: dict[str, list[AttackFlowSourceAnnotation]] = (
            defaultdict(list)
        )

        for action in flow.actions:
            self._append_evidence(
                annotations_by_source,
                action.evidence,
                kind="attack-process",
                label=action.name,
                action_ids=[action.id],
            )
            for context in action.contexts:
                self._append_evidence(
                    annotations_by_source,
                    context.evidence,
                    kind=self._context_kind(context.type),
                    label=context.name,
                    action_ids=[action.id],
                    entity_id=context.entity_id,
                )

        action_name_by_id = {action.id: action.name for action in flow.actions}
        for relation in flow.relations:
            source_name = action_name_by_id.get(
                relation.source_action_id, relation.source_action_id
            )
            target_name = action_name_by_id.get(
                relation.target_action_id, relation.target_action_id
            )
            self._append_evidence(
                annotations_by_source,
                relation.evidence,
                kind="attack-process",
                label=f"{source_name} → {target_name}",
                action_ids=[relation.source_action_id, relation.target_action_id],
            )

        for actor in flow.reported_actors:
            self._append_evidence(
                annotations_by_source,
                actor.evidence,
                kind="actor",
                label=actor.reported_name,
                entity_id=actor.actor_id,
            )

        documents: list[AttackFlowSourceDocumentView] = []
        for source in flow.sources:
            loaded = self.repository.load_source(source.id)
            if loaded is None:
                continue
            document, content, spans = loaded
            for mention in self.repository.list_source_entity_mentions(source.id):
                annotations_by_source[source.id].append(
                    AttackFlowSourceAnnotation(
                        id=f"ANN-{mention['id']}",
                        kind=self._mention_kind(
                            str(mention["entity_type"]),
                            str(mention["value_type"]),
                        ),
                        label=str(mention["label"]),
                        start_offset=0,
                        end_offset=0,
                        quote=str(mention["original_value"]),
                        confidence=float(mention["confidence"]),
                        entity_id=str(mention["entity_id"]),
                        evidence_ids=[
                            str(mention["id"]),
                            str(mention["source_span_id"]),
                        ],
                    )
                )
            span_by_id = {span.id: span for span in spans}
            resolved = [
                self._resolve_annotation(content, span_by_id, annotation)
                for annotation in annotations_by_source.get(source.id, [])
            ]
            documents.append(
                AttackFlowSourceDocumentView(
                    id=document.id,
                    title=document.title,
                    publisher=document.publisher,
                    canonical_url=document.canonical_url,
                    published_at=document.published_at,
                    mime_type=document.mime_type,
                    content=content,
                    annotations=self._merge_annotations(resolved),
                )
            )
        return documents

    @staticmethod
    def _context_kind(context_type: str) -> AttackFlowSourceAnnotationKind:
        if context_type in {"ip", "domain", "url", "hash", "infrastructure"}:
            return "ioc"
        if context_type == "vulnerability":
            return "vulnerability"
        if context_type in {"asset", "account"}:
            return "asset"
        return "software"

    @staticmethod
    def _mention_kind(
        entity_type: str,
        value_type: str,
    ) -> AttackFlowSourceAnnotationKind:
        if entity_type == "攻击组织" or value_type == "actor-name":
            return "actor"
        if entity_type == "CVE" or value_type == "cve":
            return "vulnerability"
        if entity_type == "IOC/基础设施":
            return "ioc"
        if entity_type == "恶意软件/工具":
            return "software"
        return "asset"

    @staticmethod
    def _append_evidence(
        annotations_by_source: dict[str, list[AttackFlowSourceAnnotation]],
        evidence_items: list[AttackFlowEvidence],
        *,
        kind: AttackFlowSourceAnnotationKind,
        label: str,
        action_ids: list[str] | None = None,
        entity_id: str | None = None,
    ) -> None:
        for evidence in evidence_items:
            annotations_by_source[evidence.source_id].append(
                AttackFlowSourceAnnotation(
                    id=f"ANN-{evidence.id}",
                    kind=kind,
                    label=label,
                    start_offset=0,
                    end_offset=0,
                    quote=evidence.quote,
                    confidence=evidence.confidence,
                    action_ids=action_ids or [],
                    entity_id=entity_id,
                    evidence_ids=[evidence.id, evidence.source_span_id],
                )
            )

    @classmethod
    def _resolve_annotation(
        cls,
        content: str,
        span_by_id: dict[str, SourceSpan],
        annotation: AttackFlowSourceAnnotation,
    ) -> AttackFlowSourceAnnotation:
        span_id = annotation.evidence_ids[-1]
        span = span_by_id.get(span_id)
        start_offset, end_offset = cls._locate_quote(content, span, annotation.quote)
        return annotation.model_copy(
            update={"start_offset": start_offset, "end_offset": end_offset}
        )

    @classmethod
    def _locate_quote(
        cls,
        content: str,
        span: SourceSpan | None,
        quote: str,
    ) -> tuple[int, int]:
        if not content:
            return 0, 0
        window_start = max(0, (span.start_offset if span else 0) - 320)
        window_end = min(
            len(content),
            (span.end_offset if span else len(content)) + 320,
        )
        window = content[window_start:window_end]
        stripped_quote = quote.strip()
        if stripped_quote:
            quote_variants = cls._quote_variants(stripped_quote)
            for quote_variant in quote_variants:
                direct_index = window.find(quote_variant)
                if direct_index < 0:
                    direct_index = window.casefold().find(quote_variant.casefold())
                if direct_index >= 0:
                    start_offset = window_start + direct_index
                    return start_offset, start_offset + len(quote_variant)

            normalized_window, offset_map = cls._normalized_with_offsets(window)
            for quote_variant in quote_variants:
                normalized_quote = re.sub(r"\s+", " ", quote_variant).casefold()
                normalized_index = normalized_window.find(normalized_quote)
                if normalized_index >= 0 and offset_map:
                    start_offset = window_start + offset_map[normalized_index]
                    final_index = normalized_index + len(normalized_quote) - 1
                    end_offset = window_start + offset_map[final_index] + 1
                    return start_offset, end_offset

            for quote_variant in quote_variants:
                matches = list(
                    re.finditer(re.escape(quote_variant), content, flags=re.IGNORECASE)
                )
                if len(matches) == 1:
                    return matches[0].start(), matches[0].end()

        if span is not None:
            return (
                max(0, min(len(content), span.start_offset)),
                max(0, min(len(content), span.end_offset)),
            )
        return 0, 0

    @staticmethod
    def _quote_variants(quote: str) -> list[str]:
        variants = [quote]
        markdown_escaped = re.sub(r"(?<!\\)([_*])", r"\\\1", quote)
        if markdown_escaped != quote:
            variants.append(markdown_escaped)
        unescaped = quote.replace("\\_", "_").replace("\\*", "*")
        if unescaped not in variants:
            variants.append(unescaped)
        return variants

    @staticmethod
    def _normalized_with_offsets(value: str) -> tuple[str, list[int]]:
        normalized: list[str] = []
        offsets: list[int] = []
        whitespace_pending = False
        whitespace_offset = 0
        for index, character in enumerate(value):
            if character.isspace():
                if normalized and normalized[-1] != " ":
                    whitespace_pending = True
                    whitespace_offset = index
                continue
            if whitespace_pending:
                normalized.append(" ")
                offsets.append(whitespace_offset)
                whitespace_pending = False
            folded = character.casefold()
            normalized.extend(folded)
            offsets.extend([index] * len(folded))
        return "".join(normalized), offsets

    @staticmethod
    def _merge_annotations(
        annotations: list[AttackFlowSourceAnnotation],
    ) -> list[AttackFlowSourceAnnotation]:
        merged: dict[
            tuple[int, int, str, str, str | None], AttackFlowSourceAnnotation
        ] = {}
        for annotation in annotations:
            if annotation.end_offset <= annotation.start_offset:
                continue
            key = (
                annotation.start_offset,
                annotation.end_offset,
                annotation.kind,
                annotation.label,
                annotation.entity_id,
            )
            existing = merged.get(key)
            if existing is None:
                merged[key] = annotation
                continue
            merged[key] = existing.model_copy(
                update={
                    "confidence": max(existing.confidence, annotation.confidence),
                    "action_ids": sorted(
                        {*existing.action_ids, *annotation.action_ids}
                    ),
                    "evidence_ids": sorted(
                        {*existing.evidence_ids, *annotation.evidence_ids}
                    ),
                }
            )
        return sorted(
            merged.values(),
            key=lambda item: (item.start_offset, item.end_offset, item.kind, item.id),
        )
