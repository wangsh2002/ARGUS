from collections import defaultdict, deque
from dataclasses import dataclass
import re
import unicodedata

from .models import (
    AttackFlow,
    PanoramicGraphEdge,
    PanoramicGraphIndex,
    PanoramicGraphIndexItem,
    PanoramicGraphNeighborhood,
    PanoramicGraphNode,
)
from .repository import SqliteRepository


CONFIDENCE_SCORES = {"high": 0.95, "medium": 0.65, "low": 0.35}


def actor_name_key(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in normalized if character.isalnum())


@dataclass(frozen=True)
class GraphSnapshot:
    nodes: dict[str, PanoramicGraphNode]
    edges: dict[str, PanoramicGraphEdge]
    atomic_edge_ids: frozenset[str]
    knowledge_version: str


class PanoramicGraphService:
    def __init__(self, repository: SqliteRepository) -> None:
        self.repository = repository

    def index(self) -> PanoramicGraphIndex:
        snapshot = self._build_snapshot()
        relation_counts: dict[str, int] = defaultdict(int)
        evidence_counts: dict[str, int] = defaultdict(int)
        for edge in snapshot.edges.values():
            source = snapshot.nodes.get(edge.source_id)
            target = snapshot.nodes.get(edge.target_id)
            if source and target and "evidence" not in {source.kind, target.kind}:
                relation_counts[edge.source_id] += 1
                relation_counts[edge.target_id] += 1
            evidence_counts[edge.source_id] += len(edge.evidence_ids)
            evidence_counts[edge.target_id] += len(edge.evidence_ids)
        items = [
            PanoramicGraphIndexItem(
                **node.model_dump(),
                relation_count=relation_counts[node.id],
                evidence_count=evidence_counts[node.id],
            )
            for node in snapshot.nodes.values()
            if node.kind != "evidence"
        ]
        items.sort(
            key=lambda node: (
                -node.relation_count,
                node.kind,
                node.label.casefold(),
                node.id,
            )
        )
        return PanoramicGraphIndex(
            nodes=items,
            node_count=len(snapshot.nodes),
            evidence_node_count=sum(
                node.kind == "evidence" for node in snapshot.nodes.values()
            ),
            atomic_edge_count=len(snapshot.atomic_edge_ids),
            aggregate_edge_count=len(snapshot.edges) - len(snapshot.atomic_edge_ids),
            knowledge_version=snapshot.knowledge_version,
        )

    def neighborhood(
        self,
        root_id: str,
        depth: int = 2,
        limit: int = 96,
    ) -> PanoramicGraphNeighborhood:
        snapshot = self._build_snapshot()
        if root_id not in snapshot.nodes:
            raise LookupError(f"Unknown panoramic graph node: {root_id}")

        adjacency: dict[str, list[PanoramicGraphEdge]] = defaultdict(list)
        for edge in snapshot.edges.values():
            adjacency[edge.source_id].append(edge)
            adjacency[edge.target_id].append(edge)
        for edges in adjacency.values():
            edges.sort(key=lambda edge: (edge.aggregate, -edge.confidence, edge.id))

        selected_node_ids = {root_id}
        selected_edge_ids: set[str] = set()
        queue = deque([(root_id, 0)])
        while queue and len(selected_node_ids) < limit:
            node_id, distance = queue.popleft()
            if distance >= depth:
                continue
            for edge in adjacency[node_id]:
                other_id = (
                    edge.target_id if edge.source_id == node_id else edge.source_id
                )
                if len(selected_node_ids) >= limit and other_id not in selected_node_ids:
                    break
                selected_edge_ids.add(edge.id)
                if other_id not in selected_node_ids:
                    selected_node_ids.add(other_id)
                    queue.append((other_id, distance + 1))

        for edge_id in list(selected_edge_ids):
            edge = snapshot.edges[edge_id]
            if not edge.aggregate or edge.explanation is None:
                continue
            selected_node_ids.update(edge.explanation.node_ids)
            selected_edge_ids.update(edge.explanation.edge_ids)

        selected_edges = [
            snapshot.edges[edge_id]
            for edge_id in selected_edge_ids
            if edge_id in snapshot.edges
            and snapshot.edges[edge_id].source_id in selected_node_ids
            and snapshot.edges[edge_id].target_id in selected_node_ids
        ]
        selected_edges.sort(key=lambda edge: (edge.aggregate, edge.type, edge.id))
        selected_nodes = [snapshot.nodes[node_id] for node_id in selected_node_ids]
        selected_nodes.sort(
            key=lambda node: (node.id != root_id, node.kind, node.label, node.id)
        )
        return PanoramicGraphNeighborhood(
            root_id=root_id,
            depth=depth,
            nodes=selected_nodes,
            edges=selected_edges,
            available_expansions={
                node.id: len(
                    {
                        edge.target_id if edge.source_id == node.id else edge.source_id
                        for edge in adjacency[node.id]
                    }
                )
                for node in selected_nodes
            },
            knowledge_version=snapshot.knowledge_version,
        )

    def _build_snapshot(self) -> GraphSnapshot:
        identity_context = self.repository.load_panoramic_graph_identity_context()
        entity_rows = identity_context["entities"]
        flow_metadata = identity_context["flows"]
        nodes: dict[str, PanoramicGraphNode] = {}
        edges: dict[str, PanoramicGraphEdge] = {}

        entity_by_id = {str(row["id"]): row for row in entity_rows}
        actor_by_name = {
            actor_name_key(str(row["label"])): str(row["id"])
            for row in entity_rows
            if str(row["entity_type"]) == "攻击组织"
        }
        for row in entity_rows:
            entity_id = str(row["id"])
            entity_type = str(row["entity_type"])
            nodes[entity_id] = PanoramicGraphNode(
                id=entity_id,
                kind="actor" if entity_type == "攻击组织" else "entity",
                label=str(row["label"]),
                type=entity_type,
                description=str(row.get("description") or ""),
                confidence=1.0,
                properties={"normalized_value": str(row.get("normalized_value") or "")},
            )

        flows = self.repository.list_attack_flows()
        for flow in flows:
            self._add_flow(flow, nodes, edges)
            self._add_actor_claims(
                flow,
                flow_metadata.get(flow.id, {}),
                actor_by_name,
                nodes,
                edges,
            )

        atomic_edge_ids = frozenset(edges)
        referenced_node_ids = {
            node_id
            for edge in edges.values()
            for node_id in (edge.source_id, edge.target_id)
        }
        nodes = {
            node_id: node
            for node_id, node in nodes.items()
            if node_id in referenced_node_ids
            or node.kind in {"action", "actor", "entity"}
        }
        return GraphSnapshot(
            nodes=nodes,
            edges=edges,
            atomic_edge_ids=atomic_edge_ids,
            knowledge_version=str(identity_context["knowledge_version"]),
        )

    def _add_flow(
        self,
        flow: AttackFlow,
        nodes: dict[str, PanoramicGraphNode],
        edges: dict[str, PanoramicGraphEdge],
    ) -> None:
        source_dates = {source.id: source.published_at for source in flow.sources}

        for action in flow.actions:
            action_score = CONFIDENCE_SCORES[action.confidence]
            nodes[action.id] = PanoramicGraphNode(
                id=action.id,
                kind="action",
                label=action.name,
                type="攻击步骤",
                description=action.description,
                confidence=action_score,
                properties={
                    "flow_id": flow.id,
                    "flow_title": flow.title,
                    "flow_description": flow.description,
                    "mainline": flow.mainline,
                    "phase": action.phase,
                    "technique_ids": action.technique_ids,
                },
            )
            self._add_evidence(
                action.id,
                action.evidence,
                nodes,
                edges,
                "action",
                source_dates,
            )
            for context in action.contexts:
                if context.entity_id is None:
                    continue
                context_score = CONFIDENCE_SCORES[context.confidence]
                context_evidence_ids = [
                    item.source_span_id for item in context.evidence
                ]
                context_edge = PanoramicGraphEdge(
                    id=context.id,
                    source_id=(
                        action.id
                        if context.direction == "action-to-entity"
                        else context.entity_id
                    ),
                    target_id=(
                        context.entity_id
                        if context.direction == "action-to-entity"
                        else action.id
                    ),
                    type="action-context",
                    label=context.role,
                    confidence=context_score,
                    evidence_ids=context_evidence_ids,
                    evidence=context.evidence,
                )
                edges[context.id] = context_edge
                self._add_evidence(
                    action.id,
                    context.evidence,
                    nodes,
                    edges,
                    f"context:{context.id}",
                    source_dates,
                )

        for relation in flow.relations:
            relation_score = CONFIDENCE_SCORES[relation.confidence]
            evidence_ids = [item.source_span_id for item in relation.evidence]
            edges[relation.id] = PanoramicGraphEdge(
                id=relation.id,
                source_id=relation.source_action_id,
                target_id=relation.target_action_id,
                type=relation.type,
                label=relation.condition or relation.type,
                confidence=relation_score,
                evidence_ids=evidence_ids,
                evidence=relation.evidence,
            )
            self._add_evidence(
                relation.source_action_id,
                relation.evidence,
                nodes,
                edges,
                f"relation:{relation.id}",
                source_dates,
            )

    def _add_actor_claims(
        self,
        flow: AttackFlow,
        metadata: dict,
        actor_by_name: dict[str, str],
        nodes: dict[str, PanoramicGraphNode],
        edges: dict[str, PanoramicGraphEdge],
    ) -> list[PanoramicGraphEdge]:
        target_action_id = next(
            (
                action_id
                for action_id in flow.mainline
                if action_id in {action.id for action in flow.actions}
            ),
            flow.actions[0].id if flow.actions else None,
        )
        if target_action_id is None:
            return []

        source_dates = {source.id: source.published_at for source in flow.sources}
        claims = list(flow.reported_actors)
        if not claims and str(metadata.get("actor") or "").strip():
            reported_name = str(metadata["actor"]).strip()
            actor_id = actor_by_name.get(actor_name_key(reported_name))
            if actor_id:
                evidence = next(
                    (
                        item
                        for action in flow.actions
                        for item in action.evidence
                    ),
                    None,
                )
                edge_id = f"metadata-actor-claim:{flow.id}:{actor_id}"
                edge = PanoramicGraphEdge(
                    id=edge_id,
                    source_id=actor_id,
                    target_id=target_action_id,
                    type="reported-actor",
                    label="报告归因",
                    confidence=0.65,
                    evidence_ids=[evidence.source_span_id] if evidence else [],
                    evidence=[evidence] if evidence else [],
                )
                edges[edge_id] = edge
                return [edge]

        actor_edges: list[PanoramicGraphEdge] = []
        for claim in claims:
            resolved_actor_ids = []
            if claim.actor_id and claim.actor_id in nodes:
                resolved_actor_ids = [claim.actor_id]
            else:
                direct_actor_id = actor_by_name.get(
                    actor_name_key(claim.reported_name)
                )
                if direct_actor_id:
                    resolved_actor_ids = [direct_actor_id]
                else:
                    resolved_actor_ids = sorted(
                        {
                            actor_by_name[part_key]
                            for part in re.split(
                                r"\s+(?:and|&)\s+|\s*/\s*|[,、]",
                                claim.reported_name,
                            )
                            if (part_key := actor_name_key(part)) in actor_by_name
                        }
                    )
            actor_ids = resolved_actor_ids or [f"reported-actor:{claim.id}"]
            for actor_id in actor_ids:
                if actor_id not in nodes:
                    nodes[actor_id] = PanoramicGraphNode(
                        id=actor_id,
                        kind="actor",
                        label=claim.reported_name,
                        type="报告提及组织",
                        confidence=CONFIDENCE_SCORES[claim.confidence],
                        properties={"resolved": False},
                    )
                edge_id = (
                    claim.id
                    if len(actor_ids) == 1
                    else f"{claim.id}:{actor_id}"
                )
                edge = PanoramicGraphEdge(
                    id=edge_id,
                    source_id=actor_id,
                    target_id=target_action_id,
                    type="reported-actor",
                    label="报告归因",
                    confidence=CONFIDENCE_SCORES[claim.confidence],
                    evidence_ids=[item.source_span_id for item in claim.evidence],
                    evidence=claim.evidence,
                )
                edges[edge.id] = edge
                actor_edges.append(edge)
                self._add_evidence(
                    actor_id,
                    claim.evidence,
                    nodes,
                    edges,
                    "actor",
                    source_dates,
                )
        return actor_edges

    @staticmethod
    def _add_evidence(
        owner_id: str,
        evidence_items: list,
        nodes: dict[str, PanoramicGraphNode],
        edges: dict[str, PanoramicGraphEdge],
        relation_scope: str,
        source_dates: dict[str, str],
    ) -> None:
        for evidence in evidence_items:
            evidence_id = evidence.source_span_id
            nodes.setdefault(
                evidence_id,
                PanoramicGraphNode(
                    id=evidence_id,
                    kind="evidence",
                    label=f"证据 · {evidence.locator}",
                    type="来源片段",
                    description=evidence.quote,
                    confidence=evidence.confidence,
                    properties={
                        "source_id": evidence.source_id,
                        "source_title": evidence.title,
                        "publisher": evidence.publisher,
                        "canonical_url": evidence.canonical_url,
                        "published_at": source_dates.get(evidence.source_id, ""),
                    },
                ),
            )
            owner_edge_id = (
                f"evidence-support:{relation_scope}:{owner_id}:{evidence_id}"
            )
            edges.setdefault(
                owner_edge_id,
                PanoramicGraphEdge(
                    id=owner_edge_id,
                    source_id=owner_id,
                    target_id=evidence_id,
                    type="supported-by-evidence",
                    label="证据支持",
                    confidence=evidence.confidence,
                    evidence_ids=[evidence_id],
                ),
            )
