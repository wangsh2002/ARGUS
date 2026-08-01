from collections import defaultdict, deque
from dataclasses import dataclass

from .models import (
    AttackFlow,
    PanoramicGraphEdge,
    PanoramicGraphExplanation,
    PanoramicGraphIndex,
    PanoramicGraphIndexItem,
    PanoramicGraphNeighborhood,
    PanoramicGraphNode,
)
from .repository import SqliteRepository


CONFIDENCE_SCORES = {"high": 0.95, "medium": 0.65, "low": 0.35}


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
            str(row["label"]).strip().casefold(): str(row["id"])
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
        flow_actor_edges: list[PanoramicGraphEdge] = []
        flow_context_paths: dict[str, dict[str, tuple[str, str]]] = defaultdict(dict)
        for flow in flows:
            self._add_flow(flow, nodes, edges, flow_context_paths)
            actor_edges = self._add_actor_claims(
                flow,
                flow_metadata.get(flow.id, {}),
                actor_by_name,
                nodes,
                edges,
            )
            flow_actor_edges.extend(actor_edges)

        atomic_edge_ids = frozenset(edges)
        self._add_aggregate_edges(edges, flow_actor_edges, flow_context_paths)
        referenced_node_ids = {
            node_id
            for edge in edges.values()
            for node_id in (edge.source_id, edge.target_id)
        }
        nodes = {
            node_id: node
            for node_id, node in nodes.items()
            if node_id in referenced_node_ids
            or node.kind in {"attack-flow", "action", "source"}
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
        flow_context_paths: dict[str, dict[str, tuple[str, str]]],
    ) -> None:
        nodes[flow.id] = PanoramicGraphNode(
            id=flow.id,
            kind="attack-flow",
            label=flow.title,
            type="攻击流",
            description=flow.description,
            properties={"mainline": flow.mainline},
        )
        for source in flow.sources:
            nodes[source.id] = PanoramicGraphNode(
                id=source.id,
                kind="source",
                label=source.title,
                type="来源报告",
                description=source.publisher,
                properties={
                    "publisher": source.publisher,
                    "canonical_url": source.canonical_url,
                    "published_at": source.published_at,
                },
            )
            edge_id = f"flow-source:{flow.id}:{source.id}"
            edges[edge_id] = PanoramicGraphEdge(
                id=edge_id,
                source_id=flow.id,
                target_id=source.id,
                type="supported-by-source",
                label="来源支持",
            )

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
                    "phase": action.phase,
                    "technique_ids": action.technique_ids,
                },
            )
            membership_id = f"flow-action:{flow.id}:{action.id}"
            action_evidence_ids = [item.source_span_id for item in action.evidence]
            edges[membership_id] = PanoramicGraphEdge(
                id=membership_id,
                source_id=flow.id,
                target_id=action.id,
                type="contains-action",
                label="包含步骤",
                confidence=action_score,
                evidence_ids=action_evidence_ids,
            )
            self._add_evidence(action.id, action.evidence, nodes, edges, "action")
            for context in action.contexts:
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
                )
                edges[context.id] = context_edge
                flow_context_paths[flow.id].setdefault(
                    context.entity_id,
                    (membership_id, context.id),
                )
                self._add_evidence(
                    action.id,
                    context.evidence,
                    nodes,
                    edges,
                    f"context:{context.id}",
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
            )
            self._add_evidence(
                relation.source_action_id,
                relation.evidence,
                nodes,
                edges,
                f"relation:{relation.id}",
            )

    def _add_actor_claims(
        self,
        flow: AttackFlow,
        metadata: dict,
        actor_by_name: dict[str, str],
        nodes: dict[str, PanoramicGraphNode],
        edges: dict[str, PanoramicGraphEdge],
    ) -> list[PanoramicGraphEdge]:
        claims = list(flow.reported_actors)
        if not claims and str(metadata.get("actor") or "").strip():
            reported_name = str(metadata["actor"]).strip()
            actor_id = actor_by_name.get(reported_name.casefold())
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
                    target_id=flow.id,
                    type="reported-actor",
                    label="报告归因",
                    confidence=0.65,
                    evidence_ids=[evidence.source_span_id] if evidence else [],
                )
                edges[edge_id] = edge
                return [edge]

        actor_edges: list[PanoramicGraphEdge] = []
        for claim in claims:
            actor_id = claim.actor_id or f"reported-actor:{claim.id}"
            if actor_id not in nodes:
                nodes[actor_id] = PanoramicGraphNode(
                    id=actor_id,
                    kind="actor",
                    label=claim.reported_name,
                    type="报告提及组织",
                    confidence=CONFIDENCE_SCORES[claim.confidence],
                    properties={"resolved": claim.actor_id is not None},
                )
            edge = PanoramicGraphEdge(
                id=claim.id,
                source_id=actor_id,
                target_id=flow.id,
                type="reported-actor",
                label="报告归因",
                confidence=CONFIDENCE_SCORES[claim.confidence],
                evidence_ids=[item.source_span_id for item in claim.evidence],
            )
            edges[edge.id] = edge
            actor_edges.append(edge)
            self._add_evidence(actor_id, claim.evidence, nodes, edges, "actor")
        return actor_edges

    @staticmethod
    def _add_evidence(
        owner_id: str,
        evidence_items: list,
        nodes: dict[str, PanoramicGraphNode],
        edges: dict[str, PanoramicGraphEdge],
        relation_scope: str,
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
                    properties={"source_id": evidence.source_id},
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
            source_edge_id = f"evidence-source:{evidence_id}:{evidence.source_id}"
            edges.setdefault(
                source_edge_id,
                PanoramicGraphEdge(
                    id=source_edge_id,
                    source_id=evidence_id,
                    target_id=evidence.source_id,
                    type="excerpt-of",
                    label="摘录自",
                    confidence=evidence.confidence,
                    evidence_ids=[evidence_id],
                ),
            )

    @staticmethod
    def _add_aggregate_edges(
        edges: dict[str, PanoramicGraphEdge],
        actor_edges: list[PanoramicGraphEdge],
        flow_context_paths: dict[str, dict[str, tuple[str, str]]],
    ) -> None:
        for flow_id, entity_paths in flow_context_paths.items():
            for entity_id, (membership_id, context_id) in entity_paths.items():
                aggregate_id = f"aggregate:flow-entity:{flow_id}:{entity_id}"
                edges[aggregate_id] = PanoramicGraphEdge(
                    id=aggregate_id,
                    source_id=flow_id,
                    target_id=entity_id,
                    type="aggregated-related",
                    label="攻击流相关实体",
                    confidence=min(
                        edges[membership_id].confidence,
                        edges[context_id].confidence,
                    ),
                    aggregate=True,
                    evidence_ids=edges[context_id].evidence_ids,
                    explanation=PanoramicGraphExplanation(
                        node_ids=[
                            flow_id,
                            edges[membership_id].target_id,
                            entity_id,
                        ],
                        edge_ids=[membership_id, context_id],
                    ),
                )

        for actor_edge in actor_edges:
            flow_id = actor_edge.target_id
            for entity_id, (membership_id, context_id) in flow_context_paths.get(
                flow_id, {}
            ).items():
                aggregate_id = (
                    f"aggregate:actor-entity:{actor_edge.source_id}:{entity_id}"
                )
                edges.setdefault(
                    aggregate_id,
                    PanoramicGraphEdge(
                        id=aggregate_id,
                        source_id=actor_edge.source_id,
                        target_id=entity_id,
                        type="aggregated-related",
                        label="组织相关 IOC / 上下文",
                        confidence=min(
                            actor_edge.confidence,
                            edges[membership_id].confidence,
                            edges[context_id].confidence,
                        ),
                        aggregate=True,
                        evidence_ids=list(
                            dict.fromkeys(
                                actor_edge.evidence_ids
                                + edges[context_id].evidence_ids
                            )
                        ),
                        explanation=PanoramicGraphExplanation(
                            node_ids=[
                                actor_edge.source_id,
                                flow_id,
                                edges[membership_id].target_id,
                                entity_id,
                            ],
                            edge_ids=[actor_edge.id, membership_id, context_id],
                        ),
                    ),
                )
