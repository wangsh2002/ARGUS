import type {
  Entity,
  GraphEdge,
  GraphNode,
  PanoramicGraphIndex,
  PanoramicGraphIndexNode,
  PanoramicGraphNeighborhood,
} from "./types";


async function requestJson<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    headers: { accept: "application/json" },
    cache: "no-store",
  });
  const payload = (await response.json()) as T & {
    error?: { message?: string };
  };
  if (!response.ok) {
    throw new Error(payload.error?.message || `图谱后端返回 ${response.status}。`);
  }
  return payload;
}


export function requestPanoramicGraphIndex() {
  return requestJson<PanoramicGraphIndex>("/api/graph/nodes");
}


export function requestPanoramicGraphNeighborhood(nodeId: string) {
  return requestJson<PanoramicGraphNeighborhood>(
    `/api/graph/neighborhoods/${encodeURIComponent(nodeId)}?depth=3&limit=128`,
  );
}


export function panoramicIndexNodeToEntity(
  node: PanoramicGraphIndexNode,
): Entity {
  return {
    id: node.id,
    entity_type: node.type,
    canonical_key: node.id,
    label: node.label,
    normalized_value:
      typeof node.properties.normalized_value === "string"
        ? node.properties.normalized_value
        : node.label.toLocaleLowerCase(),
    description: node.description,
    first_seen: null,
    last_seen: null,
    source_count: node.evidence_count,
    properties: {
      ...node.properties,
      runtime_kind: node.kind,
      confidence: node.confidence,
    },
  };
}


function edgeCategory(type: string, aggregate: boolean) {
  if (aggregate) return "association";
  if (["contains-action", "precedes", "leads_to", "enables", "causes", "on_success", "on_failure"].includes(type)) {
    return "chain";
  }
  if (["supported-by-source", "supported-by-evidence", "excerpt-of"].includes(type)) {
    return "evidence";
  }
  if (type === "reported-actor") return "attribution";
  if (type === "action-context") return "context";
  return "association";
}


export function adaptPanoramicNeighborhood(
  neighborhood: PanoramicGraphNeighborhood,
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodeById = new Map(neighborhood.nodes.map((node) => [node.id, node]));
  const nodes = neighborhood.nodes.map<GraphNode>((node) => ({
    id: node.id,
    label: node.label,
    type: node.type,
    confidence: node.confidence,
    status: node.kind === "evidence" ? "positive" : undefined,
    description: node.description,
    properties: node.properties,
    historicalPathId:
      node.kind === "attack-flow"
        ? node.id
        : node.kind === "action" && typeof node.properties.flow_id === "string"
          ? node.properties.flow_id
          : undefined,
  }));
  const edges = neighborhood.edges.map<GraphEdge>((edge) => {
    const evidence = edge.evidence_ids.flatMap((evidenceId) => {
      const evidence = nodeById.get(evidenceId);
      if (!evidence) return [];
      const sourceId =
        typeof evidence.properties.source_id === "string"
          ? evidence.properties.source_id
          : undefined;
      const source = sourceId ? nodeById.get(sourceId) : undefined;
      return [{
        id: evidence.id,
        relationship_id: edge.id,
        report_id: sourceId ?? "",
        source_ref: sourceId ?? "",
        excerpt: evidence.description,
        location: evidence.label.replace(/^证据\s*·\s*/, ""),
        confidence: evidence.confidence,
        report_title: source?.label ?? "来源报告",
        publisher: source?.description ?? "",
        report_date:
          typeof source?.properties.published_at === "string"
            ? source.properties.published_at
            : "",
        canonical_url:
          typeof source?.properties.canonical_url === "string"
            ? source.properties.canonical_url
            : undefined,
      }];
    });
    return {
      id: edge.id,
      source: edge.source_id,
      target: edge.target_id,
      label: edge.label,
      category: edgeCategory(edge.type, edge.aggregate),
      status: edge.aggregate ? "partial" : "positive",
      confidence: edge.confidence,
      aggregate: edge.aggregate,
      evidence,
      explanation: edge.explanation
        ? {
            nodeIds: edge.explanation.node_ids,
            edgeIds: edge.explanation.edge_ids,
          }
        : undefined,
    };
  });
  return { nodes, edges };
}
