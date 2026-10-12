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
  return requestJson<PanoramicGraphIndex>("/api/graph/nodes").then((index) => {
    const evidenceNodeCount = Math.max(
      index.evidence_node_count ?? index.node_count - index.nodes.length,
      0,
    );
    const nodes = index.nodes.filter(
      (node) => node.kind !== "attack-flow" && node.kind !== "source",
    );
    return {
      ...index,
      nodes,
      node_count: nodes.length,
      evidence_node_count: evidenceNodeCount,
    };
  });
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

function graphEdgeLabel(type: string, label: string) {
  const normalized = label.trim().toLocaleLowerCase();
  return ({
    uses: "使用",
    "communicates-with": "通信",
    "downloads-from": "下载自",
    "drops-on": "投放至",
    exploits: "利用",
    enables: "促成",
    leads_to: "推进至",
    precedes: "先于",
    on_failure: "失败分支",
    on_success: "成功分支",
    "reported-actor": "报告归因",
  } as Record<string, string>)[normalized] ??
    ({
      leads_to: "推进至",
      precedes: "先于",
      enables: "促成",
      on_failure: "失败分支",
      on_success: "成功分支",
    } as Record<string, string>)[type] ??
    label;
}


export function adaptPanoramicNeighborhood(
  neighborhood: PanoramicGraphNeighborhood,
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodeById = new Map(neighborhood.nodes.map((node) => [node.id, node]));
  const visibleNodes = neighborhood.nodes.filter(
    (node) =>
      node.kind !== "attack-flow" &&
      node.kind !== "source" &&
      node.kind !== "evidence",
  );
  const visibleNodeIds = new Set(visibleNodes.map((node) => node.id));
  const nodes = visibleNodes.map<GraphNode>((node) => ({
    id: node.id,
    label: node.label,
    type: node.type,
    confidence: node.confidence,
    status: node.kind === "evidence" ? "positive" : undefined,
    description: node.description,
    properties: node.properties,
    historicalPathId:
      node.kind === "action" && typeof node.properties.flow_id === "string"
        ? node.properties.flow_id
        : undefined,
  }));
  const edges = neighborhood.edges
    .filter(
      (edge) =>
        visibleNodeIds.has(edge.source_id) &&
        visibleNodeIds.has(edge.target_id) &&
        !["contains-action", "supported-by-source", "excerpt-of"].includes(
          edge.type,
        ),
    )
    .map<GraphEdge>((edge) => {
    const evidence = edge.evidence?.length
      ? edge.evidence.map((item) => {
          const sourceSpan = nodeById.get(item.source_span_id);
          return {
            id: item.id,
            relationship_id: edge.id,
            report_id: item.source_id,
            source_ref: item.source_id,
            excerpt: item.quote,
            location: item.locator,
            confidence: item.confidence,
            report_title: item.title,
            publisher: item.publisher,
            report_date:
              typeof sourceSpan?.properties.published_at === "string"
                ? sourceSpan.properties.published_at
                : "",
            canonical_url: item.canonical_url || undefined,
          };
        })
      : edge.evidence_ids.flatMap((evidenceId) => {
      const evidenceNode = nodeById.get(evidenceId);
      if (!evidenceNode) return [];
      const sourceId =
        typeof evidenceNode.properties.source_id === "string"
          ? evidenceNode.properties.source_id
          : undefined;
      return [{
        id: evidenceNode.id,
        relationship_id: edge.id,
        report_id: sourceId ?? "",
        source_ref: sourceId ?? "",
        excerpt: evidenceNode.description,
        location: evidenceNode.label.replace(/^证据\s*·\s*/, ""),
        confidence: evidenceNode.confidence,
        report_title:
          typeof evidenceNode.properties.source_title === "string"
            ? evidenceNode.properties.source_title
            : "来源报告",
        publisher:
          typeof evidenceNode.properties.publisher === "string"
            ? evidenceNode.properties.publisher
            : "",
        report_date:
          typeof evidenceNode.properties.published_at === "string"
            ? evidenceNode.properties.published_at
            : "",
        canonical_url:
          typeof evidenceNode.properties.canonical_url === "string"
            ? evidenceNode.properties.canonical_url
            : undefined,
      }];
    });
    return {
      id: edge.id,
      source: edge.source_id,
      target: edge.target_id,
      label: graphEdgeLabel(edge.type, edge.label),
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
