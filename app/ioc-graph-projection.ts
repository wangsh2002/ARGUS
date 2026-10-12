import type { GraphEdge, GraphNode } from "./types";

export const HIGH_CARDINALITY_IOC_THRESHOLD = 7;

export type IocCollectionMember = {
  id: string;
  label: string;
  contextType: string;
  observableKind: string;
  confidence: number;
  evidenceCount: number;
};

export type CompactIocGraph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  rootIds: string[];
};

function inferredObservableKind(label: string, contextType: string) {
  const value = label.trim();
  if (/^https?:\/\//i.test(value)) return "URL";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "邮箱";
  if (/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(value)) return "IP";
  if (/^[a-f\d]{32}$|^[a-f\d]{40}$|^[a-f\d]{64}$/i.test(value)) return "文件哈希";
  if (/^(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,}$/i.test(value)) {
    return "域名";
  }
  return (
    {
      infrastructure: "基础设施",
      domain: "域名",
      url: "URL",
      ip: "IP",
      hash: "文件哈希",
      file: "文件",
      process: "进程",
      account: "账号",
      other: "其他",
    }[contextType] ?? "IOC"
  );
}

function collectionLabel() {
  return "报告关联 IOC 集合";
}

function collectionId(actionId: string, role: string) {
  const normalizedRole = role
    .normalize("NFKC")
    .replace(/[^\p{L}\p{N}]+/gu, "-")
    .replace(/^-|-$/g, "")
    .toLocaleLowerCase();
  return `ioc-collection:${actionId}:${normalizedRole || "related"}`;
}

export function iocCollectionMembers(node?: GraphNode): IocCollectionMember[] {
  if (node?.type !== "IOC 集合") return [];
  const members = node.properties?.members;
  if (!Array.isArray(members)) return [];
  return members.filter(
    (member): member is IocCollectionMember =>
      Boolean(
        member &&
          typeof member === "object" &&
          "id" in member &&
          typeof member.id === "string" &&
          "label" in member &&
          typeof member.label === "string",
      ),
  );
}

export function compactHighCardinalityIocs(
  nodes: GraphNode[],
  edges: GraphEdge[],
  rootIds: string[],
  threshold = HIGH_CARDINALITY_IOC_THRESHOLD,
): CompactIocGraph {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const groups = new Map<
    string,
    { actionId: string; role: string; items: Array<{ node: GraphNode; edge: GraphEdge }> }
  >();

  edges.forEach((edge) => {
    if (!["行为上下文", "context"].includes(edge.category ?? "")) return;
    const source = nodeById.get(edge.source);
    const target = nodeById.get(edge.target);
    const iocNode =
      source?.type === "IOC/基础设施"
        ? source
        : target?.type === "IOC/基础设施"
          ? target
          : undefined;
    const actionNode =
      source?.type === "攻击步骤"
        ? source
        : target?.type === "攻击步骤"
          ? target
          : undefined;
    if (!iocNode || !actionNode) return;
    const key = `${actionNode.id}\u001f${edge.label}`;
    const group = groups.get(key) ?? {
      actionId: actionNode.id,
      role: edge.label,
      items: [],
    };
    group.items.push({ node: iocNode, edge });
    groups.set(key, group);
  });

  const compactGroups = [...groups.values()].filter(
    (group) =>
      group.items.length >= threshold &&
      !group.items.some(
        ({ node }) => rootIds.length === 1 && rootIds.includes(node.id),
      ),
  );
  if (!compactGroups.length) return { nodes, edges, rootIds };

  const removedNodeIds = new Set<string>();
  const removedEdgeIds = new Set<string>();
  const memberToCollection = new Map<string, string>();
  const collectionNodes: GraphNode[] = [];
  const collectionEdges: GraphEdge[] = [];

  compactGroups.forEach((group) => {
    const id = collectionId(group.actionId, group.role);
    const members = group.items
      .map(({ node, edge }) => {
        const contextType =
          typeof node.entity?.properties.context_type === "string"
            ? node.entity.properties.context_type
            : "other";
        return {
          id: node.id,
          label: node.label,
          contextType,
          observableKind: inferredObservableKind(node.label, contextType),
          confidence: node.confidence ?? 0,
          evidenceCount: edge.evidence?.length ?? node.entity?.source_count ?? 0,
        };
      })
      .sort(
        (left, right) =>
          right.evidenceCount - left.evidenceCount ||
          right.confidence - left.confidence ||
          left.label.localeCompare(right.label),
      );
    const averageConfidence =
      members.reduce((sum, member) => sum + member.confidence, 0) /
      members.length;
    const evidenceCount = new Set(
      group.items.flatMap(({ edge }) =>
        (edge.evidence ?? []).map((evidence) => evidence.id),
      ),
    ).size;
    const evidence = [
      ...new Map(
        group.items
          .flatMap(({ edge }) => edge.evidence ?? [])
          .map((item) => [item.id, item]),
      ).values(),
    ];
    const label = collectionLabel();

    group.items.forEach(({ node, edge }) => {
      removedNodeIds.add(node.id);
      removedEdgeIds.add(edge.id);
      memberToCollection.set(node.id, id);
    });
    collectionNodes.push({
      id,
      label,
      type: "IOC 集合",
      status: "partial",
      confidence: averageConfidence,
      virtual: true,
      description: `抽取结果将 ${members.length} 个 IOC 关联到同一攻击步骤，原始角色统一标注为“${group.role}”。为避免过度断言，图中按报告关联集合展示；每个对象、原始角色与来源证据仍完整保留。`,
      properties: {
        member_count: members.length,
        evidence_count: evidenceCount,
        collection_role: group.role,
        members,
      },
    });
    const firstEdge = group.items[0].edge;
    const entityToAction = firstEdge.target === group.actionId;
    collectionEdges.push({
      id: `${id}:edge`,
      source: entityToAction ? id : group.actionId,
      target: entityToAction ? group.actionId : id,
      label: `报告关联 · ${members.length} 个 IOC`,
      category: firstEdge.category ?? "context",
      status: "partial",
      confidence: averageConfidence,
      aggregate: true,
      evidence,
    });
  });

  const nextNodes = [
    ...nodes.filter((node) => !removedNodeIds.has(node.id)),
    ...collectionNodes,
  ];
  const nextNodeIds = new Set(nextNodes.map((node) => node.id));
  const nextEdges = [
    ...edges.filter(
      (edge) =>
        !removedEdgeIds.has(edge.id) &&
        nextNodeIds.has(edge.source) &&
        nextNodeIds.has(edge.target),
    ),
    ...collectionEdges,
  ];
  const nextRootIds = [
    ...new Set(
      rootIds
        .map((id) => memberToCollection.get(id) ?? id)
        .filter((id) => nextNodeIds.has(id)),
    ),
  ];

  return { nodes: nextNodes, edges: nextEdges, rootIds: nextRootIds };
}
