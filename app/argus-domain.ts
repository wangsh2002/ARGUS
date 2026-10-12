import type {
  AdviceItem,
  ChainLink,
  ChainStep,
  Entity,
  GraphEdge,
  GraphNode,
  InvestigationCase,
  PathCandidate,
  Report,
  Relationship,
  SearchResult,
  Snapshot,
  SourceCitation,
} from "./types";

export function propString(entity: Entity, key: string) {
  const value = entity.properties[key];
  return typeof value === "string" ? value : "";
}

export function propNumber(entity: Entity, key: string, fallback = 0.7) {
  const value = entity.properties[key];
  return typeof value === "number" ? value : fallback;
}

function normalize(value: string) {
  return value.trim().toLocaleLowerCase().replace(/\s+/g, " ");
}

export function formatDate(value?: string | null) {
  if (!value) return "时间未记录";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

export function detectQueryType(query: string) {
  const trimmed = query.trim();
  if (getChainParts(trimmed).length >= 3) return "攻击链";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return "IPv4";
  if (/^[a-f0-9]{32,64}$/i.test(trimmed)) return "文件哈希";
  if (/^cve-\d{4}-\d+$/i.test(trimmed)) return "CVE";
  if (/^(?:https?:\/\/)?(?:[\w-]+\.)+[a-z]{2,}(?:\/\S*)?$/i.test(trimmed)) {
    return trimmed.includes("/") ? "URL" : "域名";
  }
  return "自然语言";
}

export function getChainParts(query: string) {
  let pathSource = query;
  let structuredSignals: string[] = [];
  const trimmed = query.trim();
  if (trimmed.startsWith("{")) {
    try {
      const payload = JSON.parse(trimmed) as Record<string, unknown>;
      if (typeof payload.query_path === "string") {
        pathSource = payload.query_path;
      } else if (Array.isArray(payload.signals)) {
        structuredSignals = payload.signals
          .map((signal) => {
            if (typeof signal === "string") return signal;
            if (!signal || typeof signal !== "object") return "";
            const record = signal as Record<string, unknown>;
            return ["raw_signal", "observed_value", "summary", "value"]
              .map((key) => record[key])
              .find((value): value is string => typeof value === "string") ?? "";
          })
          .filter((signal) => signal.length > 1);
      }
    } catch {
      // Keep free-text parsing when an uploaded JSON fragment is incomplete.
    }
  }
  if (structuredSignals.length) return structuredSignals;
  return pathSource
    .split(/\s*(?:→|->|=>|＞|然后|再到)\s*|\n+/)
    .map((part) => part.replace(/^[\d.、\s]+/, "").trim())
    .filter((part) => part.length > 1);
}

function entityHaystack(entity: Entity, aliases: string[] = []) {
  return normalize(
    [
      entity.label,
      entity.normalized_value,
      entity.description,
      propString(entity, "entity_value"),
      propString(entity, "sub"),
      propString(entity, "actor"),
      propString(entity, "event"),
      ...aliases,
    ].join(" "),
  );
}

function pathPartMatchScore(entity: Entity, part: string) {
  const query = normalize(part);
  const label = normalize(entity.label);
  const value = normalize(propString(entity, "entity_value"));
  const normalizedValue = normalize(entity.normalized_value);
  const haystack = entityHaystack(entity);
  const semantic = (text: string) =>
    normalize(text)
      .replace(/\b(?:cli|cmd|powershell)\b/g, " ")
      .replace(/[系统设备主机终端]/g, "")
      .replace(/\s+/g, " ")
      .trim();
  let score = 0;
  if (label === query || value === query || normalizedValue === query) {
    score = 110;
  } else if (label.includes(query) || query.includes(label)) {
    score = 92;
  } else if (haystack.includes(query)) {
    score = 78;
  } else {
    const semanticQuery = semantic(query);
    if (
      semanticQuery.length >= 4 &&
      semantic(haystack).includes(semanticQuery)
    ) {
      score = 70;
    }
  }
  if (score && entity.entity_type === "攻击步骤") score += 12;
  return score;
}

type SearchKnowledge = Pick<Snapshot, "entities" | "aliases" | "reports">;

export function exactReportMatch(reports: Report[], query: string) {
  const normalizedQuery = normalize(query);
  return reports.find((report) => normalize(report.title) === normalizedQuery);
}

function matchCoherentPathEntities(data: SearchKnowledge, parts: string[]) {
  const candidatesByPart = parts.map((part) =>
    data.entities
      .map((entity) => ({
        entity,
        score: pathPartMatchScore(entity, part),
      }))
      .filter(
        (candidate) =>
          candidate.score > 0 && candidate.entity.entity_type === "攻击步骤",
      )
      .sort(
        (left, right) =>
          right.score - left.score ||
          right.entity.source_count - left.entity.source_count,
      ),
  );
  const events = new Set(
    candidatesByPart.flatMap((candidates) =>
      candidates
        .map(({ entity }) => propString(entity, "event"))
        .filter(Boolean),
    ),
  );
  const selectedEvent = [...events]
    .map((event) => {
      const bestByPart = candidatesByPart.map(
        (candidates) =>
          candidates.find(
            ({ entity }) => propString(entity, "event") === event,
          )?.score ?? 0,
      );
      return {
        event,
        coverage: bestByPart.filter(Boolean).length,
        score: bestByPart.reduce((sum, value) => sum + value, 0),
      };
    })
    .sort(
      (left, right) =>
        right.coverage - left.coverage || right.score - left.score,
    )[0]?.event;

  return candidatesByPart.map((candidates, index) => {
    const coherent = selectedEvent
      ? candidates.find(
          ({ entity }) => propString(entity, "event") === selectedEvent,
        )?.entity
      : undefined;
    return (
      coherent ??
      candidates[0]?.entity ??
      searchSnapshot(data, parts[index]).entities[0]?.entity
    );
  });
}

export function searchSnapshot(data: SearchKnowledge, query: string): SearchResult {
  const q = normalize(query);
  const chainParts = getChainParts(query).map(normalize);
  const aliasesByEntity = data.aliases.reduce((index, item) => {
    const current = index.get(item.entity_id) ?? [];
    current.push(item.alias);
    index.set(item.entity_id, current);
    return index;
  }, new Map<string, string[]>());
  const entities = data.entities
    .map((entity) => {
      const haystack = entityHaystack(
        entity,
        aliasesByEntity.get(entity.id),
      );
      const label = normalize(entity.label);
      const value = normalize(propString(entity, "entity_value"));
      let score = 0;
      if (label === q || value === q || normalize(entity.normalized_value) === q) score = 100;
      else if (q.includes(label) && label.length >= 3) score = 82;
      else if (haystack.includes(q) && q.length >= 3) score = 68;
      chainParts.forEach((part) => {
        if (label === part || value === part) score = Math.max(score, 96);
        else if (part.length >= 3 && haystack.includes(part)) score = Math.max(score, 78);
      });
      q.split(/[\s，。；、?？]+/)
        .filter((token) => token.length >= 3)
        .forEach((token) => {
          if (haystack.includes(token)) score += 12;
        });
      return { entity, score: Math.min(100, score) };
    })
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score || b.entity.source_count - a.entity.source_count);

  const reports = data.reports
    .map((report) => {
      const title = normalize(report.title);
      const haystack = normalize(
        `${report.title} ${report.source} ${report.extracted_text} ${report.assessment}`,
      );
      let score =
        title === q
          ? 100
          : title.includes(q) && q.length >= 3
            ? 84
            : haystack.includes(q) && q.length >= 3
              ? 60
              : 0;
      entities.slice(0, 10).forEach(({ entity }) => {
        if (haystack.includes(normalize(entity.label))) score += 5;
      });
      return { report, score: Math.min(100, score) };
    })
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score);

  return { queryType: detectQueryType(query), entities, reports };
}

function entityToNode(entity: Entity): GraphNode {
  return {
    id: entity.id,
    label: entity.label,
    type: entity.entity_type,
    status: propString(entity, "status") || "positive",
    confidence: propNumber(entity, "confidence"),
    entity,
  };
}

/**
 * Reports are provenance, not topology.  They belong in the evidence panel
 * and must never be rendered as attack-knowledge nodes.  The second guard
 * keeps accidental sentence extraction out of the canvas while preserving
 * long hashes, URLs and other legitimate IOC values.
 */
export function isGraphEntity(entity: Entity) {
  if (entity.entity_type === "情报报告") return false;
  if (
    entity.entity_type === "攻击步骤" &&
    (entity.label.length > 28 ||
      /[。！？；]/u.test(entity.label) ||
      (entity.label.length > 20 && /[,，:：]/u.test(entity.label)))
  ) {
    return false;
  }
  return true;
}

/**
 * "报告提及" is an indexing edge used to find source documents.  It is not
 * evidence that two attack entities participate in the same activity.
 */
export function isGraphRelationship(
  relationship: Relationship,
  entityMap?: Map<string, Entity>,
) {
  if (relationship.relation_type === "报告提及") return false;
  if (!entityMap) return true;
  const source = entityMap.get(relationship.source_entity_id);
  const target = entityMap.get(relationship.target_entity_id);
  return Boolean(source && target && isGraphEntity(source) && isGraphEntity(target));
}

const pathEdgeLabels: Record<string, string> = {
  sequence: "随后发生",
  precedes: "有证据先于",
  leads_to: "推进至",
  enables: "使后续行为成为可能",
  causes: "直接触发",
  on_success: "成功后进入",
  on_failure: "失败后进入",
  conditional: "条件触发",
  branch: "形成分支",
  merge: "汇入主路径",
};

const contextRoleLabels: Record<string, string> = {
  uses: "使用",
  targets: "作用于目标",
  "communicates-with": "连接基础设施",
  exploits: "利用漏洞",
  "downloads-from": "从其下载",
  "drops-on": "释放到",
  "runs-on": "运行于",
  modifies: "修改",
  creates: "创建",
  other: "关联上下文",
  "connects-to": "连接基础设施",
  "exfiltrates-to": "向其外传",
  "uses-malware": "使用恶意软件",
  "mapped-to-technique": "映射技战术",
  "exploits-vulnerability": "利用漏洞",
  "executes-file": "执行文件",
  "targets-asset": "作用于资产",
};

function recordString(
  record: Record<string, unknown>,
  key: string,
  fallback = "",
) {
  const value = record[key];
  return typeof value === "string" ? value : fallback;
}

function recordNumber(
  record: Record<string, unknown>,
  key: string,
  fallback = 0,
) {
  const value = record[key];
  return typeof value === "number" ? value : fallback;
}

function analysisStatus(assertionOrigin: string) {
  if (assertionOrigin === "algorithm-predicted") return "predicted";
  if (assertionOrigin === "algorithm-reconstructed") return "partial";
  return "positive";
}

export function buildSubgraph(
  data: Pick<Snapshot, "entities" | "relationships" | "historicalPaths">,
  seedIds: string[],
  limit = 28,
  allowedCategories?: Set<string>,
  maxDepth = 2,
) {
  const entityMap = new Map(data.entities.map((entity) => [entity.id, entity]));
  const graphRelationships = data.relationships.filter((relationship) =>
    isGraphRelationship(relationship, entityMap),
  );
  const selected = new Set(
    seedIds.filter((id) => {
      const entity = entityMap.get(id);
      return Boolean(entity && isGraphEntity(entity));
    }),
  );
  const queue = [...selected].map((id) => ({ id, depth: 0 }));
  while (queue.length && selected.size < limit) {
    const current = queue.shift();
    if (!current || current.depth >= maxDepth) continue;
    const adjacent = graphRelationships
      .filter(
        (edge) =>
          (!allowedCategories || allowedCategories.has(edge.category)) &&
          (edge.source_entity_id === current.id || edge.target_entity_id === current.id),
      )
      .sort((a, b) => b.confidence - a.confidence);
    for (const edge of adjacent) {
      const next =
        edge.source_entity_id === current.id ? edge.target_entity_id : edge.source_entity_id;
      if (!selected.has(next) && entityMap.has(next)) {
        selected.add(next);
        queue.push({ id: next, depth: current.depth + 1 });
      }
      if (selected.size >= limit) break;
    }
  }

  const pathNodes = new Map<string, GraphNode>();
  const pathEdges = new Map<string, GraphEdge>();
  const seedIdSet = new Set(seedIds);
  const matchingPaths = data.historicalPaths
    .map((path) => ({
      path,
      seedLinks: path.contextLinks.filter((link) =>
        seedIdSet.has(link.entity_id),
      ),
    }))
    .filter(({ seedLinks }) => seedLinks.length > 0)
    .sort(
      (left, right) =>
        right.path.confidence - left.path.confidence ||
        left.path.id.localeCompare(right.path.id),
    );

  matchingPaths.forEach(({ path, seedLinks }) => {
    if (selected.size + pathNodes.size >= limit) return;
    const nodeById = new Map(
      path.nodes.map((node) => [recordString(node, "id"), node]),
    );
    const orderedNodeIds = [
      ...(path.projection?.mainline_action_refs ?? []),
      ...[...path.nodes]
        .sort(
          (left, right) =>
            recordNumber(left, "sequence_hint") -
            recordNumber(right, "sequence_hint"),
        )
        .map((node) => recordString(node, "id")),
    ].filter(
      (id, index, ids) =>
        Boolean(id) && ids.indexOf(id) === index && nodeById.has(id),
    );
    const focusActionIds = new Set(
      seedLinks.map((link) => link.action_node_id),
    );
    orderedNodeIds.sort(
      (left, right) =>
        Number(focusActionIds.has(right)) -
        Number(focusActionIds.has(left)),
    );

    orderedNodeIds.forEach((id) => {
      if (selected.size + pathNodes.size >= limit) return;
      const node = nodeById.get(id);
      if (!node || pathNodes.has(id)) return;
      const assertionOrigin = recordString(
        node,
        "assertion_origin",
        "source-observed",
      );
      pathNodes.set(id, {
        id,
        label: recordString(node, "label", "未命名攻击行为"),
        type: "攻击步骤",
        status: analysisStatus(assertionOrigin),
        confidence: recordNumber(node, "confidence", path.confidence),
        virtual: true,
        historicalPathId: path.id,
      });
    });

    [...path.contextLinks]
      .sort(
        (left, right) =>
          Number(seedIdSet.has(right.entity_id)) -
          Number(seedIdSet.has(left.entity_id)),
      )
      .forEach((link) => {
        if (!pathNodes.has(link.action_node_id)) return;
        const entity = entityMap.get(link.entity_id);
        if (
          !entity ||
          !isGraphEntity(entity) ||
          selected.size + pathNodes.size >= limit
        ) {
          return;
        }
        selected.add(entity.id);
      });

    path.edges.forEach((edge) => {
      const id = recordString(edge, "id");
      const source = recordString(edge, "source_node_id");
      const target = recordString(edge, "target_node_id");
      if (
        !id ||
        !pathNodes.has(source) ||
        !pathNodes.has(target) ||
        pathEdges.has(id)
      ) {
        return;
      }
      const assertionOrigin = recordString(
        edge,
        "assertion_origin",
        "source-observed",
      );
      const edgeType = recordString(edge, "edge_type", "sequence");
      pathEdges.set(id, {
        id,
        source,
        target,
        label: pathEdgeLabels[edgeType] ?? edgeType,
        category: "chain",
        status: analysisStatus(assertionOrigin),
        confidence: recordNumber(edge, "confidence", path.confidence),
        historicalPathId: path.id,
      });
    });

    path.contextLinks.forEach((link) => {
      if (
        !pathNodes.has(link.action_node_id) ||
        !selected.has(link.entity_id)
      ) {
        return;
      }
      const actionToEntity = link.direction === "action-to-entity";
      pathEdges.set(link.id, {
        id: link.id,
        source: actionToEntity ? link.action_node_id : link.entity_id,
        target: actionToEntity ? link.entity_id : link.action_node_id,
        label: contextRoleLabels[link.role] ?? link.role,
        category: "context",
        status: analysisStatus(link.assertion_origin),
        confidence: link.confidence,
        historicalPathId: path.id,
      });
    });
  });

  const nodes = [
    ...[...selected]
      .map((id) => entityMap.get(id))
      .filter((entity): entity is Entity => Boolean(entity))
      .map(entityToNode),
    ...pathNodes.values(),
  ];
  const edges: GraphEdge[] = [
    ...data.relationships
    .filter(
      (edge) =>
        isGraphRelationship(edge, entityMap) &&
        selected.has(edge.source_entity_id) &&
        selected.has(edge.target_entity_id) &&
        (!allowedCategories || allowedCategories.has(edge.category)),
    )
    .map((edge) => ({
      id: edge.id,
      source: edge.source_entity_id,
      target: edge.target_entity_id,
      label: edge.relation_type,
      category: edge.category,
      status: edge.status,
      confidence: edge.confidence,
      relationship: edge,
    })),
    ...pathEdges.values(),
  ];
  return { nodes, edges };
}

export function historicalPathCandidate(
  path: Snapshot["historicalPaths"][number],
): PathCandidate {
  const sortedNodes = [...path.nodes].sort(
    (left, right) =>
      recordNumber(left, "sequence_hint") -
      recordNumber(right, "sequence_hint"),
  );
  const stepIds = new Map(
    sortedNodes.map((node) => [
      recordString(node, "id"),
      `historical-path-step-${recordString(node, "id")}`,
    ]),
  );
  const contextIdsByAction = new Map<string, string[]>();
  path.contextLinks.forEach((link) => {
    const current = contextIdsByAction.get(link.action_node_id) ?? [];
    contextIdsByAction.set(link.action_node_id, [
      ...current,
      link.entity_id,
    ]);
  });
  return {
    id: `historical-path-${path.id}`,
    historicalPathId: path.id,
    title: path.name,
    summary: path.description,
    reason: "节点与关系均来自已归档原始报告，并保留逐节点、逐关系证据定位。",
    gap: path.nodes.some(
      (node) =>
        typeof node.properties === "object" &&
        node.properties &&
        "known_gap" in node.properties &&
        Boolean(node.properties.known_gap),
    )
      ? "原始报告存在明确缺口；系统不为缺失入口或中间步骤编造事实。"
      : "当前路径按原报告复原，仍需结合本地遥测确认是否命中当前环境。",
    confidence: path.confidence,
    sourceCount: path.primary_artifact_id ? 1 : 0,
    disposition: "primary",
    knowledgeSnapshot: "published-attack-flow",
    extractionMethod: "reviewed-flow-publication",
    analysisQuery: sortedNodes
      .map((node) => recordString(node, "label"))
      .join(" → "),
    steps: sortedNodes.map((node) => ({
      id: stepIds.get(recordString(node, "id")) as string,
      pathNodeId: recordString(node, "id"),
      entityId:
        typeof node.entity_id === "string" ? node.entity_id : undefined,
      contextEntityIds:
        contextIdsByAction.get(recordString(node, "id")) ?? [],
      label: recordString(node, "label", "未命名行为"),
      description:
        typeof node.properties === "object" &&
        node.properties &&
        "description" in node.properties
          ? String(node.properties.description)
          : path.description,
      phase: recordString(node, "phase", "待研判"),
      analysisState: "observed",
      confidence: recordNumber(node, "confidence", path.confidence),
      evidenceCount: path.evidence.filter(
        (item) => item.node_id === node.id,
      ).length,
    })),
    links: path.edges.flatMap((edge) => {
      const sourceStepId = stepIds.get(
        recordString(edge, "source_node_id"),
      );
      const targetStepId = stepIds.get(
        recordString(edge, "target_node_id"),
      );
      if (!sourceStepId || !targetStepId) return [];
      return [
        {
          id: `historical-path-edge-${recordString(edge, "id")}`,
          sourceStepId,
          targetStepId,
          label:
            recordString(edge, "condition_label") ||
            pathEdgeLabels[recordString(edge, "edge_type")] ||
            "存在过程依赖",
          reviewStatus: "observed" as const,
          confidence: recordNumber(
            edge,
            "confidence",
            path.confidence,
          ),
        },
      ];
    }),
  };
}

function stepIndex(entity: Entity) {
  const sub = propString(entity, "sub");
  const match = sub.match(/第\s*(\d+)\s*步/);
  if (match) return Number(match[1]);
  const suffix = entity.id.match(/step-(\d+)$/);
  return suffix ? Number(suffix[1]) + 1 : 999;
}

function phaseFor(entity: Entity) {
  const text = normalize(`${entity.label} ${entity.description} ${propString(entity, "sub")}`);
  if (/钓鱼|诱饵|投递|漏洞|cve|初始|community|string|snmp/.test(text)) return "初始访问";
  if (/执行|脚本|命令|powershell|加载/.test(text)) return "执行";
  if (/持久|后门|oauth|规则/.test(text)) return "持久化";
  if (/凭据|ntlm|口令|认证/.test(text)) return "凭据访问";
  if (/发现|枚举|收集|arp|mac|信息/.test(text)) return "发现";
  if (/横向|smb|远程/.test(text)) return "横向移动";
  if (/外传|tftp|泄露/.test(text)) return "数据外传";
  if (/回连|c2|通信|隧道/.test(text)) return "命令与控制";
  return "攻击活动";
}

function techniqueFor(data: Snapshot, entityId: string) {
  const edge = data.relationships.find(
    (relationship) =>
      relationship.source_entity_id === entityId && relationship.category === "technique",
  );
  if (!edge) return "";
  return data.entities.find((entity) => entity.id === edge.target_entity_id)?.label ?? "";
}

function relationshipBetween(data: Snapshot, source: string, target: string) {
  return data.relationships.find(
    (relationship) =>
      relationship.source_entity_id === source && relationship.target_entity_id === target,
  );
}

function eventForReport(
  data: Snapshot,
  report: Report,
  preferredEvent = "",
) {
  if (preferredEvent) {
    const preferred = data.entities.find(
      (entity) =>
        entity.entity_type === "历史事件" &&
        propString(entity, "event") === preferredEvent,
    );
    if (preferred) return preferred;
  }
  const exact = data.entities.find(
    (entity) =>
      entity.entity_type === "历史事件" &&
      [report.id, report.source_ref].includes(
        propString(entity, "source_ref"),
      ),
  );
  if (exact) return exact;
  return data.entities.find(
    (entity) =>
      entity.entity_type === "历史事件" &&
      normalize(report.extracted_text).includes(normalize(entity.label)),
  );
}

function getDefaultReport(data: Snapshot) {
  return (
    data.reports.find((report) => report.external_url && report.source_ref.includes("NCSC")) ??
    data.reports.find((report) => report.external_url) ??
    data.reports[0]
  );
}

function createCaseFromReport(
  data: Snapshot,
  reportId?: string,
  preferredEvent = "",
): InvestigationCase {
  const report = data.reports.find((item) => item.id === reportId) ?? getDefaultReport(data);
  const eventEntity = report
    ? eventForReport(data, report, preferredEvent)
    : undefined;
  const event = eventEntity ? propString(eventEntity, "event") || eventEntity.label : "";
  const actor = eventEntity ? propString(eventEntity, "actor") : "";
  let entities = data.entities
    .filter((entity) => entity.entity_type === "攻击步骤" && propString(entity, "event") === event)
    .sort((a, b) => stepIndex(a) - stepIndex(b));

  if (!entities.length && report && !eventEntity) {
    const haystack = normalize(report.extracted_text);
    entities = data.entities
      .filter(
        (entity) =>
          entity.entity_type === "攻击步骤" &&
          entity.label.length >= 3 &&
          haystack.includes(normalize(entity.label)),
      )
      .sort((a, b) => stepIndex(a) - stepIndex(b))
      .slice(0, 10);
  }

  if (!entities.length && !eventEntity) {
    entities = data.entities
      .filter((entity) => entity.entity_type === "攻击步骤")
      .sort((a, b) => propNumber(b, "confidence") - propNumber(a, "confidence"))
      .slice(0, 8);
  }

  const steps: ChainStep[] = entities.map((entity, index) => {
    const previous = entities[index - 1];
    const relation = previous ? relationshipBetween(data, previous.id, entity.id) : undefined;
    return {
      id: `step-${entity.id}`,
      entityId: entity.id,
      label: entity.label,
      type: entity.entity_type,
      relation: relation?.relation_type ?? (index ? "待确认关系" : "链路起点"),
      phase: phaseFor(entity),
      attackId: techniqueFor(data, entity.id) || undefined,
      occurredAt: entity.first_seen,
      confidence: propNumber(entity, "confidence"),
      evidenceCount: relation?.evidence_count ?? entity.source_count,
      status: propString(entity, "status") || "positive",
      origin: "database",
      reviewStatus: propString(entity, "status") === "negative" ? "candidate" : "matched",
      description: entity.description || propString(entity, "entity_value"),
    };
  });

  const links: ChainLink[] = steps.slice(1).map((step, index) => {
    const sourceEntityId = steps[index].entityId;
    const targetEntityId = step.entityId;
    const relationship =
      sourceEntityId && targetEntityId
        ? relationshipBetween(data, sourceEntityId, targetEntityId)
        : undefined;
    return {
      id: relationship?.id ?? `draft-link-${index}`,
      source: steps[index].id,
      target: step.id,
      label: relationship?.relation_type ?? "待确认关系",
      confidence: relationship?.confidence ?? Math.min(steps[index].confidence, step.confidence),
      status: relationship?.status ?? "partial",
      relationshipId: relationship?.id,
    };
  });

  const now = new Date().toISOString();
  return {
    id: `CASE-${event || "DRAFT"}-${Date.now().toString(36).toUpperCase()}`,
    title: eventEntity?.label ?? report?.title ?? "未命名攻击链调查",
    summary:
      report?.assessment ||
      eventEntity?.description ||
      "基于当前情报库生成的攻击链研判草稿，所有结论均需结合来源证据复核。",
    sourceKind: report ? "report" : "manual",
    sourceLabel: report?.title ?? "人工创建",
    actor: actor || undefined,
    event: event || undefined,
    createdAt: now,
    updatedAt: now,
    steps,
    links,
    notes: "",
    completedAdviceIds: [],
    version: 1,
  };
}

export function createCaseFromQuery(data: Snapshot, query: string): InvestigationCase {
  const parts = getChainParts(query);
  if (parts.length < 2) {
    const result = searchSnapshot(data, query);
    const matchedEntity = result.entities[0]?.entity;
    const matchedEvent = matchedEntity
      ? propString(matchedEntity, "event")
      : "";
    const eventEntity = matchedEvent
      ? data.entities.find(
          (entity) =>
            entity.entity_type === "历史事件" &&
            propString(entity, "event") === matchedEvent,
        )
      : undefined;
    const eventSourceRef = eventEntity
      ? propString(eventEntity, "source_ref")
      : "";
    const report =
      (eventSourceRef
        ? data.reports.find(
            (candidate) =>
              candidate.id === eventSourceRef ||
              candidate.source_ref === eventSourceRef,
          )
        : undefined) ?? result.reports[0]?.report;
    const next = createCaseFromReport(data, report?.id, matchedEvent);
    return {
      ...next,
      sourceKind: "query",
      sourceLabel: query,
      title: eventEntity ? next.title : `调查：${query}`,
    };
  }

  const coherentHits = matchCoherentPathEntities(data, parts);
  const steps: ChainStep[] = parts.map((part, index) => {
    const hit = coherentHits[index];
    return {
      id: `query-step-${index}-${Date.now().toString(36)}`,
      entityId: hit?.id,
      label: hit?.label ?? part,
      type: hit?.entity_type ?? "输入步骤",
      relation: index ? "输入时序" : "链路起点",
      phase: hit ? phaseFor(hit) : "待研判",
      attackId: hit ? techniqueFor(data, hit.id) || undefined : undefined,
      occurredAt: hit?.first_seen,
      confidence: hit ? propNumber(hit, "confidence") : 0.45,
      evidenceCount: hit?.source_count ?? 0,
      status: hit ? propString(hit, "status") || "positive" : "partial",
      origin: hit ? "database" : "manual",
      reviewStatus: hit ? "matched" : "candidate",
      description: hit?.description || "用户输入的候选攻击步骤，尚未与情报来源完成匹配。",
    };
  });
  const links: ChainLink[] = steps.slice(1).map((step, index) => ({
    id: `query-link-${index}-${Date.now().toString(36)}`,
    source: steps[index].id,
    target: step.id,
    label: "输入时序",
    confidence: Math.min(steps[index].confidence, step.confidence),
    status: step.reviewStatus === "candidate" ? "partial" : "positive",
  }));
  const matchedEntities = steps
    .map((step) =>
      step.entityId
        ? data.entities.find((entity) => entity.id === step.entityId)
        : undefined,
    )
    .filter((entity): entity is Entity => Boolean(entity));
  const eventCounts = new Map<string, number>();
  matchedEntities.forEach((entity) => {
    const matchedEvent = propString(entity, "event");
    if (matchedEvent) {
      eventCounts.set(matchedEvent, (eventCounts.get(matchedEvent) ?? 0) + 1);
    }
  });
  const event = [...eventCounts.entries()].sort((left, right) => right[1] - left[1])[0]?.[0];
  const actor = matchedEntities
    .map((entity) => propString(entity, "actor"))
    .find(Boolean);
  const eventEntity = event
    ? data.entities.find(
        (entity) =>
          entity.entity_type === "历史事件" &&
          propString(entity, "event") === event,
      )
    : undefined;
  const now = new Date().toISOString();
  return {
    id: `CASE-QUERY-${Date.now().toString(36).toUpperCase()}`,
    title: eventEntity?.label ?? `攻击链研判：${parts[0]}`,
    summary:
      "根据输入顺序与已入库情报生成的匹配结果；未命中直接证据的节点会明确保留为候选，不视为已验证事实。",
    sourceKind: "query",
    sourceLabel: query,
    actor: actor || undefined,
    event: event || undefined,
    createdAt: now,
    updatedAt: now,
    steps,
    links,
    notes: "",
    completedAdviceIds: [],
    version: 1,
  };
}

export function citationsForCase(
  data: Snapshot,
  investigation: InvestigationCase,
): SourceCitation[] {
  const relationshipIds = new Set(
    investigation.links
      .map((link) => link.relationshipId)
      .filter((id): id is string => Boolean(id)),
  );
  const entityIds = new Set(
    investigation.steps
      .map((step) => step.entityId)
      .filter((id): id is string => Boolean(id)),
  );
  data.relationships.forEach((relationship) => {
    if (
      entityIds.has(relationship.source_entity_id) &&
      entityIds.has(relationship.target_entity_id)
    ) {
      relationshipIds.add(relationship.id);
    }
  });

  const reportMap = new Map(data.reports.map((report) => [report.id, report]));
  return data.evidence
    .filter((evidence) => relationshipIds.has(evidence.relationship_id))
    .map((evidence) => {
      const report = reportMap.get(evidence.report_id);
      return {
        id: evidence.id,
        reportId: evidence.report_id,
        title: evidence.report_title,
        publisher: evidence.publisher,
        reportDate: evidence.report_date,
        sourceRef: evidence.source_ref,
        excerpt: evidence.excerpt,
        location: evidence.location,
        confidence: evidence.confidence,
        externalUrl: report?.external_url ?? "",
      };
    })
    .filter(
      (citation, index, all) =>
        all.findIndex(
          (item) =>
            item.reportId === citation.reportId &&
            item.excerpt === citation.excerpt &&
            item.location === citation.location,
        ) === index,
    )
    .sort((a, b) => b.reportDate.localeCompare(a.reportDate));
}

export function citationsForEntity(
  data: Pick<Snapshot, "relationships" | "evidence" | "reports">,
  entityId: string,
) {
  const relationshipIds = new Set(
    data.relationships
      .filter(
        (relationship) =>
          relationship.source_entity_id === entityId ||
          relationship.target_entity_id === entityId,
      )
      .map((relationship) => relationship.id),
  );
  const reportMap = new Map(data.reports.map((report) => [report.id, report]));
  return data.evidence
    .filter((evidence) => relationshipIds.has(evidence.relationship_id))
    .map((evidence) => {
      const report = reportMap.get(evidence.report_id);
      return {
        id: evidence.id,
        reportId: evidence.report_id,
        title: evidence.report_title,
        publisher: evidence.publisher,
        reportDate: evidence.report_date,
        sourceRef: evidence.source_ref,
        excerpt: evidence.excerpt,
        location: evidence.location,
        confidence: evidence.confidence,
        externalUrl: report?.external_url ?? "",
      };
    });
}


export function adviceForCase(
  data: Snapshot,
  investigation: InvestigationCase,
): AdviceItem[] {
  const activeSteps = investigation.steps.filter((step) => step.reviewStatus !== "excluded");
  const stepTypes = new Set(activeSteps.map((step) => step.type));
  const groups: AdviceItem["group"][] = ["立即遏制", "排查狩猎", "清除恢复", "长期加固"];
  const eventRules = investigation.event
    ? data.responseRules.filter((rule) => rule.match_event === investigation.event)
    : [];
  const matchingRules = data.responseRules.filter(
    (rule) =>
      !rule.match_event && stepTypes.has(rule.match_entity_type),
  );
  const defaultRules = data.responseRules.filter(
    (rule) => !rule.match_event && rule.match_entity_type === "*",
  );
  const base = eventRules.length
    ? eventRules
    : matchingRules.length || defaultRules.length
      ? [...matchingRules, ...defaultRules]
      : data.responseRules.filter((rule) => !rule.match_event).slice(0, 8);
  return base.slice(0, 8).map((rule, index) => ({
    id: rule.id,
    group: groups.includes(rule.group_label as AdviceItem["group"])
      ? (rule.group_label as AdviceItem["group"])
      : groups[index % groups.length],
    priority: rule.priority,
    title:
      rule.title ||
      (rule.match_entity_type === "IOC/基础设施"
        ? "复核相关指标与当前环境命中"
        : rule.match_entity_type === "ATT&CK 技术"
          ? "检查对应阶段的检测覆盖"
          : `围绕${rule.match_entity_type}开展复核`),
    recommendation: rule.action_template,
    condition: "仅在当前环境存在对应资产、日志或证据命中时适用；执行前需由安全负责人复核。",
    rationale: rule.rationale,
    sourceUrl: rule.source_url || undefined,
    stepIds: activeSteps
      .filter(
        (step) =>
          rule.match_entity_type === "*" ||
          step.type === rule.match_entity_type,
      )
      .map((step) => step.id),
  }));
}
