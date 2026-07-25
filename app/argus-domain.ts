import type {
  Actor,
  AdviceItem,
  ChainLink,
  ChainStep,
  Entity,
  GraphEdge,
  GraphNode,
  HistoricalFinding,
  InvestigationCase,
  Report,
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

export function normalize(value: string) {
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
  return query
    .split(/\s*(?:→|->|=>|＞|然后|再到)\s*|\n+/)
    .map((part) => part.replace(/^[\d.、\s]+/, "").trim())
    .filter((part) => part.length > 1);
}

function entityHaystack(entity: Entity) {
  return normalize(
    [
      entity.label,
      entity.normalized_value,
      entity.description,
      propString(entity, "entity_value"),
      propString(entity, "sub"),
      propString(entity, "actor"),
      propString(entity, "event"),
    ].join(" "),
  );
}

export function searchSnapshot(data: Snapshot, query: string): SearchResult {
  const q = normalize(query);
  const chainParts = getChainParts(query).map(normalize);
  const entities = data.entities
    .map((entity) => {
      const haystack = entityHaystack(entity);
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
      const haystack = normalize(
        `${report.title} ${report.source} ${report.extracted_text} ${report.assessment}`,
      );
      let score = haystack.includes(q) && q.length >= 3 ? 60 : 0;
      entities.slice(0, 10).forEach(({ entity }) => {
        if (haystack.includes(normalize(entity.label))) score += 5;
      });
      return { report, score: Math.min(99, score) };
    })
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score);

  return { queryType: detectQueryType(query), entities, reports };
}

export function entityToNode(entity: Entity): GraphNode {
  return {
    id: entity.id,
    label: entity.label,
    type: entity.entity_type,
    status: propString(entity, "status") || "positive",
    confidence: propNumber(entity, "confidence"),
    entity,
  };
}

export function buildSubgraph(
  data: Snapshot,
  seedIds: string[],
  limit = 28,
  allowedCategories?: Set<string>,
) {
  const entityMap = new Map(data.entities.map((entity) => [entity.id, entity]));
  const selected = new Set(seedIds.filter((id) => entityMap.has(id)));
  const queue = [...selected].map((id) => ({ id, depth: 0 }));
  while (queue.length && selected.size < limit) {
    const current = queue.shift();
    if (!current || current.depth >= 2) continue;
    const adjacent = data.relationships
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

  const nodes = [...selected]
    .map((id) => entityMap.get(id))
    .filter((entity): entity is Entity => Boolean(entity))
    .map(entityToNode);
  const edges: GraphEdge[] = data.relationships
    .filter(
      (edge) =>
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
    }));
  return { nodes, edges };
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

function eventForReport(data: Snapshot, report: Report) {
  const exact = data.entities.find(
    (entity) =>
      entity.entity_type === "历史事件" &&
      propString(entity, "source_ref") === report.source_ref,
  );
  if (exact) return exact;
  return data.entities.find(
    (entity) =>
      entity.entity_type === "历史事件" &&
      normalize(report.extracted_text).includes(normalize(entity.label)),
  );
}

export function getDefaultReport(data: Snapshot) {
  return (
    data.reports.find((report) => report.external_url && report.source_ref.includes("NCSC")) ??
    data.reports.find((report) => report.external_url) ??
    data.reports[0]
  );
}

export function createCaseFromReport(data: Snapshot, reportId?: string): InvestigationCase {
  const report = data.reports.find((item) => item.id === reportId) ?? getDefaultReport(data);
  const eventEntity = report ? eventForReport(data, report) : undefined;
  const event = eventEntity ? propString(eventEntity, "event") || eventEntity.label : "";
  const actor = eventEntity ? propString(eventEntity, "actor") : "";
  let entities = data.entities
    .filter((entity) => entity.entity_type === "攻击步骤" && propString(entity, "event") === event)
    .sort((a, b) => stepIndex(a) - stepIndex(b));

  if (!entities.length && report) {
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

  if (!entities.length) {
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
    const report = searchSnapshot(data, query).reports[0]?.report;
    const next = createCaseFromReport(data, report?.id);
    return { ...next, sourceKind: "query", sourceLabel: query, title: `调查：${query}` };
  }

  const steps: ChainStep[] = parts.map((part, index) => {
    const hit = searchSnapshot(data, part).entities[0]?.entity;
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
  const now = new Date().toISOString();
  return {
    id: `CASE-QUERY-${Date.now().toString(36).toUpperCase()}`,
    title: `攻击链研判：${parts[0]}`,
    summary: "根据用户输入顺序形成的研判草稿，候选节点需要人工确认。",
    sourceKind: "query",
    sourceLabel: query,
    createdAt: now,
    updatedAt: now,
    steps,
    links,
    notes: "",
    completedAdviceIds: [],
    version: 1,
  };
}

export function caseGraph(data: Snapshot, investigation: InvestigationCase) {
  const nodes: GraphNode[] = investigation.steps
    .filter((step) => step.reviewStatus !== "excluded")
    .map((step) => {
      const entity = step.entityId
        ? data.entities.find((item) => item.id === step.entityId)
        : undefined;
      return {
        id: step.id,
        label: step.label,
        type: step.type,
        status:
          step.reviewStatus === "candidate"
            ? "partial"
            : step.reviewStatus === "excluded"
              ? "negative"
              : step.status,
        confidence: step.confidence,
        entity,
        virtual: !entity,
      };
    });
  const visibleIds = new Set(nodes.map((node) => node.id));
  const edges: GraphEdge[] = investigation.links
    .filter((link) => visibleIds.has(link.source) && visibleIds.has(link.target))
    .map((link) => ({
      id: link.id,
      source: link.source,
      target: link.target,
      label: link.label,
      status: link.status,
      confidence: link.confidence,
    }));
  return { nodes, edges };
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

export function citationsForEntity(data: Snapshot, entityId: string) {
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

export function historicalFindings(
  data: Snapshot,
  investigation: InvestigationCase,
  citations: SourceCitation[],
): HistoricalFinding[] {
  const groups = new Map<string, ChainStep[]>();
  investigation.steps
    .filter((step) => step.reviewStatus !== "excluded")
    .forEach((step) => groups.set(step.phase, [...(groups.get(step.phase) ?? []), step]));
  const citationIds = citations.slice(0, 4).map((citation) => citation.id);
  const findings: HistoricalFinding[] = [...groups.entries()]
    .slice(0, 4)
    .map(([phase, steps], index) => ({
      id: `finding-${index}`,
      phase,
      title: `${phase}阶段观察到 ${steps.length} 个可追溯节点`,
      summary: steps
        .map((step) => step.label)
        .slice(0, 4)
        .join("、")
        .concat(
          "。该结论来自当前已入库报告与关系证据，未覆盖的环节应继续保留为未知。",
        ),
      tone: index === 0 ? "consensus" : "timeline",
      citationIds,
    }));
  if (citations.length > 1) {
    findings.push({
      id: "finding-difference",
      phase: "证据差异",
      title: "不同来源对攻击范围与归属的表述存在差异",
      summary:
        "ARGUS 仅聚合可追溯事实，不把行为相似或单一 IOC 重合自动提升为确定性归因。",
      tone: "difference",
      citationIds: citations.slice(0, 3).map((citation) => citation.id),
    });
  }
  return findings;
}

export function adviceForCase(
  data: Snapshot,
  investigation: InvestigationCase,
): AdviceItem[] {
  const activeSteps = investigation.steps.filter((step) => step.reviewStatus !== "excluded");
  const stepTypes = new Set(activeSteps.map((step) => step.type));
  const groups: AdviceItem["group"][] = ["立即遏制", "排查狩猎", "清除恢复", "长期加固"];
  const rules = data.responseRules.filter((rule) => stepTypes.has(rule.match_entity_type));
  const base = rules.length ? rules : data.responseRules.slice(0, 4);
  return base.slice(0, 6).map((rule, index) => ({
    id: rule.id,
    group: groups[index % groups.length],
    priority: rule.priority,
    title:
      rule.match_entity_type === "IOC/基础设施"
        ? "复核相关指标与当前环境命中"
        : rule.match_entity_type === "ATT&CK 技术"
          ? "检查对应阶段的检测覆盖"
          : `围绕${rule.match_entity_type}开展复核`,
    recommendation: rule.action_template,
    condition: "仅在当前环境存在对应资产、日志或证据命中时适用；执行前需由安全负责人复核。",
    rationale: rule.rationale,
    sourceUrl: rule.source_url || undefined,
    stepIds: activeSteps
      .filter((step) => step.type === rule.match_entity_type)
      .map((step) => step.id),
  }));
}

export function reportsForCase(data: Snapshot, citations: SourceCitation[]) {
  const ids = new Set(citations.map((citation) => citation.reportId));
  return data.reports.filter((report) => ids.has(report.id));
}

export function actorForCase(data: Snapshot, investigation: InvestigationCase): Actor | undefined {
  return data.actors.find((actor) => actor.label === investigation.actor);
}

export function actorGraph(data: Snapshot, actor: Actor, focusId?: string) {
  return buildSubgraph(
    data,
    [actor.id, ...(focusId ? [focusId] : [])],
    46,
    new Set(["chain", "infrastructure", "technique", "attribution"]),
  );
}
