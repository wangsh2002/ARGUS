"use client";

import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  ClipboardCheck,
  CornerDownRight,
  Crosshair,
  Download,
  FileCode2,
  FileSearch,
  GitBranch,
  ListChecks,
  Network,
  Plus,
  ShieldAlert,
  ShieldCheck,
  Target,
  Undo2,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  adviceForCase,
  buildSubgraph,
  citationsForCase,
  citationsForEntity,
  createCaseFromQuery,
  getChainParts,
  propNumber,
  propString,
  searchSnapshot,
} from "../argus-domain";
import type {
  AdviceItem,
  Actor,
  Entity,
  GraphEdge,
  GraphNode,
  PathCandidate,
  PathWorkspace,
  SourceCitation,
} from "../types";
import { NetworkGraph } from "../NetworkGraph";
import {
  deriveGraphBackbone,
  GraphSwimlaneProjection,
  initialExplorationIds,
} from "./GraphDensityPrototype";
import { SourceViewer, StatusBadge } from "./Primitives";

function uniqueById<T extends { id: string }>(items: T[]) {
  return items.filter(
    (item, index) => items.findIndex((candidate) => candidate.id === item.id) === index,
  );
}

function uniqueSources(items: SourceCitation[]) {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = item.reportId;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function collectInputEntities(data: PathWorkspace, query: string) {
  const investigation = createCaseFromQuery(data, query);
  const parts = getChainParts(query);
  const directHits = parts.flatMap((part) =>
    searchSnapshot(data, part)
      .entities.slice(0, 2)
      .map((hit) => hit.entity),
  );
  const normalizedInput = query.toLocaleLowerCase();
  const mentionedEntities = data.entities
    .filter(
      (entity) =>
        entity.label.length >= 4 &&
        normalizedInput.includes(entity.label.toLocaleLowerCase()),
    )
    .slice(0, 16);
  const caseEntities = investigation.steps
    .map((step) =>
      step.entityId
        ? data.entities.find((entity) => entity.id === step.entityId)
        : undefined,
    )
    .filter((entity): entity is Entity => Boolean(entity));

  return {
    investigation,
    entities: uniqueById([...directHits, ...mentionedEntities, ...caseEntities]).slice(
      0,
      12,
    ),
  };
}

function inferInputType(query: string) {
  const trimmed = query.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "结构化告警";
  if (trimmed.length > 500 || trimmed.split("\n").length > 8) return "完整情报文本";
  if (trimmed.includes("→")) return "多线索攻击序列";
  return "告警或情报线索";
}

function observedAtFromInput(query: string) {
  if (!query.trim().startsWith("{")) return "";
  try {
    const parsed = JSON.parse(query) as { observed_at?: unknown };
    if (typeof parsed.observed_at === "string") {
      return parsed.observed_at.replace("T", " ").replace("Z", " UTC");
    }
  } catch {
    // Fall back to entity timestamps for incomplete input.
  }
  return "";
}

function evidenceClassLabel(value: string) {
  return (
    {
      "public-confirmed": "公开确认",
      "demo-observed": "演示观测",
      correlated: "多源关联",
      inference: "分析推断",
      blocked: "阻断 / 反证",
    }[value] ?? "待验证"
  );
}

function evidenceGapFor(value: string) {
  return (
    {
      "public-confirmed": "公开情报确认该攻击机制，但仍需本地日志证明当前环境实际发生。",
      "demo-observed": "已存在本地观测，需要与后续身份或应用层日志关联确认攻击结果。",
      correlated: "多源时间与实体关系一致，仍应补充原始流量或身份审计完成闭环。",
      inference: "当前仅为候选路径，缺少直接观测证据，不应升级为确定结论。",
      blocked: "现有证据支持攻击被阻断，相关事件不能被解释为攻击成功。",
    }[value] ?? "当前证据不足，需要补充本地日志与可靠来源。"
  );
}

function actionContextRoleLabel(role: string) {
  return (
    {
      uses_tool: "使用工具",
      executes_file: "执行文件",
      drops_file: "落地文件",
      communicates_with: "连接基础设施",
      sends_to: "向目标发送",
      targets_asset: "作用于资产",
      exploits_vulnerability: "利用漏洞",
      implements_technique: "对应技战术",
      collects: "收集",
      produces: "产生",
      persists_via: "借此驻留",
      masquerades_as: "伪装为",
    }[role] ?? role.replaceAll("_", " ")
  );
}

function historicalPathGraph(
  data: PathWorkspace,
  path: PathWorkspace["historicalPaths"][number],
  selectedPath?: PathCandidate,
) {
  const entityById = new Map(data.entities.map((entity) => [entity.id, entity]));
  const projection = path.projection;
  const mainlineIds = new Set(
    projection?.mainline_action_refs ??
      path.nodes.map((node) => String(node.id)),
  );
  const evidenceCountByNode = new Map<string, number>();
  const reviewedStepByAction = new Map(
    selectedPath?.steps.flatMap((step) => {
      const actionId = step.pathNodeId ?? step.entityId;
      return actionId ? [[actionId, step] as const] : [];
    }) ?? [],
  );
  path.evidence.forEach((item) => {
    const nodeId = typeof item.node_id === "string" ? item.node_id : "";
    if (!nodeId) return;
    evidenceCountByNode.set(
      nodeId,
      (evidenceCountByNode.get(nodeId) ?? 0) + 1,
    );
  });
  const actionNodes: GraphNode[] = path.nodes.map((node) => {
    const id = String(node.id);
    const reviewedStep = reviewedStepByAction.get(id);
    const properties =
      typeof node.properties === "object" && node.properties
        ? node.properties
        : {};
    const entity: Entity = {
      id,
      entity_type: "攻击步骤",
      canonical_key: `activity-action:${path.id}:${id}`,
      label: String(node.label ?? "未命名行为"),
      normalized_value: String(node.label ?? "").toLocaleLowerCase(),
      description:
        "description" in properties
          ? String(properties.description)
          : path.description,
      first_seen: path.started_at,
      last_seen: path.ended_at,
      source_count: evidenceCountByNode.get(id) ?? 0,
      properties: {
        ...properties,
        actor: String(path.metadata.actor ?? ""),
        event: path.name,
        phase: String(node.phase ?? "待研判"),
        mainline_role: mainlineIds.has(id) ? "backbone" : "supporting",
        mainline_order: mainlineIds.has(id)
          ? [...mainlineIds].indexOf(id) + 1
          : 0,
        analysis_state:
          reviewedStep?.analysisState ?? projection?.node_state[id] ?? "observed",
        match_reason: reviewedStep?.matchReason ?? "",
        evidence_class: "public-confirmed",
        confidence:
          reviewedStep?.confidence ?? Number(node.confidence ?? path.confidence),
        evidence_count: evidenceCountByNode.get(id) ?? 0,
      },
    };
    return {
      id,
      label: entity.label,
      type: "攻击步骤",
      status: "confirmed",
      confidence:
        reviewedStep?.confidence ?? Number(node.confidence ?? path.confidence),
      entity,
      virtual: true,
    };
  });
  const contextEntityIds = [
    ...new Set(path.contextLinks.map((link) => link.entity_id)),
  ];
  const contextNodes: GraphNode[] = contextEntityIds.flatMap((entityId) => {
    const entity = entityById.get(entityId);
    return entity
      ? [
          {
            id: entity.id,
            label: entity.label,
            type: entity.entity_type,
            status: "confirmed",
            confidence: propNumber(entity, "confidence") || 0.85,
            entity,
          },
        ]
      : [];
  });
  const dependencyEdges: GraphEdge[] = path.edges.map((edge) => ({
    id: String(edge.id),
    source: String(edge.source_node_id),
    target: String(edge.target_node_id),
    label: String(
      edge.condition_label ||
        ({
          enables: "使后续行为成为可能",
          causes: "直接触发",
          branch: "形成并行分支",
        }[String(edge.edge_type)] ??
          "存在过程依赖"),
    ),
    category: "攻击过程",
    status: "confirmed",
    confidence: Number(edge.confidence ?? path.confidence),
  }));
  const contextEdges: GraphEdge[] = path.contextLinks.map((link) => {
    const entityToAction = link.direction === "entity_to_action";
    return {
      id: link.id,
      source: entityToAction ? link.entity_id : link.action_node_id,
      target: entityToAction ? link.action_node_id : link.entity_id,
      label: actionContextRoleLabel(link.role),
      category: "行为上下文",
      status: "confirmed",
      confidence: link.confidence,
    };
  });
  const keyContextIds = projection
    ? Object.values(projection.key_context_by_action)
        .flat()
        .filter((id): id is string => Boolean(id))
    : contextEntityIds.slice(0, 4);
  return {
    nodes: [...actionNodes, ...contextNodes],
    edges: [...dependencyEdges, ...contextEdges],
    rootIds: [
      ...(projection?.root_action_refs ?? actionNodes.slice(0, 1).map((node) => node.id)),
      ...keyContextIds,
    ],
    preferredPathIds:
      projection?.mainline_action_refs ??
      actionNodes.map((node) => node.id),
  };
}

function citationsForHistoricalPath(
  data: PathWorkspace,
  path: PathWorkspace["historicalPaths"][number],
  selectedId?: string,
): SourceCitation[] {
  const artifactById = new Map(
    data.sourceArtifacts.map((artifact) => [artifact.id, artifact]),
  );
  const selectedEdgeIds = new Set(
    path.edges
      .filter(
        (edge) =>
          edge.source_node_id === selectedId ||
          edge.target_node_id === selectedId,
      )
      .map((edge) => String(edge.id)),
  );
  const pathItems = path.evidence.filter(
    (item) =>
      !selectedId ||
      item.node_id === selectedId ||
      (typeof item.edge_id === "string" && selectedEdgeIds.has(item.edge_id)),
  );
  const contextItems = path.contextEvidence.filter(
    (item) =>
      !selectedId ||
      item.action_node_id === selectedId ||
      item.entity_id === selectedId,
  );
  return [...pathItems, ...contextItems].map((item, index) => {
    const artifactId = String(item.artifact_id ?? path.primary_artifact_id ?? "");
    const artifact = artifactById.get(artifactId);
    return {
      id: String(item.id ?? `${path.id}-source-${index}`),
      reportId: artifactId,
      title: String(item.report_title ?? artifact?.title ?? path.name),
      publisher: String(item.publisher ?? artifact?.publisher ?? "原始报告"),
      reportDate: String(artifact?.published_at ?? path.started_at ?? ""),
      sourceRef: String(item.source_span_id ?? ""),
      excerpt: String(item.quote ?? ""),
      location: String(item.locator ?? ""),
      confidence: Number(item.confidence ?? path.confidence),
      externalUrl: String(item.canonical_url ?? artifact?.canonical_url ?? ""),
    };
  });
}

function analysisStateLabel(value: string) {
  return (
    {
      observed: "输入命中",
      reconstructed: "路径补全",
      predicted: "后续预测",
      reference: "历史分支",
      candidate: "候选路径",
      blocked: "阻断结果",
    }[value] ?? "待研判"
  );
}

function branchAnnotation(
  edge: GraphEdge,
  target: GraphNode | undefined,
) {
  if (!target) return undefined;
  const analysisState = target.entity
    ? propString(target.entity, "analysis_state")
    : "";
  const relationText = `${edge.label} ${target.label}`;

  if (/WebDAV|回退/i.test(relationText)) {
    return { label: "失败时回退", tone: "failure" as const };
  }
  if (/未证明|不足以证明/i.test(relationText)) {
    return { label: "证据不足", tone: "failure" as const };
  }
  if (analysisState === "blocked" || target.status === "negative") {
    return { label: "防守阻断", tone: "failure" as const };
  }
  if (/继续投递|扩散/i.test(relationText)) {
    return { label: "并行扩散", tone: "parallel" as const };
  }
  if (analysisState === "candidate") {
    return {
      label: /离线|破解/i.test(relationText) ? "中继失败候选" : "候选推进",
      tone: "candidate" as const,
    };
  }
  return undefined;
}

function nodeIdsForAdvice(
  item: AdviceItem,
  nodes: GraphNode[],
  backbone: GraphNode[],
) {
  const text = `${item.title} ${item.recommendation} ${item.rationale}`;
  let matcher: RegExp | undefined;

  if (/阻断对外 SMB/i.test(text)) {
    matcher = /Outlook 无交互|对外 SMB 445|SMB 出口被阻断/;
  } else if (/扫描恶意提醒|修复 Outlook/i.test(text)) {
    matcher = /恶意提醒消息投递|外部 UNC 路径植入|Outlook 无交互触发/;
  } else if (/清理恶意邮件|扩散项目/i.test(text)) {
    matcher =
      /恶意提醒消息投递|外部 UNC 路径植入|Outlook 无交互触发|对外 SMB 445|Net-NTLMv2|NTLM 中继|EWS 邮箱访问|EWS 继续投递/;
  } else if (/验证泄露|中继是否成功/i.test(text)) {
    matcher = /对外 SMB 445|Net-NTLMv2|NTLM 中继|EWS 邮箱访问/;
  } else if (/Exchange 邮箱持久化|邮箱权限/i.test(text)) {
    matcher = /NTLM 中继|EWS 邮箱访问|邮箱权限持久化/;
  } else if (/身份与邮件检测|限制或禁用 NTLM/i.test(text)) {
    matcher = /对外 SMB 445|Net-NTLMv2|NTLM 中继|EWS 邮箱访问|邮箱权限持久化/;
  }

  const matched = nodes
    .filter((node) => matcher?.test(node.label))
    .map((node) => node.id);
  const directIds = item.stepIds.filter((id) =>
    nodes.some((node) => node.id === id),
  );
  const ids = new Set([...directIds, ...matched]);
  const matchedBackboneIndexes = backbone
    .map((node, index) => (ids.has(node.id) ? index : -1))
    .filter((index) => index >= 0);

  if (matchedBackboneIndexes.length > 1) {
    const first = Math.min(...matchedBackboneIndexes);
    const last = Math.max(...matchedBackboneIndexes);
    backbone.slice(first, last + 1).forEach((node) => ids.add(node.id));
  }
  if (!ids.size) {
    backbone.slice(0, Math.min(3, backbone.length)).forEach((node) => ids.add(node.id));
  }
  return [...ids];
}

const propertyLabels: Record<string, string> = {
  entity_value: "关键值",
  phase: "攻击阶段",
  actor: "关联组织",
  event: "关联事件",
  source_ref: "来源编号",
  sub: "节点说明",
  raw_signal: "原始信号",
  inference_basis: "补全依据",
  prediction_basis: "预测依据",
  prediction_horizon: "预测窗口",
  verification_needed: "待验证证据",
};

function actorScore(actor: Actor, graphNodes: GraphNode[]) {
  const evidenceNodes = graphNodes.filter(
    (node) =>
      node.entity &&
      (propString(node.entity, "actor") === actor.label ||
        node.entity.label === actor.label),
  );
  if (!evidenceNodes.length) return Math.round(actor.source_grade * 100);
  return Math.round(
    (evidenceNodes.reduce(
      (sum, node) => sum + (node.confidence ?? propNumber(node.entity!, "confidence")),
      0,
    ) /
      evidenceNodes.length) *
      100,
  );
}

type AttributionEvidencePath = {
  id: string;
  title: string;
  summary: string;
  contribution: string;
  tone: "strong" | "supporting" | "neutral";
  nodeIds: string[];
  sourceRefs: string[];
};

type AttributionCandidateAssessment = {
  actor: Actor;
  score: number;
  decision: string;
  reason: string;
  gap: string;
};

const coreAttributionPaths: AttributionEvidencePath[] = [
  {
    id: "outlook-forced-auth",
    title: "Outlook 强制认证公开活动链",
    summary:
      "恶意提醒属性、外部 UNC 与对外 SMB 认证形成连续路径，并命中 APT28 已公开利用活动。",
    contribution: "+31",
    tone: "strong",
    nodeIds: [
      "ENT-ACTOR-fbde425d47a0",
      "APT28-event-H2",
      "APT28-event-H2-step-0",
      "APT28-event-H2-step-1",
      "APT28-event-H2-step-2",
      "APT28-event-H2-step-3",
      "APT28-tech-t1187",
    ],
    sourceRefs: ["SRC-MS-MSRC-23397", "SRC-A28-H2"],
  },
  {
    id: "exchange-persistence",
    title: "Exchange 中继与邮箱持久化链",
    summary:
      "NTLM 中继、EWS 会话和邮箱权限修改与公开披露的 APT28 邮箱行动路径一致。",
    contribution: "+28",
    tone: "strong",
    nodeIds: [
      "ENT-ACTOR-fbde425d47a0",
      "APT28-event-H2",
      "APT28-event-H2-step-0",
      "APT28-event-H2-step-1",
      "APT28-event-H2-step-2",
      "APT28-event-H2-step-3",
      "CORE-23397-step-4",
      "CORE-23397-step-5",
      "CORE-23397-step-6",
      "CORE-23397-step-7",
      "APT28-tech-t1557-001",
      "APT28-tech-t1098-002",
    ],
    sourceRefs: ["SRC-POL-DKWOC-23397", "SRC-A28-H2"],
  },
  {
    id: "unattributed-ioc",
    title: "IOC 专属性核查",
    summary:
      "203.0.113.77 只能证明本次演示中的外连目标，没有组织专属历史记录，不参与归因加分。",
    contribution: "+0",
    tone: "neutral",
    nodeIds: ["APT28-event-H2-step-3", "CORE-23397-ioc-demo-smb"],
    sourceRefs: ["SRC-DEMO-INPUT-23397"],
  },
];

const coreCandidateProfiles: Record<
  string,
  Omit<AttributionCandidateAssessment, "actor">
> = {
  APT28: {
    score: 87,
    decision: "高关联候选",
    reason: "命中公开活动、关键技战术与攻击顺序",
    gap: "缺少组织专属基础设施或恶意软件样本",
  },
  Lazarus: {
    score: 52,
    decision: "一般关联",
    reason: "仅存在通用凭据访问行为重合",
    gap: "未命中本漏洞活动和 Exchange 持久化历史",
  },
  "组织 Z": {
    score: 34,
    decision: "弱关联",
    reason: "远程认证行为相似",
    gap: "活动簇身份未确认，缺少权威公开来源",
  },
};

const coreAttributionLedger = [
  {
    tone: "strong",
    label: "强支持",
    fact: "Microsoft 与波兰网络司令部公开材料将该漏洞活动和邮箱持久化行为关联至 APT28。",
    impact: "+26",
  },
  {
    tone: "strong",
    label: "强支持",
    fact: "T1187、T1557.001、T1098.002 在同一有向攻击路径中连续命中。",
    impact: "+18",
  },
  {
    tone: "supporting",
    label: "一般支持",
    fact: "目标环境、企业邮箱和身份访问方式与 APT28 历史活动范围一致。",
    impact: "+10",
  },
  {
    tone: "neutral",
    label: "不参与归因",
    fact: "203.0.113.77 是本次演示 IOC，没有组织专属历史记录。",
    impact: "+0",
  },
  {
    tone: "gap",
    label: "证据缺口",
    fact: "未发现 APT28 专属恶意软件样本或可复用指挥基础设施。",
    impact: "-5",
  },
];

function citationsForAttributionPath(
  citations: SourceCitation[],
  path: AttributionEvidencePath,
) {
  return citations.filter((citation) => path.sourceRefs.includes(citation.sourceRef));
}

function AttributionGraphDialog({
  data,
  actor,
  path,
  citations,
  onOpenSource,
  onClose,
}: {
  data: PathWorkspace;
  actor: Actor;
  path: AttributionEvidencePath;
  citations: SourceCitation[];
  onOpenSource: (citation: SourceCitation) => void;
  onClose: () => void;
}) {
  const graph = useMemo(
    () => buildSubgraph(data, [actor.id, ...path.nodeIds], 48),
    [actor.id, data, path.nodeIds],
  );
  const highlightedIds = useMemo(
    () => path.nodeIds.filter((id) => graph.nodes.some((node) => node.id === id)),
    [graph.nodes, path.nodeIds],
  );
  const highlightedIdSet = useMemo(
    () => new Set(highlightedIds),
    [highlightedIds],
  );
  const highlightedEdgeIds = useMemo(
    () =>
      graph.edges
        .filter(
          (edge) =>
            highlightedIdSet.has(edge.source) &&
            highlightedIdSet.has(edge.target),
        )
        .map((edge) => edge.id),
    [graph.edges, highlightedIdSet],
  );
  const [selectedId, setSelectedId] = useState(
    highlightedIds[highlightedIds.length - 1] ?? actor.id,
  );
  const selectedNode =
    graph.nodes.find((node) => node.id === selectedId) ??
    graph.nodes.find((node) => node.id === actor.id) ??
    graph.nodes[0];
  const selectedRelations = graph.edges.filter(
    (edge) => edge.source === selectedNode?.id || edge.target === selectedNode?.id,
  );
  const pathCitations = citationsForAttributionPath(citations, path);

  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (
        event.key === "Escape" &&
        !document.querySelector(".source-viewer-backdrop")
      ) {
        onClose();
      }
    };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  return (
    <div
      className="attribution-graph-backdrop"
      role="presentation"
      onMouseDown={onClose}
    >
      <section
        className="attribution-graph-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={`${actor.label} 组织知识图谱`}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header>
          <div>
            <span>组织知识图谱核验</span>
            <h2>{actor.label} 真实关联图谱</h2>
            <p>
              保留组织历史活动、工具与技战术上下文，仅高亮本案命中的
              “{path.title}”。
            </p>
          </div>
          <div className="attribution-graph-dialog-meta">
            <span>{graph.nodes.length} 节点</span>
            <span>{graph.edges.length} 关系</span>
            <button
              type="button"
              aria-label="关闭组织知识图谱"
              onClick={onClose}
            >
              <X size={17} />
            </button>
          </div>
        </header>

        <div className="attribution-graph-dialog-body">
          <section className="attribution-organization-graph has-highlight-path">
            <div className="attribution-graph-path-heading">
              <div>
                <GitBranch size={16} />
                <span>
                  <strong>{path.title}</strong>
                  <small>{path.summary}</small>
                </span>
              </div>
              <b>{path.contribution} 归因贡献</b>
            </div>
            <NetworkGraph
              nodes={graph.nodes}
              edges={graph.edges}
              rootId={actor.id}
              selectedId={selectedNode?.id}
              highlightIds={highlightedIds}
              highlightEdgeIds={highlightedEdgeIds}
              onSelect={(node) => setSelectedId(node.id)}
            />
            <div className="attribution-graph-legend" aria-label="图谱高亮说明">
              <span className="is-path">本案命中路径</span>
              <span className="is-context">组织历史上下文</span>
            </div>
          </section>

          <aside className="attribution-graph-inspector">
            <span>当前节点</span>
            {selectedNode ? (
              <>
                <div className="attribution-inspector-heading">
                  <Target size={17} />
                  <div>
                    <h3>{selectedNode.label}</h3>
                    <small>{selectedNode.type}</small>
                  </div>
                </div>
                <StatusBadge
                  status={
                    highlightedIdSet.has(selectedNode.id)
                      ? "confirmed"
                      : selectedNode.status ?? "positive"
                  }
                >
                  {highlightedIdSet.has(selectedNode.id)
                    ? "本案路径节点"
                    : "组织上下文"}
                </StatusBadge>
                <p>
                  {selectedNode.entity?.description ||
                    "当前节点没有补充描述，可通过直接关系继续核验上下文。"}
                </p>
                <dl>
                  <div>
                    <dt>置信度</dt>
                    <dd>
                      {Math.round(
                        (selectedNode.confidence ??
                          (selectedNode.entity
                            ? propNumber(selectedNode.entity, "confidence")
                            : 0)) * 100,
                      )}
                      %
                    </dd>
                  </div>
                  <div>
                    <dt>直接关系</dt>
                    <dd>{selectedRelations.length}</dd>
                  </div>
                  <div>
                    <dt>路径状态</dt>
                    <dd>
                      {highlightedIdSet.has(selectedNode.id)
                        ? "已命中"
                        : "背景知识"}
                    </dd>
                  </div>
                </dl>
                <div className="attribution-inspector-relations">
                  <strong>直接关系</strong>
                  {selectedRelations.slice(0, 5).map((edge: GraphEdge) => (
                    <div key={edge.id}>
                      <span>{edge.label}</span>
                      <small>{Math.round((edge.confidence ?? 0) * 100)}%</small>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <p>点击图谱节点查看组织知识和本案命中状态。</p>
            )}

            <div className="attribution-inspector-sources">
              <strong>支撑来源</strong>
              {pathCitations.map((citation) => (
                <button
                  type="button"
                  key={citation.id}
                  onClick={() => onOpenSource(citation)}
                >
                  <BookOpen size={14} />
                  <span>
                    <b>{citation.publisher}</b>
                    <small>{citation.title}</small>
                  </span>
                </button>
              ))}
              {!pathCitations.length && <p>该路径暂无可打开的原始来源。</p>}
            </div>
          </aside>
        </div>
      </section>
    </div>
  );
}

export function AttackPathAnalysisView({
  data,
  query,
  selectedPath,
  backLabel,
  onBack,
}: {
  data: PathWorkspace;
  query: string;
  selectedPath?: PathCandidate;
  backLabel: string;
  onBack: () => void;
}) {
  const historicalPath = useMemo(
    () =>
      selectedPath?.historicalPathId
        ? data.historicalPaths.find(
            (path) => path.id === selectedPath.historicalPathId,
          )
        : undefined,
    [data.historicalPaths, selectedPath],
  );
  const curatedGraph = useMemo(
    () =>
      historicalPath
        ? historicalPathGraph(data, historicalPath, selectedPath)
        : undefined,
    [data, historicalPath, selectedPath],
  );
  const analysisQuery = selectedPath?.analysisQuery || query;
  const analysisInput = useMemo(
    () => collectInputEntities(data, analysisQuery),
    [analysisQuery, data],
  );
  const rootIds = useMemo(
    () =>
      curatedGraph?.rootIds ??
      analysisInput.entities.map((entity) => entity.id),
    [analysisInput.entities, curatedGraph],
  );
  const preferredPathIds = useMemo(
    () => {
      if (curatedGraph) return curatedGraph.preferredPathIds;
      const reviewedPathIds = selectedPath?.steps
        .map((step) => step.entityId ?? step.pathNodeId)
        .filter((id): id is string => Boolean(id));
      const event = analysisInput.investigation.event;
      const canonicalEventPath = event
        ? data.entities
            .filter(
              (entity) =>
                entity.entity_type === "攻击步骤" &&
                propString(entity, "event") === event &&
                /第\s*\d+\s*步/.test(propString(entity, "sub")),
            )
            .sort((left, right) => {
              const stepNumber = (entity: Entity) =>
                Number(propString(entity, "sub").match(/第\s*(\d+)\s*步/)?.[1] ?? 99);
              return stepNumber(left) - stepNumber(right);
            })
            .map((entity) => entity.id)
        : [];
      if (
        canonicalEventPath.length >= 2 &&
        reviewedPathIds?.some((id) => canonicalEventPath.includes(id))
      ) {
        return canonicalEventPath;
      }
      if (reviewedPathIds && reviewedPathIds.length >= 2) {
        return reviewedPathIds;
      }
      if (canonicalEventPath.length >= 2) return canonicalEventPath;
      return analysisInput.investigation.steps
        .map((step) => step.entityId)
        .filter((id): id is string => Boolean(id));
    },
    [
      analysisInput.investigation.event,
      analysisInput.investigation.steps,
      data.entities,
      curatedGraph,
      selectedPath,
    ],
  );
  const graph = useMemo(
    () => {
      if (curatedGraph) {
        return {
          nodes: curatedGraph.nodes,
          edges: curatedGraph.edges,
        };
      }
      const built = buildSubgraph(
        data,
        [...new Set([...rootIds, ...preferredPathIds])],
        48,
      );
      const reviewedLabels = new Map(
        selectedPath?.steps
          .filter((step) => step.entityId)
          .map((step) => [step.entityId as string, step.label]) ?? [],
      );
      const reviewedSteps = new Map(
        selectedPath?.steps
          .filter((step) => step.entityId)
          .map((step) => [step.entityId as string, step]) ?? [],
      );
      const reviewedStepEntities = new Map(
        selectedPath?.steps.map((step) => [step.id, step.entityId]) ?? [],
      );
      const reviewedLinks = new Map(
        selectedPath?.links?.flatMap((link) => {
          const source = reviewedStepEntities.get(link.sourceStepId);
          const target = reviewedStepEntities.get(link.targetStepId);
          return source && target ? [[`${source}:${target}`, link]] : [];
        }) ?? [],
      );
      const eventPathIds = analysisInput.investigation.event
        ? data.entities
            .filter(
              (entity) =>
                entity.entity_type === "攻击步骤" &&
                propString(entity, "event") ===
                  analysisInput.investigation.event &&
                /第\s*\d+\s*步/.test(propString(entity, "sub")),
            )
            .sort((left, right) => {
              const stepNumber = (entity: Entity) =>
                Number(
                  propString(entity, "sub").match(/第\s*(\d+)\s*步/)?.[1] ??
                    99,
                );
              return stepNumber(left) - stepNumber(right);
            })
            .map((entity) => entity.id)
        : [];
      const eventPathIndex = new Map(
        eventPathIds.map((id, index) => [id, index]),
      );
      const reviewedPathIndexes = selectedPath?.steps
        .filter((step) => step.analysisState === "observed")
        .map((step) =>
          step.entityId ? eventPathIndex.get(step.entityId) : undefined,
        )
        .filter((index): index is number => index !== undefined) ?? [];
      const lastObservedPathIndex = reviewedPathIndexes.length
        ? Math.max(...reviewedPathIndexes)
        : undefined;
      return {
        ...built,
        nodes: built.nodes.map((node) => {
          const reviewedLabel = reviewedLabels.get(node.id);
          const reviewedStep = reviewedSteps.get(node.id);
          const eventIndex = eventPathIndex.get(node.id);
          const inferredState =
            selectedPath &&
            eventIndex !== undefined &&
            lastObservedPathIndex !== undefined
              ? eventIndex <= lastObservedPathIndex
                ? "reconstructed"
                : "predicted"
              : undefined;
          const analysisState =
            reviewedStep?.analysisState ?? inferredState;
          if (!analysisState) {
            return reviewedLabel ? { ...node, label: reviewedLabel } : node;
          }
          const evidenceClass =
            analysisState === "observed"
              ? "demo-observed"
              : analysisState === "reference"
                ? "public-confirmed"
              : analysisState === "blocked"
                ? "blocked"
                : "inference";
          const status =
            analysisState === "observed"
              ? "confirmed"
              : analysisState === "reference"
                ? "confirmed"
              : analysisState === "blocked"
                ? "negative"
                : "partial";
          return {
            ...node,
            label: reviewedStep?.label ?? node.label,
            status,
            confidence: reviewedStep?.confidence ?? node.confidence,
            entity: node.entity
              ? {
                  ...node.entity,
                  label: reviewedStep?.label ?? node.entity.label,
                  properties: {
                    ...node.entity.properties,
                    analysis_state: analysisState,
                    evidence_class: evidenceClass,
                    confidence:
                      reviewedStep?.confidence ?? node.confidence,
                    evidence_count:
                      reviewedStep?.evidenceCount ??
                      node.entity.source_count,
                    match_reason: reviewedStep?.matchReason ?? "",
                  },
                }
              : node.entity,
          };
        }),
        edges: built.edges.map((edge) => {
          const reviewedLink = reviewedLinks.get(
            `${edge.source}:${edge.target}`,
          );
          if (!reviewedLink) return edge;
          return {
            ...edge,
            label: reviewedLink.label,
            confidence: reviewedLink.confidence,
            status:
              reviewedLink.reviewStatus === "rejected"
                ? "negative"
                : reviewedLink.reviewStatus === "observed"
                  ? edge.status
                  : "partial",
          };
        }),
      };
    },
    [
      analysisInput.investigation.event,
      curatedGraph,
      data,
      preferredPathIds,
      rootIds,
      selectedPath,
    ],
  );
  const primaryEventId = graph.nodes.find(
    (node) => node.type === "历史事件",
  )?.id;
  const backbone = useMemo(
    () =>
      deriveGraphBackbone(
        graph.nodes,
        graph.edges,
        rootIds,
        primaryEventId,
        preferredPathIds,
      ),
    [graph.edges, graph.nodes, preferredPathIds, primaryEventId, rootIds],
  );
  const initialVisibleIds = useMemo(
    () => initialExplorationIds(backbone, graph.nodes, graph.edges, rootIds),
    [backbone, graph.edges, graph.nodes, rootIds],
  );
  const [visibleIds, setVisibleIds] = useState<string[]>(initialVisibleIds);
  const [expansionHistory, setExpansionHistory] = useState<string[][]>([]);
  const [graphMode, setGraphMode] = useState<"original" | "augmented">("augmented");
  const [gapFocus, setGapFocus] = useState(false);
  const [focusedAdviceId, setFocusedAdviceId] = useState<string>();
  const [selectedId, setSelectedId] = useState(
    backbone[0]?.id ?? rootIds[0] ?? graph.nodes[0]?.id,
  );
  const [source, setSource] = useState<SourceCitation>();
  const [showUpstream, setShowUpstream] = useState(false);
  const [panelTab, setPanelTab] = useState<
    "verdict" | "evidence" | "logs" | "sources"
  >("verdict");
  const [expandedResponseGroups, setExpandedResponseGroups] = useState<string[]>([
    "立即遏制",
    "排查狩猎",
  ]);
  const [attributionOpen, setAttributionOpen] = useState(false);
  const [selectedAttributionPath, setSelectedAttributionPath] =
    useState<AttributionEvidencePath>();
  const analysisGraphRef = useRef<HTMLDivElement>(null);

  const selectedNode =
    graph.nodes.find((node) => node.id === selectedId) ?? graph.nodes[0];
  const selectedEntity = selectedNode?.entity;
  const selectedEdges = graph.edges.filter(
    (edge) => edge.source === selectedNode?.id || edge.target === selectedNode?.id,
  );
  const observedBackboneIds = useMemo(
    () =>
      new Set(
        backbone
          .filter(
            (node) =>
              node.entity &&
              propString(node.entity, "analysis_state") === "observed",
          )
          .map((node) => node.id),
      ),
    [backbone],
  );
  const originalRelevantIds = useMemo(() => {
    const directInputIds = rootIds.filter((id) => {
      const node = graph.nodes.find((candidate) => candidate.id === id);
      const state = node?.entity
        ? propString(node.entity, "analysis_state")
        : "";
      return !state || state === "observed";
    });
    const ids = new Set([...directInputIds, ...observedBackboneIds]);
    graph.edges.forEach((edge) => {
      if (!observedBackboneIds.has(edge.source)) return;
      const target = graph.nodes.find((node) => node.id === edge.target);
      if (
        target &&
        (target.type === "检测证据" ||
          target.type === "IOC/基础设施" ||
          target.type === "资产" ||
          target.type === "身份")
      ) {
        ids.add(target.id);
      }
    });
    return ids;
  }, [graph.edges, graph.nodes, observedBackboneIds, rootIds]);
  const effectiveVisibleIds = useMemo(
    () =>
      graphMode === "original"
        ? visibleIds.filter((id) => originalRelevantIds.has(id))
        : visibleIds,
    [graphMode, originalRelevantIds, visibleIds],
  );
  const visibleIdSet = useMemo(
    () => new Set(effectiveVisibleIds),
    [effectiveVisibleIds],
  );
  const visibleNodes = useMemo(
    () => graph.nodes.filter((node) => visibleIdSet.has(node.id)),
    [graph.nodes, visibleIdSet],
  );
  const visibleEdges = useMemo(
    () =>
      graph.edges.filter(
        (edge) =>
          visibleIdSet.has(edge.source) && visibleIdSet.has(edge.target),
      ),
    [graph.edges, visibleIdSet],
  );
  const backboneIds = useMemo(
    () => backbone.map((node) => node.id),
    [backbone],
  );
  const edgeAnnotations = useMemo(() => {
    const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));

    return Object.fromEntries(
      graph.edges.flatMap((edge) => {
        const annotation = branchAnnotation(
          edge,
          nodeById.get(edge.target),
        );
        return annotation ? [[edge.id, annotation]] : [];
      }),
    );
  }, [graph.edges, graph.nodes]);
  const hiddenNeighborCounts = useMemo(() => {
    if (graphMode === "original") return {};
    return Object.fromEntries(
      visibleNodes.map((node) => {
        const hiddenTargets = new Set(
          graph.edges
            .filter(
              (edge) =>
                edge.source === node.id && !visibleIdSet.has(edge.target),
            )
            .map((edge) => edge.target),
        );
        return [node.id, hiddenTargets.size];
      }),
    );
  }, [graph.edges, graphMode, visibleIdSet, visibleNodes]);
  const projectedBackbone = useMemo(
    () =>
      backbone.map((node) => {
        const state = node.entity
          ? propString(node.entity, "analysis_state")
          : "";
        if (graphMode !== "original" || state === "observed") return node;
        return {
          ...node,
          label: state === "predicted" ? "未知后续" : "缺失环节",
        };
      }),
    [backbone, graphMode],
  );
  const downstreamRelations = useMemo(() => {
    const seen = new Set<string>();
    return graph.edges
      .filter((edge) => edge.source === selectedNode?.id)
      .map((edge) => ({
        edge,
        node: graph.nodes.find((node) => node.id === edge.target),
      }))
      .filter(({ node }) => {
        if (!node || seen.has(node.id)) return false;
        seen.add(node.id);
        return true;
      });
  }, [graph.edges, graph.nodes, selectedNode?.id]);
  const upstreamRelations = useMemo(() => {
    const seen = new Set<string>();
    return graph.edges
      .filter((edge) => edge.target === selectedNode?.id)
      .map((edge) => ({
        edge,
        node: graph.nodes.find((node) => node.id === edge.source),
      }))
      .filter(({ node }) => {
        if (!node || seen.has(node.id)) return false;
        seen.add(node.id);
        return true;
      });
  }, [graph.edges, graph.nodes, selectedNode?.id]);
  const hiddenDownstream = downstreamRelations.filter(
    ({ node }) => node && !visibleIdSet.has(node.id),
  );

  const downstreamAttackRelations = downstreamRelations.filter(
    ({ node }) => node?.type === "攻击步骤",
  );
  const selectedBackboneIndex = backbone.findIndex(
    (node) => node.id === selectedNode?.id,
  );
  const expectedNextId =
    selectedBackboneIndex >= 0 ? backbone[selectedBackboneIndex + 1]?.id : undefined;
  const hasCandidatePaths = downstreamAttackRelations.length > 1;

  const revealNode = (node: GraphNode) => {
    setGraphMode("augmented");
    if (!visibleIds.includes(node.id)) {
      setExpansionHistory((current) => [...current, visibleIds].slice(-12));
      setVisibleIds([...visibleIds, node.id]);
    }
    setSelectedId(node.id);
  };

  const revealAllDownstream = () => {
    setGraphMode("augmented");
    const next = [
      ...new Set([
        ...visibleIds,
        ...downstreamRelations
          .map(({ node }) => node?.id)
          .filter((id): id is string => Boolean(id)),
      ]),
    ];
    if (next.length === visibleIds.length) return;
    setExpansionHistory((current) => [...current, visibleIds].slice(-12));
    setVisibleIds(next);
  };

  const undoLastExpansion = () => {
    const previous = expansionHistory[expansionHistory.length - 1];
    if (!previous) return;
    setExpansionHistory((current) => current.slice(0, -1));
    setVisibleIds(previous);
    if (!previous.includes(selectedId ?? "")) {
      setSelectedId(
        [...backbone]
          .reverse()
          .find((node) => previous.includes(node.id))?.id ?? previous[0],
      );
    }
  };

  const historicalCitations = useMemo(
    () =>
      historicalPath
        ? citationsForHistoricalPath(data, historicalPath)
        : [],
    [data, historicalPath],
  );
  const citations = useMemo(
    () =>
      uniqueSources([
        ...historicalCitations,
        ...citationsForCase(data, analysisInput.investigation),
        ...analysisInput.entities.flatMap((entity) =>
          citationsForEntity(data, entity.id),
        ),
      ]),
    [analysisInput.entities, analysisInput.investigation, data, historicalCitations],
  );
  const selectedCitations = historicalPath
    ? uniqueSources(
        citationsForHistoricalPath(data, historicalPath, selectedNode?.id),
      ).slice(0, 5)
    : selectedEntity
      ? uniqueSources(citationsForEntity(data, selectedEntity.id)).slice(0, 5)
      : citations.slice(0, 5);
  const advice = useMemo(
    () => adviceForCase(data, analysisInput.investigation).slice(0, 7),
    [analysisInput.investigation, data],
  );

  const eventNodes = graph.nodes.filter((node) => node.type === "历史事件");
  const actorLabels = [
    ...new Set(
      [
        ...graph.nodes
          .filter((node) => node.type === "攻击组织")
          .map((node) => node.label),
        ...graph.nodes
          .map((node) =>
            node.entity ? propString(node.entity, "actor") : "",
          )
          .filter(Boolean),
      ].filter(Boolean),
    ),
  ];
  const actorCandidates = actorLabels
    .map((label) => data.actors.find((actor) => actor.label === label))
    .filter((actor): actor is Actor => Boolean(actor))
    .map((actor) => ({
      actor,
      score: actorScore(actor, graph.nodes),
    }))
    .sort((left, right) => right.score - left.score)
    .slice(0, 3);
  const algorithm = data.algorithms[0];
  const weights = algorithm?.weights ?? {};
  const isCoreAttributionCase = eventNodes.some(
    (node) => node.id === "APT28-event-H2",
  );
  const attributionCandidates = isCoreAttributionCase
    ? ["APT28", "Lazarus", "组织 Z"]
        .map((label) => {
          const actor = data.actors.find((candidate) => candidate.label === label);
          const profile = coreCandidateProfiles[label];
          return actor && profile ? { actor, ...profile } : undefined;
        })
        .filter(
          (
            candidate,
          ): candidate is AttributionCandidateAssessment => Boolean(candidate),
        )
    : actorCandidates.map(({ actor, score }, index) => ({
        actor,
        score,
        decision: index === 0 ? "首要候选" : "一般关联",
        reason: "依据当前图谱中的实体、技战术与历史活动重合排序",
        gap: "需要补充组织专属基础设施、工具或权威公开来源",
      }));
  const primaryAttributionCandidate = attributionCandidates[0];
  const attributionPaths = isCoreAttributionCase ? coreAttributionPaths : [];
  const inputType = inferInputType(query);
  const observedAt = observedAtFromInput(query);
  const backboneIndex = new Map(
    backbone.map((node, index) => [node.id, index]),
  );
  const branchPointCount = new Set(
    graph.edges
      .filter((edge) => {
        const sourceIndex = backboneIndex.get(edge.source);
        if (sourceIndex === undefined) return false;
        const target = graph.nodes.find((node) => node.id === edge.target);
        const expectedNext = backbone[sourceIndex + 1]?.id;
        return target?.type === "攻击步骤" && edge.target !== expectedNext;
      })
      .map((edge) => edge.source),
  ).size;
  const pendingNodeCount = graph.nodes.filter(
    (node) =>
      node.status === "partial" ||
      (node.entity && propString(node.entity, "evidence_class") === "inference"),
  ).length;
  const blockedNodeCount = graph.nodes.filter(
    (node) =>
      node.status === "negative" ||
      (node.entity && propString(node.entity, "evidence_class") === "blocked"),
  ).length;
  const analysisStateCount = (state: string) =>
    backbone.filter(
      (node) =>
        node.entity && propString(node.entity, "analysis_state") === state,
    ).length;
  const observedStepCount = analysisStateCount("observed");
  const reconstructedStepCount = analysisStateCount("reconstructed");
  const predictedStepCount = analysisStateCount("predicted");
  const gapNodes = backbone.filter((node) => {
    const state = node.entity
      ? propString(node.entity, "analysis_state")
      : "";
    return state === "reconstructed" || state === "predicted";
  });
  const selectedEvidenceClass = selectedEntity
    ? evidenceClassLabel(propString(selectedEntity, "evidence_class"))
    : "待验证";
  const selectedEvidenceKey = selectedEntity
    ? propString(selectedEntity, "evidence_class")
    : "";
  const selectedAnalysisKey = selectedEntity
    ? propString(selectedEntity, "analysis_state")
    : "";
  const selectedAnalysisLabel = analysisStateLabel(selectedAnalysisKey);
  const selectedVerification =
    selectedEntity && propString(selectedEntity, "verification_needed");
  const selectedVerdictTitle =
    {
      reconstructed: "为什么补全这一步",
      predicted: "为什么预测这一步",
      candidate: "候选路径依据",
      blocked: "为什么判定已阻断",
    }[selectedAnalysisKey] ?? "这一步说明了什么";
  const selectedFacts = selectedEntity
    ? Object.entries(selectedEntity.properties)
        .filter(
          ([key, value]) =>
            propertyLabels[key] &&
            (typeof value === "string" || typeof value === "number"),
        )
        .slice(0, 6)
    : [];
  const lastConfirmedStage =
    [...backbone]
      .reverse()
      .find(
        (node) =>
          node.entity &&
          propString(node.entity, "analysis_state") === "observed",
      ) ?? backbone[backbone.length - 1];
  const selectedAdvice =
    advice.find((item) => {
      const label = selectedNode?.label ?? "";
      if (/提醒|Outlook|UNC/i.test(label)) return /扫描|修复/.test(item.title);
      if (/SMB|445/i.test(label)) return /阻断/.test(item.title);
      if (/NTLM|中继/i.test(label)) return /验证/.test(item.title);
      if (/EWS|邮箱|权限/i.test(label)) return /Exchange|清理/.test(item.title);
      return false;
    }) ?? advice[0];
  const comprehensiveAdvice = advice[0]
    ? `优先执行“${advice[0].title}”：${advice[0].recommendation} 对无法回到来源的关系保留为待验证，不自动升级为已发生事实、封禁或组织归因结论。`
    : "当前路径尚未命中可执行响应规则。请先核验输入命中与来源证据，再由分析员制定处置动作。";
  const responseGroupOrder = [
    "立即遏制",
    "排查狩猎",
    "清除恢复",
    "长期加固",
  ] as const;
  const responseGroups = responseGroupOrder.map((group) => ({
    group,
    items: advice.filter((item) => item.group === group),
  }));
  const focusedAdvice = advice.find((item) => item.id === focusedAdviceId);
  const focusedAdviceNodeIds = useMemo(
    () =>
      focusedAdvice
        ? nodeIdsForAdvice(focusedAdvice, graph.nodes, backbone)
        : [],
    [backbone, focusedAdvice, graph.nodes],
  );
  const focusedAdviceNodeIdSet = useMemo(
    () => new Set(focusedAdviceNodeIds),
    [focusedAdviceNodeIds],
  );
  const focusedAdviceEdgeIds = useMemo(
    () =>
      focusedAdvice
        ? graph.edges
            .filter(
              (edge) =>
                focusedAdviceNodeIdSet.has(edge.source) &&
                focusedAdviceNodeIdSet.has(edge.target),
            )
            .map((edge) => edge.id)
        : [],
    [focusedAdvice, focusedAdviceNodeIdSet, graph.edges],
  );

  const locateAdviceInGraph = (item: AdviceItem) => {
    if (focusedAdviceId === item.id) {
      setFocusedAdviceId(undefined);
      return;
    }
    const relatedIds = nodeIdsForAdvice(item, graph.nodes, backbone);
    const nextVisibleIds = [...new Set([...visibleIds, ...relatedIds])];
    if (nextVisibleIds.length !== visibleIds.length) {
      setExpansionHistory((current) => [...current, visibleIds].slice(-12));
      setVisibleIds(nextVisibleIds);
    }
    setGraphMode("augmented");
    setFocusedAdviceId(item.id);
    if (relatedIds[0]) setSelectedId(relatedIds[0]);
    setPanelTab("verdict");
    window.requestAnimationFrame(() => {
      const reduceMotion =
        window
          .matchMedia?.("(prefers-reduced-motion: reduce)")
          .matches ?? false;
      analysisGraphRef.current?.scrollIntoView?.({
        behavior: reduceMotion ? "auto" : "smooth",
        block: "center",
      });
    });
  };

  const toggleGapFocus = () => {
    setGapFocus((current) => {
      const next = !current;
      if (next) {
        setGraphMode("augmented");
        setVisibleIds((ids) => [
          ...new Set([...ids, ...gapNodes.map((node) => node.id)]),
        ]);
        if (gapNodes[0]) setSelectedId(gapNodes[0].id);
        setPanelTab("verdict");
      }
      return next;
    });
  };

  const exportResponseReport = () => {
    const sections = [
      "# ARGUS 威胁情报处置报告",
      "",
      `- 调查对象：${eventNodes[0]?.label || analysisInput.investigation.title}`,
      `- 输入类型：${inputType}`,
      `- 主路径：${backbone.map((node) => node.label).join(" → ")}`,
      `- 图谱规模：${graph.nodes.length} 个节点 / ${graph.edges.length} 条关系 / ${branchPointCount} 个分支点`,
      `- 证据状态：${pendingNodeCount} 个待验证节点 / ${blockedNodeCount} 个阻断或反证节点`,
      "",
      "## 处置建议",
      "",
      ...advice.flatMap((item, index) => [
        `### ${index + 1}. [${item.priority}] ${item.title}`,
        "",
        `- 阶段：${item.group}`,
        `- 建议：${item.recommendation}`,
        `- 依据：${item.rationale}`,
        item.sourceUrl ? `- 来源：${item.sourceUrl}` : "",
        "",
      ]),
      "## 证据边界",
      "",
      "公开确认、演示观测、多源关联、分析推断与阻断反证已分层呈现；单一端点事件不自动升级为凭据泄露或组织归因结论。",
    ];
    const blob = new Blob([sections.filter(Boolean).join("\n")], {
      type: "text/markdown;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "ARGUS-CVE-2023-23397-response.md";
    link.click();
    URL.revokeObjectURL(url);
  };

  const attributionScoreGap =
    attributionCandidates.length > 1
      ? attributionCandidates[0].score - attributionCandidates[1].score
      : attributionCandidates[0]?.score ?? 0;
  const attributionLedger = isCoreAttributionCase
    ? coreAttributionLedger
    : [
        {
          tone: "supporting",
          label: "一般支持",
          fact: "当前实体、技战术和历史活动存在重合，但尚未形成组织专属证据路径。",
          impact: "+0",
        },
        {
          tone: "gap",
          label: "证据缺口",
          fact: "需要补充权威公开来源、专属工具或基础设施复用证据。",
          impact: "-0",
        },
      ];

  return (
    <main className="threat-analysis-page">
      <div
        className={`threat-analysis-inner ${gapFocus ? "is-gap-focus" : ""}`}
      >
        <button type="button" className="back-link" onClick={onBack}>
          <ArrowLeft size={15} /> {backLabel}
        </button>

        <header className="threat-analysis-heading is-compact">
          <div>
            <span>威胁情报综合分析</span>
            <h1>
              {selectedPath?.title ||
                eventNodes[0]?.label ||
                "已完成情报关联分析"}
            </h1>
            <p>
              {selectedPath?.summary ||
                "结构化输入、关系证据和公开情报已完成关联，结论按证据等级分层展示。"}
            </p>
          </div>
          <dl>
            <div>
              <dt>输入类型</dt>
              <dd>{inputType}</dd>
            </div>
            <div>
              <dt>命中实体</dt>
              <dd>{analysisInput.entities.length}</dd>
            </div>
            <div>
              <dt>时间范围</dt>
              <dd>
                {observedAt || backbone[0]?.entity?.first_seen?.slice(0, 10) || "持续活动"}
              </dd>
            </div>
            <div>
              <dt>来源报告</dt>
              <dd>{new Set(citations.map((item) => item.reportId)).size}</dd>
            </div>
          </dl>
        </header>

        <section className="analysis-value-strip" aria-label="系统研判结论">
          <div className="analysis-value-summary">
            <span>系统研判</span>
            <strong>
              已确认推进至：{lastConfirmedStage?.label || "待确认阶段"}
            </strong>
            <p>
              基于 {observedStepCount} 个输入命中，补全 {reconstructedStepCount}{" "}
              个缺失步骤并展示 {predictedStepCount} 个历史后续步骤。完整路径不是输入原文的复述。
            </p>
          </div>
          <div className="analysis-value-metrics" aria-label="路径研判统计">
            <div className="analysis-value-metric">
              <span>输入命中</span>
              <strong>{observedStepCount}</strong>
              <small>来自输入信号</small>
            </div>
            <button
              type="button"
              className={gapFocus ? "is-active" : ""}
              aria-pressed={gapFocus}
              onClick={toggleGapFocus}
            >
              <span>补全步骤</span>
              <strong>{reconstructedStepCount}</strong>
              <small>点击定位缺口</small>
            </button>
            <button
              type="button"
              className={gapFocus ? "is-active" : ""}
              aria-pressed={gapFocus}
              onClick={toggleGapFocus}
            >
              <span>后续预测</span>
              <strong>{predictedStepCount}</strong>
              <small>点击定位缺口</small>
            </button>
          </div>
          <div className="analysis-next-action">
            <span>首要动作 · {advice[0]?.priority || "P0"}</span>
            <strong>{advice[0]?.title || "复核关键证据"}</strong>
            <p>{advice[0]?.recommendation}</p>
          </div>
        </section>

        <section className="analysis-stage-rail" aria-label="攻击阶段判定">
          <header>
            <div>
              <strong>攻击阶段判定</strong>
              <span>点击阶段可同步定位图谱与右侧研判面板</span>
            </div>
            <div className="stage-rail-legend" aria-label="研判状态图例">
              <span className="is-observed">输入命中</span>
              <span className="is-reconstructed">路径补全</span>
              <span className="is-predicted">后续预测</span>
            </div>
          </header>
          <div className="stage-rail-track">
            {backbone.map((node, index) => {
              const evidenceKey = node.entity
                ? propString(node.entity, "evidence_class")
                : "";
              const analysisKey = node.entity
                ? propString(node.entity, "analysis_state")
                : "";
              const concealed =
                graphMode === "original" && analysisKey !== "observed";
              const displayLabel = concealed
                ? analysisKey === "predicted"
                  ? "未知后续"
                  : "缺失环节"
                : node.label;
              return (
                <button
                  type="button"
                  key={node.id}
                  disabled={concealed}
                  className={`stage-rail-step evidence-${evidenceKey || "unknown"} analysis-${analysisKey || "unknown"} ${
                    selectedNode?.id === node.id ? "is-selected" : ""
                  }`}
                  onClick={() => setSelectedId(node.id)}
                >
                  <span className="stage-index">
                    {node.status === "negative" ? (
                      <AlertTriangle size={12} />
                    ) : (
                      <CheckCircle2 size={12} />
                    )}
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <strong>{displayLabel}</strong>
                  <small>
                    {concealed
                      ? "输入中未出现"
                      : `${analysisStateLabel(analysisKey)} · ${Math.round(
                          (node.confidence ?? 0) * 100,
                        )}%`}
                  </small>
                </button>
              );
            })}
          </div>
        </section>

        <section className="analysis-graph-layout">
          <div className="analysis-graph-panel" ref={analysisGraphRef}>
            <header>
              <div>
                <h2>关联知识图谱</h2>
                <p>
                  {graphMode === "original"
                    ? "仅显示本次输入直接命中的信号与对象。"
                    : "主路径横向固定，补全、预测和候选分支按真实关系展开。"}
                </p>
              </div>
              <div className="analysis-graph-toolbar">
                <div
                  className="analysis-graph-mode"
                  role="group"
                  aria-label="图谱展示模式"
                >
                  <button
                    type="button"
                    className={graphMode === "original" ? "is-active" : ""}
                    aria-pressed={graphMode === "original"}
                    onClick={() => {
                      setGraphMode("original");
                      setGapFocus(false);
                      const observedSelection = backbone.find((node) =>
                        observedBackboneIds.has(node.id),
                      );
                      if (observedSelection) setSelectedId(observedSelection.id);
                    }}
                  >
                    原始线索 {observedStepCount}
                  </button>
                  <button
                    type="button"
                    className={graphMode === "augmented" ? "is-active" : ""}
                    aria-pressed={graphMode === "augmented"}
                    onClick={() => setGraphMode("augmented")}
                  >
                    补全研判 {backbone.length}
                  </button>
                </div>
                <div className="analysis-graph-counts">
                  <span>{visibleNodes.length} 节点</span>
                  <span>{visibleEdges.length} 关系</span>
                </div>
              </div>
            </header>
            {focusedAdvice && (
              <div className="analysis-graph-focus-bar" role="status">
                <Crosshair size={15} />
                <div>
                  <span>处置动作反向定位</span>
                  <strong>{focusedAdvice.title}</strong>
                  <small>
                    已高亮 {focusedAdviceNodeIds.length} 个关联节点和{" "}
                    {focusedAdviceEdgeIds.length} 条路径关系
                  </small>
                </div>
                <button
                  type="button"
                  aria-label="清除处置路径高亮"
                  onClick={() => setFocusedAdviceId(undefined)}
                >
                  <X size={14} />
                </button>
              </div>
            )}
            <NetworkGraph
              nodes={visibleNodes}
              edges={visibleEdges}
              rootId={backbone[0]?.id ?? rootIds[0]}
              selectedId={selectedNode?.id}
              highlightIds={
                focusedAdvice ? focusedAdviceNodeIds : rootIds
              }
              highlightEdgeIds={focusedAdviceEdgeIds}
              edgeAnnotations={edgeAnnotations}
              hiddenNeighborCounts={hiddenNeighborCounts}
              focusMode={Boolean(focusedAdvice)}
              layout="path"
              pathIds={backboneIds}
              onSelect={(node) => setSelectedId(node.id)}
            />
          </div>

          <aside className="analysis-context-panel">
            <section className="analysis-investigation-panel">
              <header className="investigation-panel-heading">
                <div>
                  <span>当前研判节点</span>
                  <h2>{selectedNode?.label || "请选择图谱节点"}</h2>
                </div>
                {selectedNode && (
                  <StatusBadge status={selectedNode.status ?? "positive"} />
                )}
              </header>

              <div className="investigation-verdict-bar">
                <div>
                  <span>研判状态</span>
                  <strong>{selectedAnalysisLabel}</strong>
                </div>
                <div>
                  <span>置信度</span>
                  <strong>
                    {Math.round(
                      (selectedNode?.confidence ??
                        (selectedEntity
                          ? propNumber(selectedEntity, "confidence")
                          : 0)) * 100,
                    )}
                    %
                  </strong>
                </div>
                <div>
                  <span>直接关系</span>
                  <strong>{selectedEdges.length}</strong>
                </div>
              </div>

              <div className="investigation-tabs" role="tablist" aria-label="节点研判内容">
                {[
                  ["verdict", "研判"],
                  ["evidence", "证据"],
                  ["logs", "原始信息"],
                  ["sources", "来源"],
                ].map(([id, label]) => (
                  <button
                    type="button"
                    role="tab"
                    key={id}
                    aria-selected={panelTab === id}
                    className={panelTab === id ? "is-active" : ""}
                    onClick={() =>
                      setPanelTab(
                        id as "verdict" | "evidence" | "logs" | "sources",
                      )
                    }
                  >
                    {label}
                  </button>
                ))}
              </div>

              <div className="investigation-tab-content">
                {panelTab === "verdict" && (
                  <div className="investigation-verdict">
                    <div className="verdict-statement">
                      <Activity size={15} />
                      <div>
                        <strong>{selectedVerdictTitle}</strong>
                        <p>
                          {(selectedEntity
                            ? propString(selectedEntity, "match_reason")
                            : "") ||
                            selectedEntity?.description ||
                            "点击图谱中的节点查看该行为在当前攻击过程中的意义。"}
                        </p>
                      </div>
                    </div>
                    <div className="evidence-gap-note">
                      <AlertTriangle size={14} />
                      <div>
                        <strong>下一项验证</strong>
                        <p>
                          {selectedVerification ||
                            evidenceGapFor(selectedEvidenceKey)}
                        </p>
                      </div>
                    </div>
                    <div className="analysis-expansion-controls">
                      <button
                        type="button"
                        className="expand-all-button"
                        disabled={!hiddenDownstream.length}
                        onClick={revealAllDownstream}
                      >
                        <CornerDownRight size={14} />
                        <span>
                          <strong>展开全部直接下游</strong>
                          <small>
                            {hiddenDownstream.length
                              ? `将显示 ${hiddenDownstream.length} 个节点`
                              : "直接下游已全部显示"}
                          </small>
                        </span>
                      </button>
                      <button
                        type="button"
                        className="undo-expansion-button"
                        disabled={!expansionHistory.length}
                        onClick={undoLastExpansion}
                      >
                        <Undo2 size={14} />
                        <span>
                          <strong>撤销上次展开</strong>
                          <small>
                            {expansionHistory.length
                              ? `可回退 ${expansionHistory.length} 次`
                              : "尚未展开新节点"}
                          </small>
                        </span>
                      </button>
                    </div>
                    <div className="analysis-neighbor-list is-directed">
                      <div className="relation-list-heading">
                        <strong>
                          {hasCandidatePaths ? "候选路径" : "下游关系"}
                        </strong>
                        <span>{downstreamRelations.length}</span>
                      </div>
                      {downstreamRelations.length ? (
                        downstreamRelations.map(({ edge, node }) => {
                          const isAttackPath = node?.type === "攻击步骤";
                          const isMainPath = node?.id === expectedNextId;
                          const analysisState = node?.entity
                            ? propString(node.entity, "analysis_state")
                            : "";
                          const pathLabel =
                            edgeAnnotations[edge.id]?.label ||
                            (isMainPath
                              ? "主路径"
                              : analysisState === "blocked"
                                ? "阻断分支"
                                : isAttackPath
                                  ? "候选"
                                  : "");
                          return (
                            <button
                              type="button"
                              key={edge.id}
                              className={`${node && visibleIdSet.has(node.id) ? "is-visible" : ""} ${isAttackPath && !isMainPath ? "is-candidate" : ""}`}
                              onClick={() => node && revealNode(node)}
                            >
                              <span>
                                <strong>{node?.label}</strong>
                                <small>
                                  {edge.label}
                                  {pathLabel ? ` · ${pathLabel}` : ""}
                                </small>
                              </span>
                              {isAttackPath && (
                                <b>
                                  排序分{" "}
                                  {Math.round(
                                    (edge.confidence ??
                                      node?.confidence ??
                                      0) * 100,
                                  )}
                                </b>
                              )}
                              {node && visibleIdSet.has(node.id) ? (
                                <ArrowRight size={13} />
                              ) : (
                                <Plus size={13} />
                              )}
                            </button>
                          );
                        })
                      ) : (
                        <p>当前节点没有已知下游关系。</p>
                      )}
                    </div>
                    <div className="analysis-upstream">
                      <button
                        type="button"
                        onClick={() => setShowUpstream((current) => !current)}
                      >
                        <span>查看上游来源</span>
                        <span>
                          {upstreamRelations.length}
                          {showUpstream ? (
                            <ChevronUp size={13} />
                          ) : (
                            <ChevronDown size={13} />
                          )}
                        </span>
                      </button>
                      {showUpstream && (
                        <div>
                          {upstreamRelations.length ? (
                            upstreamRelations.map(({ edge, node }) => (
                              <button
                                type="button"
                                key={edge.id}
                                onClick={() => node && revealNode(node)}
                              >
                                <span>
                                  <strong>{node?.label}</strong>
                                  <small>{edge.label}</small>
                                </span>
                                <ArrowRight size={13} />
                              </button>
                            ))
                          ) : (
                            <p>当前节点没有已知上游来源。</p>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {panelTab === "evidence" && (
                  <div className="investigation-evidence-list">
                    <div className="evidence-class-summary">
                      <ClipboardCheck size={15} />
                      <div>
                        <strong>
                          {selectedAnalysisLabel} · {selectedEvidenceClass}
                        </strong>
                        <p>
                          {selectedVerification ||
                            evidenceGapFor(selectedEvidenceKey)}
                        </p>
                      </div>
                    </div>
                    {selectedCitations.length ? (
                      selectedCitations.map((citation) => (
                        <button
                          type="button"
                          key={citation.id}
                          onClick={() => setSource(citation)}
                        >
                          <span>{citation.publisher}</span>
                          <strong>{citation.excerpt}</strong>
                          <small>
                            {citation.location} ·{" "}
                            {Math.round(citation.confidence * 100)}%
                          </small>
                        </button>
                      ))
                    ) : (
                      <p>当前节点暂无独立证据摘录。</p>
                    )}
                  </div>
                )}

                {panelTab === "logs" && (
                  <div className="investigation-raw-facts">
                    <div className="raw-fact-heading">
                      <FileCode2 size={15} />
                      <div>
                        <strong>结构化实体信息</strong>
                        <span>{selectedNode?.type}</span>
                      </div>
                    </div>
                    <dl>
                      {selectedEntity?.first_seen && (
                        <div>
                          <dt>首次观测</dt>
                          <dd>{selectedEntity.first_seen}</dd>
                        </div>
                      )}
                      {selectedFacts.map(([key, value]) => (
                        <div key={key}>
                          <dt>{propertyLabels[key]}</dt>
                          <dd>{String(value)}</dd>
                        </div>
                      ))}
                    </dl>
                    <div className="raw-relation-list">
                      <strong>直接关系记录</strong>
                      {selectedEdges.map((edge) => (
                        <div key={edge.id}>
                          <span>{edge.label}</span>
                          <small>
                            {Math.round((edge.confidence ?? 0) * 100)}% ·{" "}
                            {edge.status}
                          </small>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {panelTab === "sources" && (
                  <div className="investigation-source-list">
                    {selectedCitations.length ? (
                      selectedCitations.map((citation) => (
                        <button
                          type="button"
                          key={citation.id}
                          onClick={() => setSource(citation)}
                        >
                          <FileSearch size={14} />
                          <span>
                            <strong>{citation.title}</strong>
                            <small>
                              {citation.publisher} · {citation.reportDate}
                            </small>
                          </span>
                          <b>{Math.round(citation.confidence * 100)}%</b>
                        </button>
                      ))
                    ) : (
                      <p>当前节点暂无可追溯来源。</p>
                    )}
                  </div>
                )}
              </div>

              <div className="investigation-next-step">
                <ListChecks size={15} />
                <div>
                  <span>下一步核查 · {selectedAdvice?.priority || "P0"}</span>
                  <strong>{selectedAdvice?.title || "复核关键证据"}</strong>
                  <p>{selectedAdvice?.recommendation}</p>
                </div>
              </div>
            </section>
          </aside>
        </section>

        <section className="analysis-swimlane-panel">
          <GraphSwimlaneProjection
            nodes={graph.nodes}
            edges={graph.edges}
            rootIds={rootIds}
            backbone={projectedBackbone}
            visibleIds={effectiveVisibleIds}
            selectedId={selectedNode?.id}
            onSelect={(node) => setSelectedId(node.id)}
          />
        </section>

        <section className="analysis-response">
          <header>
            <div>
              <h2>处置响应方案</h2>
              <p>依据已识别实体和攻击阶段给出可执行的核查、阻断和检测建议。</p>
            </div>
            <div className="analysis-response-actions">
              <span>{advice.length} 条响应建议</span>
              <button type="button" onClick={exportResponseReport}>
                <Download size={13} />
                导出处置报告
              </button>
            </div>
          </header>
          <div className="analysis-response-runbook">
            {responseGroups.map(({ group, items }, groupIndex) => {
              const expanded = expandedResponseGroups.includes(group);
              const topPriority = items[0]?.priority ?? "P2";
              return (
                <section
                  key={group}
                  className={`response-runbook-group ${expanded ? "is-expanded" : ""}`}
                >
                  <button
                    type="button"
                    aria-expanded={expanded}
                    onClick={() =>
                      setExpandedResponseGroups((current) =>
                        current.includes(group)
                          ? current.filter((item) => item !== group)
                          : [...current, group],
                      )
                    }
                  >
                    <span className="runbook-index">
                      {String(groupIndex + 1).padStart(2, "0")}
                    </span>
                    <span className="runbook-title">
                      <strong>{group}</strong>
                      <small>{items.length} 项响应动作</small>
                    </span>
                    <b>{topPriority}</b>
                    {expanded ? (
                      <ChevronUp size={15} />
                    ) : (
                      <ChevronDown size={15} />
                    )}
                  </button>
                  {expanded && (
                    <div className="response-runbook-items">
                      {items.map((item) => {
                        const relatedNodeCount = nodeIdsForAdvice(
                          item,
                          graph.nodes,
                          backbone,
                        ).length;
                        const focused = focusedAdviceId === item.id;
                        return (
                          <button
                            type="button"
                            key={item.id}
                            className={focused ? "is-focused" : ""}
                            aria-pressed={focused}
                            onClick={() => locateAdviceInGraph(item)}
                          >
                            <span>{item.priority}</span>
                            <div>
                              <div className="response-item-heading">
                                <h3>{item.title}</h3>
                                <b>
                                  <Crosshair size={12} />
                                  {focused
                                    ? "已定位"
                                    : `定位 ${relatedNodeCount} 步`}
                                </b>
                              </div>
                              <p>{item.recommendation}</p>
                              <small>{item.rationale}</small>
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </section>
              );
            })}
          </div>
          <div className="analysis-comprehensive-advice">
            <ShieldCheck size={18} />
            <div>
              <strong>综合建议</strong>
              <p>{comprehensiveAdvice}</p>
            </div>
          </div>
        </section>

        <section className={`analysis-attribution ${attributionOpen ? "is-open" : ""}`}>
          <button
            type="button"
            className="attribution-toggle"
            aria-expanded={attributionOpen}
            onClick={() => setAttributionOpen((current) => !current)}
          >
            <div>
              <h2>归因分析与可解释链路</h2>
              <p>比较候选差异，核验证据路径，并明确仍未被证明的部分。</p>
            </div>
            <div className="attribution-toggle-summary">
              <span>结论等级</span>
              <strong>
                {primaryAttributionCandidate?.actor.label || "证据不足"}
              </strong>
              <em>
                {primaryAttributionCandidate?.decision || "待补充证据"}
              </em>
              <b>{primaryAttributionCandidate?.score ?? 0}</b>
              {attributionOpen ? (
                <ChevronUp size={16} />
              ) : (
                <ChevronDown size={16} />
              )}
            </div>
          </button>
          {attributionOpen && (
            <div className="analysis-attribution-layout is-review-ledger">
              <div className="attribution-review-top">
                <section className="attribution-verdict-panel">
                  <header>
                    <Target size={19} />
                    <div>
                      <span>首要组织候选</span>
                      <h3>
                        {primaryAttributionCandidate?.actor.label ||
                          "暂无组织候选"}
                      </h3>
                    </div>
                    <StatusBadge status="candidate">
                      {primaryAttributionCandidate?.decision || "待补充证据"}
                    </StatusBadge>
                  </header>
                  <p>
                    {primaryAttributionCandidate
                      ? `${primaryAttributionCandidate.actor.public_attribution} 本次得分用于候选排序，不表示统计概率，也不等同于确认归因。`
                      : "现有证据不足以形成组织候选，平台不会仅凭单一 IOC 作出归因。"}
                  </p>
                  <dl>
                    <div>
                      <dt>关联得分</dt>
                      <dd>{primaryAttributionCandidate?.score ?? 0}</dd>
                    </div>
                    <div>
                      <dt>领先分差</dt>
                      <dd>+{attributionScoreGap}</dd>
                    </div>
                    <div>
                      <dt>强支持路径</dt>
                      <dd>
                        {
                          attributionPaths.filter(
                            (path) => path.tone === "strong",
                          ).length
                        }
                      </dd>
                    </div>
                    <div>
                      <dt>证据缺口</dt>
                      <dd>
                        {
                          attributionLedger.filter(
                            (item) => item.tone === "gap",
                          ).length
                        }
                      </dd>
                    </div>
                  </dl>
                  {primaryAttributionCandidate && (
                    <div className="attribution-verdict-gap">
                      <ShieldAlert size={15} />
                      <span>
                        <strong>尚未证明</strong>
                        {primaryAttributionCandidate.gap}
                      </span>
                    </div>
                  )}
                </section>

                <section className="attribution-candidate-comparison">
                  <header>
                    <div>
                      <h3>候选组织对比</h3>
                      <p>排名依据决定性差异，而不是通用行为相似度。</p>
                    </div>
                    <span>{attributionCandidates.length} 个候选</span>
                  </header>
                  <div
                    className="attribution-candidate-table"
                    role="table"
                    aria-label="候选组织对比"
                  >
                    {attributionCandidates.map((candidate, index) => (
                      <div
                        key={candidate.actor.id}
                        role="row"
                        className={index === 0 ? "is-primary" : ""}
                      >
                        <span role="cell">
                          <b>{candidate.actor.label}</b>
                          <small>{candidate.decision}</small>
                        </span>
                        <p role="cell">{candidate.reason}</p>
                        <strong role="cell">{candidate.score}</strong>
                      </div>
                    ))}
                  </div>
                </section>
              </div>

              <section className="attribution-paths">
                <header>
                  <div>
                    <h3>可解释证据路径</h3>
                    <p>
                      点击任一路径，进入候选组织真实知识图谱并核验本案命中位置。
                    </p>
                  </div>
                  <span>
                    <Network size={14} />
                    图谱核验
                  </span>
                </header>
                <div className="attribution-path-list">
                  {attributionPaths.map((path) => {
                    const pathSources = citationsForAttributionPath(
                      citations,
                      path,
                    );
                    return (
                      <button
                        type="button"
                        key={path.id}
                        className={`attribution-path-row is-${path.tone}`}
                        aria-label={`查看归因路径图谱：${path.title}`}
                        onClick={() => setSelectedAttributionPath(path)}
                      >
                        <GitBranch size={17} />
                        <span>
                          <strong>{path.title}</strong>
                          <small>{path.summary}</small>
                        </span>
                        <em>
                          {pathSources.length
                            ? `${pathSources.length} 个可追溯来源`
                            : "暂无原始来源"}
                        </em>
                        <b>{path.contribution}</b>
                        <ArrowRight size={16} />
                      </button>
                    );
                  })}
                  {!attributionPaths.length && (
                    <p className="attribution-empty-path">
                      当前情报尚未形成可进入组织图谱核验的连续证据路径。
                    </p>
                  )}
                </div>
              </section>

              <section className="attribution-evidence-ledger">
                <header>
                  <div>
                    <h3>证据账本</h3>
                    <p>支持、无效证据和缺口在同一处呈现。</p>
                  </div>
                  <span>本案实际贡献</span>
                </header>
                <div>
                  {attributionLedger.map((item, index) => (
                    <article
                      key={`${item.label}-${index}`}
                      className={`is-${item.tone}`}
                    >
                      <span>{item.label}</span>
                      <p>{item.fact}</p>
                      <strong>{item.impact}</strong>
                    </article>
                  ))}
                </div>
              </section>

              <details className="attribution-algorithm-audit">
                <summary>
                  <span>
                    <ClipboardCheck size={15} />
                    查看评分算法与权重
                  </span>
                  <ChevronDown size={15} />
                </summary>
                <div>
                  <dl>
                    <div>
                      <dt>路径连续性</dt>
                      <dd>{Math.round((weights.path ?? 0) * 100)}%</dd>
                    </div>
                    <div>
                      <dt>实体重合</dt>
                      <dd>{Math.round((weights.entity ?? 0) * 100)}%</dd>
                    </div>
                    <div>
                      <dt>TTP 重合</dt>
                      <dd>{Math.round((weights.technique ?? 0) * 100)}%</dd>
                    </div>
                    <div>
                      <dt>来源可靠性</dt>
                      <dd>{Math.round((weights.source ?? 0) * 100)}%</dd>
                    </div>
                  </dl>
                  <p>
                    {algorithm?.description ||
                      "候选排序只用于辅助分析，必须结合原始来源和反证复核。"}
                  </p>
                </div>
              </details>
            </div>
          )}
        </section>
      </div>

      {selectedAttributionPath && primaryAttributionCandidate && (
        <AttributionGraphDialog
          key={selectedAttributionPath.id}
          data={data}
          actor={primaryAttributionCandidate.actor}
          path={selectedAttributionPath}
          citations={citations}
          onOpenSource={setSource}
          onClose={() => setSelectedAttributionPath(undefined)}
        />
      )}
      {source && (
        <SourceViewer citation={source} onClose={() => setSource(undefined)} />
      )}
    </main>
  );
}
