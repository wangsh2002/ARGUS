"use client";

import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Bot,
  BrainCircuit,
  Check,
  ChevronDown,
  CircleDot,
  Clock3,
  Database,
  ExternalLink,
  FileSearch,
  FileText,
  Filter,
  GitBranch,
  Globe2,
  History,
  Info,
  Layers3,
  Link2,
  Menu,
  Network,
  Paperclip,
  PanelRight,
  Search,
  Send,
  Shield,
  ShieldAlert,
  Sparkles,
  Target,
  Upload,
  Users,
  X,
  Zap,
} from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { NetworkGraph } from "./NetworkGraph";
import type {
  Actor,
  Entity,
  GraphEdge,
  GraphNode,
  Report,
  Snapshot,
} from "./types";

type Page = "search" | "analysis" | "gpt" | "actors" | "graph";
type SearchMode = "intel" | "graph" | "gpt";

const pageLabels: Array<{ id: Page; label: string; icon: typeof Search }> = [
  { id: "search", label: "综合查询", icon: Search },
  { id: "analysis", label: "情报综合分析", icon: BrainCircuit },
  { id: "gpt", label: "GPT", icon: Bot },
  { id: "actors", label: "攻击组织总揽", icon: Users },
];

const modeLabels: Array<{ id: SearchMode; label: string; icon: typeof Search }> = [
  { id: "intel", label: "威胁情报", icon: ShieldAlert },
  { id: "graph", label: "Graph", icon: Network },
  { id: "gpt", label: "GPT 提问", icon: Sparkles },
];

function propString(entity: Entity, key: string) {
  const value = entity.properties[key];
  return typeof value === "string" ? value : "";
}

function propNumber(entity: Entity, key: string, fallback = 0.7) {
  const value = entity.properties[key];
  return typeof value === "number" ? value : fallback;
}

function normalize(value: string) {
  return value.trim().toLocaleLowerCase().replace(/\s+/g, " ");
}

function formatDate(value?: string | null) {
  if (!value) return "时间未记录";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

function getChainParts(query: string) {
  return query
    .split(/\s*(?:→|->|=>|＞|然后|再到)\s*|\n+/)
    .map((part) => part.replace(/^[\d.、\s]+/, "").trim())
    .filter((part) => part.length > 1);
}

function detectQueryType(query: string) {
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

function searchSnapshot(data: Snapshot, query: string) {
  const q = normalize(query);
  const chainParts = getChainParts(query).map(normalize);
  const entityScores = data.entities
    .map((entity) => {
      const haystack = entityHaystack(entity);
      const label = normalize(entity.label);
      const value = normalize(propString(entity, "entity_value"));
      let score = 0;
      if (label === q || value === q || normalize(entity.normalized_value) === q) score = 100;
      else if (q.includes(label) && label.length >= 3) score = 78;
      else if (haystack.includes(q) && q.length >= 3) score = 64;
      chainParts.forEach((part) => {
        if (label === part || value === part) score = Math.max(score, 92);
        else if (part.length >= 3 && haystack.includes(part)) score = Math.max(score, 76);
      });
      const tokens = q.split(/[\s，。；、?？]+/).filter((token) => token.length >= 3);
      tokens.forEach((token) => {
        if (haystack.includes(token)) score += 14;
      });
      return { entity, score };
    })
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score || b.entity.source_count - a.entity.source_count);

  const reports = data.reports
    .map((report) => {
      const haystack = normalize(
        `${report.title} ${report.source} ${report.extracted_text} ${report.assessment}`,
      );
      let score = haystack.includes(q) && q.length >= 3 ? 55 : 0;
      entityScores.slice(0, 12).forEach(({ entity }) => {
        if (haystack.includes(normalize(entity.label))) score += 6;
      });
      return { report, score };
    })
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score);

  return { entities: entityScores, reports };
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

function buildSubgraph(
  data: Snapshot,
  seedIds: string[],
  limit = 34,
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

function buildChainGraph(data: Snapshot, query: string) {
  const parts = getChainParts(query);
  const used = new Set<string>();
  const nodes: GraphNode[] = parts.map((part, index) => {
    const normalizedPart = normalize(part);
    const match = data.entities
      .filter((entity) => !used.has(entity.id))
      .map((entity) => {
        const label = normalize(entity.label);
        const value = normalize(propString(entity, "entity_value"));
        let score = label === normalizedPart || value === normalizedPart ? 100 : 0;
        if (!score && entityHaystack(entity).includes(normalizedPart)) score = 70;
        if (!score && normalizedPart.includes(label) && label.length >= 3) score = 60;
        return { entity, score };
      })
      .sort((a, b) => b.score - a.score)[0];
    if (match?.score) used.add(match.entity.id);
    return match?.score
      ? {
          ...entityToNode(match.entity),
          id: `chain-${index}-${match.entity.id}`,
          label: match.entity.label,
          status: match.entity.properties.status === "negative" ? "negative" : "hot",
        }
      : {
          id: `chain-${index}`,
          label: part,
          type: "输入步骤",
          status: "partial",
          confidence: 0,
          virtual: true,
        };
  });
  const edges: GraphEdge[] = nodes.slice(1).map((node, index) => ({
    id: `chain-edge-${index}`,
    source: nodes[index].id,
    target: node.id,
    label: "输入时序",
    status: node.virtual ? "partial" : "hot",
  }));
  return { nodes, edges, matched: nodes.filter((node) => !node.virtual).length };
}

function actorForEntity(entity: Entity) {
  return propString(entity, "actor");
}

function actorStats(data: Snapshot, actor: Actor) {
  const related = data.entities.filter((entity) => actorForEntity(entity) === actor.label);
  return {
    events: related.filter((entity) => entity.entity_type === "历史事件").length,
    iocs: related.filter((entity) => entity.entity_type === "IOC/基础设施").length,
    tools: related.filter((entity) => entity.entity_type === "恶意软件/工具").length,
    steps: related.filter((entity) => entity.entity_type === "攻击步骤").length,
  };
}

function matchingReports(data: Snapshot, actor: Actor) {
  return data.reports
    .filter(
      (report) =>
        actor.source_refs.includes(report.source_ref) ||
        normalize(report.extracted_text).includes(normalize(actor.label)),
    )
    .sort((a, b) => (b.report_date || "").localeCompare(a.report_date || ""));
}

function getAnalysis(data: Snapshot, text: string) {
  const normalizedText = normalize(text);
  const matched = data.entities
    .filter((entity) => {
      const candidates = [
        entity.label,
        propString(entity, "entity_value"),
        entity.normalized_value,
      ]
        .map(normalize)
        .filter((value) => value.length >= 3);
      return candidates.some((value) => normalizedText.includes(value));
    })
    .sort(
      (a, b) =>
        propNumber(b, "confidence") - propNumber(a, "confidence") ||
        b.label.length - a.label.length,
    );

  const actorMap = new Map<
    string,
    { actor: Actor; entities: Entity[]; support: number; negative: number }
  >();
  matched.forEach((entity) => {
    const actorName = actorForEntity(entity);
    const actor = data.actors.find((item) => item.label === actorName);
    if (!actor) return;
    const record = actorMap.get(actor.id) ?? {
      actor,
      entities: [],
      support: 0,
      negative: 0,
    };
    record.entities.push(entity);
    if (propString(entity, "status") === "negative") {
      record.negative += 1;
    } else {
      record.support += propNumber(entity, "confidence");
    }
    actorMap.set(actor.id, record);
  });
  const candidates = [...actorMap.values()]
    .map((item) => {
      const diversity = new Set(item.entities.map((entity) => entity.entity_type)).size;
      const pathDiversity = new Set(item.entities.map((entity) => propString(entity, "event")))
        .size;
      const raw =
        item.support / Math.max(item.entities.length, 1) +
        Math.min(0.08, diversity * 0.015) +
        Math.min(0.06, pathDiversity * 0.015) -
        item.negative * 0.05;
      return { ...item, score: Math.max(0, Math.min(0.99, raw)) };
    })
    .sort((a, b) => b.score - a.score);
  return { matched: matched.slice(0, 26), candidates };
}

function Logo({ small = false }: { small?: boolean }) {
  return (
    <span className={`brand-mark ${small ? "small" : ""}`} aria-hidden="true">
      <span>A</span>
    </span>
  );
}

function RiskBadge({ status = "positive" }: { status?: string }) {
  const label =
    status === "negative" ? "反证" : status === "hot" ? "高置信" : status === "partial" ? "部分" : "已验证";
  return <span className={`risk-badge status-${status}`}>{label}</span>;
}

function AppHeader({
  page,
  query,
  onQuery,
  onSubmit,
  onNavigate,
}: {
  page: Page;
  query: string;
  onQuery: (value: string) => void;
  onSubmit: () => void;
  onNavigate: (page: Page) => void;
}) {
  const [mobileOpen, setMobileOpen] = useState(false);
  return (
    <header className="app-header">
      <button className="brand" type="button" onClick={() => onNavigate("search")}>
        <Logo small />
        <span>ARGUS 情报中心</span>
      </button>
      <form
        className="header-search"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit();
        }}
      >
        <Search size={17} />
        <input
          value={query}
          onChange={(event) => onQuery(event.target.value)}
          placeholder="搜索 IOC / 攻击链 / 自然语言"
          aria-label="全局搜索"
        />
        <kbd>↵</kbd>
      </form>
      <nav className={`top-nav ${mobileOpen ? "is-open" : ""}`}>
        {pageLabels.map((item) => {
          const Icon = item.icon;
          return (
            <button
              type="button"
              key={item.id}
              className={page === item.id ? "active" : ""}
              onClick={() => {
                onNavigate(item.id);
                setMobileOpen(false);
              }}
            >
              <Icon size={16} />
              {item.label}
            </button>
          );
        })}
      </nav>
      <div className="header-actions">
        <span className="data-live">
          <span />
          数据库在线
        </span>
        <button type="button" className="icon-button" aria-label="数据概览">
          <Database size={18} />
        </button>
        <button
          type="button"
          className="icon-button mobile-menu"
          aria-label="打开导航"
          onClick={() => setMobileOpen((value) => !value)}
        >
          <Menu size={19} />
        </button>
      </div>
    </header>
  );
}

function StatStrip({ data }: { data: Snapshot }) {
  const stats = [
    { label: "情报实体", value: data.stats.entities, icon: CircleDot },
    { label: "验证关系", value: data.stats.relationships, icon: GitBranch },
    { label: "来源报告", value: data.stats.reports, icon: FileText },
    { label: "攻击组织", value: data.stats.actors, icon: Users },
  ];
  return (
    <div className="stat-strip">
      {stats.map((stat) => {
        const Icon = stat.icon;
        return (
          <div key={stat.label}>
            <Icon size={18} />
            <strong>{stat.value}</strong>
            <span>{stat.label}</span>
          </div>
        );
      })}
    </div>
  );
}

function SearchHome({
  data,
  query,
  mode,
  onQuery,
  onMode,
  onSubmit,
}: {
  data: Snapshot;
  query: string;
  mode: SearchMode;
  onQuery: (value: string) => void;
  onMode: (value: SearchMode) => void;
  onSubmit: () => void;
}) {
  const examples = [
    "cdn-meeting-update.com",
    "CVE-2023-23397",
    "Outlook 提醒 → 远程 SMB → NTLM 泄露",
    "哪些组织使用 PowerShell？",
  ];
  return (
    <main className="search-home">
      <div className="home-glow glow-one" />
      <div className="home-glow glow-two" />
      <section className="hero">
        <Logo />
        <p className="eyebrow">ARGUS · EXPLAINABLE THREAT INTELLIGENCE</p>
        <h1>威胁归因与情报分析平台</h1>
        <p className="hero-subtitle">以真实证据连接 IOC、攻击链与历史归因路径</p>
        <div className="hero-search-card">
          <form
            className="hero-search-input"
            onSubmit={(event) => {
              event.preventDefault();
              onSubmit();
            }}
          >
            <Search size={21} />
            <textarea
              rows={2}
              value={query}
              onChange={(event) => onQuery(event.target.value)}
              placeholder="输入自然语言、IOC，或用 → 连接一条攻击链"
              aria-label="综合查询输入"
            />
            <button type="submit" aria-label="执行查询" disabled={!query.trim()}>
              <ArrowRight size={19} />
            </button>
          </form>
          <div className="mode-row">
            <div className="mode-switch" role="tablist" aria-label="查询方式">
              {modeLabels.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    type="button"
                    role="tab"
                    aria-selected={mode === item.id}
                    className={mode === item.id ? "active" : ""}
                    onClick={() => onMode(item.id)}
                  >
                    <Icon size={15} />
                    {item.label}
                  </button>
                );
              })}
            </div>
            <span className="syntax-hint">
              <Info size={14} />
              攻击链语法：节点 A → 节点 B → 节点 C
            </span>
          </div>
        </div>
        <div className="example-row">
          <span>试试：</span>
          {examples.map((example) => (
            <button type="button" key={example} onClick={() => onQuery(example)}>
              {example}
            </button>
          ))}
        </div>
        <StatStrip data={data} />
      </section>
      <section className="home-capabilities">
        <article>
          <ShieldAlert size={21} />
          <div>
            <strong>IOC 同源检索</strong>
            <span>{data.stats.iocs} 个基础设施指标已入库</span>
          </div>
        </article>
        <article>
          <GitBranch size={21} />
          <div>
            <strong>攻击链结构匹配</strong>
            <span>{data.stats.attack_steps} 个历史步骤可解释对齐</span>
          </div>
        </article>
        <article>
          <FileSearch size={21} />
          <div>
            <strong>证据可回溯</strong>
            <span>{data.stats.evidence} 条关系证据保留原文</span>
          </div>
        </article>
      </section>
    </main>
  );
}

function EntitySummary({
  entity,
  data,
  onGraph,
}: {
  entity: Entity;
  data: Snapshot;
  onGraph: () => void;
}) {
  const actor = actorForEntity(entity);
  const directEdges = data.relationships.filter(
    (edge) => edge.source_entity_id === entity.id || edge.target_entity_id === entity.id,
  );
  return (
    <section className="entity-hero-card">
      <div className={`entity-risk-ring status-${propString(entity, "status") || "hot"}`}>
        <ShieldAlert size={32} />
        <span>{propString(entity, "status") === "negative" ? "反证" : "关联"}</span>
      </div>
      <div className="entity-main">
        <div className="title-line">
          <span className="entity-type">{entity.entity_type}</span>
          <h2>{entity.label}</h2>
          <RiskBadge status={propString(entity, "status") || "hot"} />
        </div>
        <p>{entity.description || propString(entity, "sub") || "数据库规范实体"}</p>
        <div className="entity-tags">
          {actor && <span><Target size={13} />{actor}</span>}
          {propString(entity, "event") && <span><History size={13} />{propString(entity, "event")}</span>}
          <span><Database size={13} />来源 {entity.source_count}</span>
          <span><Activity size={13} />置信度 {Math.round(propNumber(entity, "confidence") * 100)}%</span>
        </div>
      </div>
      <div className="entity-kpis">
        <div><strong>{directEdges.length}</strong><span>直接关系</span></div>
        <div><strong>{directEdges.reduce((sum, edge) => sum + edge.evidence_count, 0)}</strong><span>证据引用</span></div>
        <button type="button" onClick={onGraph}>
          <Network size={16} />查看图谱
        </button>
      </div>
    </section>
  );
}

function SearchResults({
  data,
  query,
  mode,
  onGraphActor,
}: {
  data: Snapshot;
  query: string;
  mode: SearchMode;
  onGraphActor: (actor?: Actor, focusId?: string) => void;
}) {
  const [tab, setTab] = useState<"overview" | "evidence" | "history">("overview");
  const [selectedNode, setSelectedNode] = useState<GraphNode | undefined>();
  const result = useMemo(() => searchSnapshot(data, query), [data, query]);
  const queryType = detectQueryType(query);
  const top = result.entities[0]?.entity;
  const chainGraph = useMemo(
    () => (queryType === "攻击链" ? buildChainGraph(data, query) : null),
    [data, query, queryType],
  );
  const seedIds = result.entities.slice(0, 7).map((item) => item.entity.id);
  const regularGraph = useMemo(
    () => buildSubgraph(data, seedIds, 28),
    [data, seedIds.join("|")],
  );
  const graph = chainGraph ?? regularGraph;
  const matchedIds = new Set(result.entities.slice(0, 18).map((item) => item.entity.id));
  const relatedEdges = data.relationships.filter(
    (edge) => matchedIds.has(edge.source_entity_id) || matchedIds.has(edge.target_entity_id),
  );
  const relatedEvidence = data.evidence
    .filter((evidence) => relatedEdges.some((edge) => edge.id === evidence.relationship_id))
    .filter(
      (evidence, index, all) =>
        all.findIndex((item) => item.report_id === evidence.report_id) === index,
    )
    .slice(0, 8);
  const actorName = top ? actorForEntity(top) : "";
  const actor = data.actors.find((item) => item.label === actorName);
  const isGraph = mode === "graph";

  return (
    <main className="page-shell result-page">
      <div className="breadcrumb-row">
        <span>综合查询</span><ChevronDown size={13} /><strong>{queryType}</strong>
        <span className="source-pill"><Database size={13} />来自 ARGUS 数据库</span>
      </div>
      {!top && !chainGraph ? (
        <section className="empty-state">
          <Search size={36} />
          <h2>数据库中未找到直接匹配</h2>
          <p>当前查询没有命中已入库实体或报告。系统不会生成不存在的情报。</p>
        </section>
      ) : (
        <>
          {top && (
            <EntitySummary
              entity={top}
              data={data}
              onGraph={() => onGraphActor(actor, top.id)}
            />
          )}
          {chainGraph && (
            <section className="chain-match-banner">
              <div>
                <GitBranch size={21} />
                <span>攻击链输入已拆分为 <strong>{chainGraph.nodes.length}</strong> 个步骤</span>
              </div>
              <div>
                <strong>{chainGraph.matched}</strong> 个节点命中历史图谱
                <span>{chainGraph.nodes.length - chainGraph.matched} 个节点待进一步研判</span>
              </div>
            </section>
          )}
          <div className={`result-grid ${isGraph ? "graph-first" : ""}`}>
            <section className="result-main">
              <div className="section-tabs">
                <button type="button" className={tab === "overview" ? "active" : ""} onClick={() => setTab("overview")}>情报概览</button>
                <button type="button" className={tab === "evidence" ? "active" : ""} onClick={() => setTab("evidence")}>关联证据 <span>{relatedEvidence.length}</span></button>
                <button type="button" className={tab === "history" ? "active" : ""} onClick={() => setTab("history")}>历史匹配 <span>{result.reports.length}</span></button>
              </div>
              {tab === "overview" && (
                <div className="panel-content">
                  <div className="section-heading">
                    <div>
                      <span className="kicker">MATCHED INTELLIGENCE</span>
                      <h3>匹配到的情报实体</h3>
                    </div>
                    <span>{result.entities.length} 条结果</span>
                  </div>
                  <div className="entity-result-list">
                    {result.entities.slice(0, 12).map(({ entity, score }, index) => (
                      <button
                        type="button"
                        key={entity.id}
                        onClick={() => setSelectedNode(entityToNode(entity))}
                      >
                        <span className="rank">{String(index + 1).padStart(2, "0")}</span>
                        <span className={`entity-mini-icon type-${entity.entity_type.replaceAll("/", "-")}`}>
                          {entity.entity_type === "IOC/基础设施" ? <Globe2 size={16} /> : entity.entity_type === "攻击步骤" ? <GitBranch size={16} /> : <CircleDot size={16} />}
                        </span>
                        <span className="entity-list-copy">
                          <strong>{entity.label}</strong>
                          <small>{entity.entity_type} · {propString(entity, "sub") || entity.canonical_key}</small>
                        </span>
                        <span className="match-score">{Math.min(100, score)}% 匹配</span>
                        <RiskBadge status={propString(entity, "status") || "positive"} />
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {tab === "evidence" && (
                <div className="panel-content">
                  <div className="section-heading">
                    <div>
                      <span className="kicker">SOURCE EVIDENCE</span>
                      <h3>可回溯关系证据</h3>
                    </div>
                  </div>
                  <div className="evidence-list">
                    {relatedEvidence.map((evidence) => (
                      <article key={evidence.id}>
                        <div className="evidence-meta">
                          <span>{evidence.source_ref || "内部来源"}</span>
                          <span>{formatDate(evidence.report_date)}</span>
                          <span>置信度 {Math.round(evidence.confidence * 100)}%</span>
                        </div>
                        <h4>{evidence.report_title}</h4>
                        <p>{evidence.excerpt}</p>
                        <small>{evidence.publisher} · {evidence.location || "原文摘录"}</small>
                      </article>
                    ))}
                  </div>
                </div>
              )}
              {tab === "history" && (
                <div className="panel-content">
                  <div className="section-heading">
                    <div>
                      <span className="kicker">HISTORICAL ALIGNMENT</span>
                      <h3>历史报告匹配</h3>
                    </div>
                  </div>
                  <div className="report-list">
                    {result.reports.slice(0, 10).map(({ report, score }) => (
                      <article key={report.id}>
                        <div className="report-icon"><FileText size={19} /></div>
                        <div>
                          <h4>{report.title}</h4>
                          <p>{report.assessment}</p>
                          <span>{report.source} · {formatDate(report.report_date)} · {report.reliability}</span>
                        </div>
                        <strong>{Math.min(99, score)}%</strong>
                      </article>
                    ))}
                  </div>
                </div>
              )}
            </section>
            <aside className="result-graph-card">
              <div className="card-heading">
                <div>
                  <span className="kicker">{chainGraph ? "CHAIN ALIGNMENT" : "RELATED GRAPH"}</span>
                  <h3>{chainGraph ? "攻击链匹配图谱" : "关联关系图谱"}</h3>
                </div>
                <button type="button" onClick={() => onGraphActor(actor, top?.id)}>
                  全屏 <ExternalLink size={14} />
                </button>
              </div>
              <NetworkGraph
                compact
                chainMode={Boolean(chainGraph)}
                nodes={graph.nodes}
                edges={graph.edges}
                rootId={chainGraph ? graph.nodes[0]?.id : top?.id}
                selectedId={selectedNode?.id}
                onSelect={setSelectedNode}
              />
              <div className="graph-legend">
                <span><i className="hot" />已匹配</span>
                <span><i className="partial" />部分匹配</span>
                <span><i className="negative" />反证节点</span>
              </div>
              {selectedNode && (
                <div className="mini-node-detail">
                  <div>
                    <strong>{selectedNode.label}</strong>
                    <span>{selectedNode.type}</span>
                  </div>
                  <RiskBadge status={selectedNode.status} />
                </div>
              )}
            </aside>
          </div>
        </>
      )}
    </main>
  );
}

function AnalysisInput({
  data,
  value,
  filename,
  onValue,
  onFilename,
  onAnalyze,
}: {
  data: Snapshot;
  value: string;
  filename: string;
  onValue: (value: string) => void;
  onFilename: (value: string) => void;
  onAnalyze: () => void;
}) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState("");
  const loadFile = async (file?: File) => {
    if (!file) return;
    if (!/\.(txt|json|md)$/i.test(file.name)) {
      setError("当前真实解析链仅支持 TXT、JSON 和 Markdown 文件。");
      return;
    }
    onFilename(file.name);
    onValue(await file.text());
    setError("");
  };
  return (
    <main className="page-shell analysis-start">
      <div className="page-title-row">
        <div>
          <span className="kicker">INTELLIGENCE FUSION</span>
          <h1>情报综合分析</h1>
          <p>上传或粘贴完整威胁情报，与现有知识图谱进行实体、攻击链和历史证据匹配。</p>
        </div>
        <span className="source-pill"><Database size={13} />{data.stats.reports} 份历史报告可供匹配</span>
      </div>
      <section className="analysis-input-card">
        <div
          className="upload-zone"
          onDragOver={(event) => event.preventDefault()}
          onDrop={(event) => {
            event.preventDefault();
            loadFile(event.dataTransfer.files[0]);
          }}
        >
          <input
            ref={fileRef}
            type="file"
            accept=".txt,.json,.md,text/plain,application/json,text/markdown"
            hidden
            onChange={(event) => loadFile(event.target.files?.[0])}
          />
          <div className="upload-icon"><Upload size={25} /></div>
          <div>
            <strong>{filename || "拖拽情报文件到这里"}</strong>
            <span>支持 TXT / JSON / Markdown，文件仅用于本次本地匹配</span>
          </div>
          <button type="button" onClick={() => fileRef.current?.click()}>选择文件</button>
        </div>
        <div className="or-divider"><span>或粘贴情报全文</span></div>
        <textarea
          value={value}
          onChange={(event) => onValue(event.target.value)}
          placeholder="粘贴报告正文、IOC 列表或攻击链描述……"
          aria-label="情报全文"
        />
        {error && <p className="inline-error"><AlertTriangle size={15} />{error}</p>}
        <div className="analysis-actions">
          <div>
            <Shield size={16} />
            只匹配数据库已有事实，不生成缺失节点
          </div>
          <button type="button" disabled={value.trim().length < 8} onClick={onAnalyze}>
            <BrainCircuit size={17} />开始综合分析
          </button>
        </div>
      </section>
      <section className="recent-reports">
        <div className="section-heading">
          <div>
            <span className="kicker">RECENT SOURCES</span>
            <h3>从已入库报告开始</h3>
          </div>
        </div>
        <div className="recent-report-grid">
          {data.reports.slice(0, 6).map((report) => (
            <button
              type="button"
              key={report.id}
              onClick={() => {
                onFilename(report.title);
                onValue(report.extracted_text);
              }}
            >
              <FileText size={18} />
              <div>
                <strong>{report.title}</strong>
                <span>{report.source} · {formatDate(report.report_date)}</span>
              </div>
              <ArrowRight size={16} />
            </button>
          ))}
        </div>
      </section>
    </main>
  );
}

function AnalysisWorkspace({
  data,
  text,
  filename,
  onReset,
}: {
  data: Snapshot;
  text: string;
  filename: string;
  onReset: () => void;
}) {
  const result = useMemo(() => getAnalysis(data, text), [data, text]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | undefined>();
  const top = result.candidates[0];
  const reportId = `report-${filename || "input"}`;
  const actorNodes = result.candidates.slice(0, 3).map((item) =>
    entityToNode(data.entities.find((entity) => entity.id === item.actor.id)!),
  );
  const matchedNodes = result.matched.slice(0, 18).map(entityToNode);
  const graphNodes: GraphNode[] = [
    { id: reportId, label: filename || "待分析情报", type: "报告", status: "hot", confidence: 1, virtual: true },
    ...matchedNodes,
    ...actorNodes.filter((node) => !matchedNodes.some((item) => item.id === node.id)),
  ];
  const graphEdges: GraphEdge[] = matchedNodes.map((node, index) => ({
    id: `report-match-${index}`,
    source: reportId,
    target: node.id,
    label: "文本命中",
    status: node.status,
  }));
  result.candidates.slice(0, 3).forEach((candidate) => {
    candidate.entities.slice(0, 5).forEach((entity, index) => {
      if (graphNodes.some((node) => node.id === entity.id)) {
        graphEdges.push({
          id: `actor-link-${candidate.actor.id}-${index}`,
          source: entity.id,
          target: candidate.actor.id,
          label: "历史归属",
          status: propString(entity, "status") || "positive",
        });
      }
    });
  });
  const matchedIds = new Set(result.matched.map((entity) => entity.id));
  const matchedRelationships = data.relationships.filter(
    (edge) => matchedIds.has(edge.source_entity_id) && matchedIds.has(edge.target_entity_id),
  );
  const sourceEvidence = data.evidence
    .filter((evidence) =>
      matchedRelationships.some((edge) => edge.id === evidence.relationship_id),
    )
    .filter(
      (evidence, index, all) =>
        all.findIndex((item) => item.report_id === evidence.report_id) === index,
    );
  const matchedTypes = new Set(result.matched.map((entity) => entity.entity_type));
  const recommendations = data.responseRules.filter(
    (rule) =>
      matchedTypes.has(rule.match_entity_type) ||
      (rule.match_entity_type === "反证" &&
        result.matched.some((entity) => propString(entity, "status") === "negative")),
  );

  return (
    <main className="page-shell analysis-workspace">
      <div className="workspace-bar">
        <button type="button" onClick={onReset}><ArrowLeft size={16} />返回输入</button>
        <div>
          <FileText size={17} />
          <span>{filename || "粘贴情报"}</span>
          <RiskBadge status={result.matched.length ? "hot" : "partial"} />
        </div>
        <span>匹配完成 · {result.matched.length} 个实体 · {sourceEvidence.length} 份历史来源</span>
      </div>
      <section className="analysis-graph-section">
        <div className="analysis-graph-main">
          <div className="card-heading">
            <div>
              <span className="kicker">EVIDENCE KNOWLEDGE GRAPH</span>
              <h2>报告证据与历史图谱匹配</h2>
            </div>
            <div className="graph-counts">
              <span><i className="hot" />命中 {result.matched.length}</span>
              <span><i className="negative" />反证 {result.matched.filter((item) => propString(item, "status") === "negative").length}</span>
            </div>
          </div>
          <NetworkGraph
            nodes={graphNodes}
            edges={graphEdges}
            rootId={reportId}
            selectedId={selectedNode?.id}
            onSelect={setSelectedNode}
          />
        </div>
        <aside className="analysis-side-panel">
          <div className="side-tabs"><button type="button" className="active">节点详情</button><button type="button">源报告</button></div>
          {selectedNode?.entity ? (
            <div className="node-detail">
              <div className="node-detail-icon"><CircleDot size={21} /></div>
              <span className="kicker">{selectedNode.entity.entity_type}</span>
              <h3>{selectedNode.entity.label}</h3>
              <RiskBadge status={selectedNode.status} />
              <p>{selectedNode.entity.description || propString(selectedNode.entity, "sub")}</p>
              <dl>
                <div><dt>规范 ID</dt><dd>{selectedNode.entity.id}</dd></div>
                <div><dt>所属组织</dt><dd>{actorForEntity(selectedNode.entity) || "未确认"}</dd></div>
                <div><dt>历史事件</dt><dd>{propString(selectedNode.entity, "event") || "未记录"}</dd></div>
                <div><dt>置信度</dt><dd>{Math.round(propNumber(selectedNode.entity, "confidence") * 100)}%</dd></div>
              </dl>
            </div>
          ) : (
            <div className="source-panel">
              <div className="side-summary">
                <strong>{sourceEvidence.length}</strong>
                <span>份历史报告支持当前匹配</span>
              </div>
              {sourceEvidence.slice(0, 6).map((evidence) => (
                <article key={evidence.id}>
                  <FileText size={17} />
                  <div>
                    <strong>{evidence.report_title}</strong>
                    <span>{evidence.source_ref} · {formatDate(evidence.report_date)}</span>
                  </div>
                </article>
              ))}
              {!sourceEvidence.length && <p className="muted">当前输入未形成可回溯的完整关系证据。</p>}
            </div>
          )}
        </aside>
      </section>
      <section className="attribution-section">
        <div className="section-heading">
          <div>
            <span className="kicker">EXPLAINABLE ATTRIBUTION</span>
            <h2>归因候选与可解释匹配历史</h2>
          </div>
          <span className="method-note"><Info size={14} />确定性规则匹配，不代表独立情报结论</span>
        </div>
        {top ? (
          <div className="attribution-grid">
            <div className="candidate-list">
              {result.candidates.slice(0, 4).map((candidate, index) => (
                <article key={candidate.actor.id} className={index === 0 ? "top" : ""}>
                  <div className="candidate-rank">{index + 1}</div>
                  <div className="candidate-main">
                    <div><strong>{candidate.actor.label}</strong><span>{candidate.actor.origin_label}</span></div>
                    <p>{candidate.entities.length} 个实体、{new Set(candidate.entities.map((entity) => propString(entity, "event"))).size} 条历史事件路径提供支持</p>
                    <div className="score-track"><span style={{ width: `${candidate.score * 100}%` }} /></div>
                  </div>
                  <div className="candidate-score"><strong>{Math.round(candidate.score * 100)}</strong><span>规则分</span></div>
                </article>
              ))}
            </div>
            <div className="explain-paths">
              <div className="explain-header">
                <div className="actor-avatar"><Target size={21} /></div>
                <div><span>首要候选</span><strong>{top.actor.label}</strong></div>
                <RiskBadge status={top.negative ? "partial" : "hot"} />
              </div>
              <div className="path-timeline">
                {top.entities.slice(0, 7).map((entity, index) => (
                  <div key={entity.id} className={propString(entity, "status") === "negative" ? "negative" : ""}>
                    <span className="path-index">{index + 1}</span>
                    <div>
                      <strong>{entity.label}</strong>
                      <p>{propString(entity, "sub") || entity.entity_type}</p>
                      <small>{propString(entity, "event") || "组织画像"} · 贡献 {Math.round(propNumber(entity, "confidence") * 100)}%</small>
                    </div>
                    <Check size={15} />
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="empty-inline"><Info size={18} />未找到足以形成组织候选的历史实体，系统不会补造归因结果。</div>
        )}
      </section>
      <section className="response-section">
        <div className="section-heading">
          <div>
            <span className="kicker">RESPONSE PLAYBOOK</span>
            <h2>处置响应与综合建议</h2>
          </div>
        </div>
        <div className="response-grid">
          {recommendations.map((rule, index) => (
            <article key={rule.id}>
              <div className={`priority priority-${rule.priority.toLowerCase()}`}>{rule.priority}</div>
              <span>0{index + 1}</span>
              <h3>{rule.match_entity_type}处置建议</h3>
              <p>{rule.action_template}</p>
              <small>{rule.rationale}</small>
              {rule.source_url && <a href={rule.source_url} target="_blank" rel="noreferrer">查看权威来源 <ExternalLink size={13} /></a>}
            </article>
          ))}
          {!recommendations.length && (
            <article>
              <div className="priority priority-p1">P1</div>
              <span>01</span>
              <h3>保留证据并继续研判</h3>
              <p>当前匹配不足以触发数据库中的专项响应规则，请保留原始报告与终端、网络证据。</p>
            </article>
          )}
        </div>
      </section>
    </main>
  );
}

function GPTPage({ initialPrompt }: { initialPrompt: string }) {
  const [prompt, setPrompt] = useState(initialPrompt);
  const [filename, setFilename] = useState("");
  const [notice, setNotice] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  return (
    <main className="gpt-page">
      <aside className="chat-sidebar">
        <button type="button" className="new-chat"><Sparkles size={16} />开启新对话</button>
        <div className="sidebar-section">
          <span>对话历史</span>
          <div className="history-placeholder"><Clock3 size={17} /><p>模型接入后，对话历史将在这里显示。</p></div>
        </div>
        <div className="sidebar-section tools">
          <span>ARGUS 工具箱</span>
          <button type="button"><FileSearch size={16} />Web 日志分析</button>
          <button type="button"><GitBranch size={16} />攻击链提取</button>
          <button type="button"><Shield size={16} />IOC 结构化</button>
          <button type="button"><FileText size={16} />JSON 格式化</button>
        </div>
      </aside>
      <section className="chat-stage">
        <div className="chat-title">
          <Logo small />
          <h1>ARGUS GPT</h1>
          <span>Chat 通用模式</span>
        </div>
        <p className="chat-subtitle">上传情报后进行智能意图识别与安全分析</p>
        <div className="chat-composer">
          <textarea value={prompt} onChange={(event) => setPrompt(event.target.value)} placeholder="输入安全分析问题或上传情报……" />
          {filename && <div className="attached-file"><FileText size={14} />{filename}<button type="button" onClick={() => setFilename("")}><X size={13} /></button></div>}
          <div className="composer-tools">
            <div>
              <span><Bot size={14} />Chat 通用模式</span>
              <span className="soft-red"><BrainCircuit size={14} />智能意图识别</span>
            </div>
            <input
              ref={fileRef}
              hidden
              type="file"
              onChange={(event) => setFilename(event.target.files?.[0]?.name ?? "")}
            />
            <button type="button" className="attach" aria-label="上传文件" onClick={() => fileRef.current?.click()}><Paperclip size={19} /></button>
            <button type="button" className="send" aria-label="发送" disabled={!prompt.trim()} onClick={() => setNotice(true)}><Send size={17} /></button>
          </div>
        </div>
        {notice && (
          <div className="service-notice">
            <Info size={17} />
            <div><strong>GPT 模型服务尚未接入</strong><p>当前页面仅完成真实的输入、附件与模式交互，不会生成模拟回答。</p></div>
            <button type="button" onClick={() => setNotice(false)}><X size={15} /></button>
          </div>
        )}
        <div className="prompt-suggestions">
          <button type="button" onClick={() => setPrompt("分析这份报告中出现的 IOC 与攻击链")}><ShieldAlert size={16} />提取 IOC 与攻击链</button>
          <button type="button" onClick={() => setPrompt("解释 CVE-2023-23397 的攻击路径")}><GitBranch size={16} />解释漏洞攻击路径</button>
          <button type="button" onClick={() => setPrompt("对比 APT28 与 APT29 的历史行为")}><Users size={16} />对比组织历史行为</button>
        </div>
        <p className="gpt-footnote">模型输出能力暂未接入；页面不会展示虚构分析结果。</p>
      </section>
    </main>
  );
}

function ActorOverview({
  data,
  onGraph,
}: {
  data: Snapshot;
  onGraph: (actor: Actor) => void;
}) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Actor>(data.actors[0]);
  const actors = data.actors.filter((actor) =>
    normalize(`${actor.label} ${actor.origin_label} ${actor.properties.sub ?? ""}`).includes(
      normalize(query),
    ),
  );
  const selectedStats = actorStats(data, selected);
  const reports = matchingReports(data, selected);
  const relatedEntities = data.entities.filter(
    (entity) => actorForEntity(entity) === selected.label,
  );
  return (
    <main className="page-shell actors-page">
      <div className="page-title-row actor-title">
        <div>
          <span className="kicker">THREAT ACTOR ARCHIVE</span>
          <h1>攻击组织总揽</h1>
          <p>组织档案、发展时间线、作战手段、IOC 与攻击链的统一情报视图。</p>
        </div>
        <div className="actor-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索组织、国家或别名" /></div>
      </div>
      <section className="actor-metrics">
        <article><strong>{data.stats.actors}</strong><span>组织档案</span><Users size={21} /></article>
        <article><strong>{data.entities.filter((item) => item.entity_type === "历史事件").length}</strong><span>历史战役</span><History size={21} /></article>
        <article><strong>{data.stats.iocs}</strong><span>关联 IOC</span><Globe2 size={21} /></article>
        <article><strong>{data.stats.attack_steps}</strong><span>攻击链节点</span><GitBranch size={21} /></article>
      </section>
      <div className="actors-layout">
        <section className="actor-list">
          <div className="list-heading"><span>组织档案</span><small>{actors.length} 个结果</small></div>
          {actors.map((actor) => {
            const stats = actorStats(data, actor);
            return (
              <article key={actor.id} className={selected.id === actor.id ? "selected" : ""}>
                <button type="button" className="actor-select" onClick={() => setSelected(actor)}>
                  <span className={`actor-emblem ${actor.profile_status === "verified" ? "" : "unverified"}`}><Target size={21} /></span>
                  <div className="actor-card-copy">
                    <div><h3>{actor.label}</h3><RiskBadge status={actor.profile_status === "verified" ? "hot" : "partial"} /></div>
                    <p>{String(actor.properties.sub ?? actor.origin_label)}</p>
                    <span>{actor.origin_label}</span>
                    <div className="actor-stat-line">
                      <span>{stats.events} 战役</span><span>{stats.iocs} IOC</span><span>{stats.steps} 步骤</span>
                    </div>
                  </div>
                </button>
                <button type="button" className="graph-preview-button" onClick={() => onGraph(actor)}>
                  <span><Network size={17} />全景图谱</span>
                  <i>
                    <b /><b /><b /><b />
                  </i>
                </button>
              </article>
            );
          })}
        </section>
        <section className="actor-profile">
          <div className="profile-header">
            <div className="profile-emblem"><Target size={29} /></div>
            <div>
              <div className="title-line"><h2>{selected.label}</h2><RiskBadge status={selected.profile_status === "verified" ? "hot" : "partial"} /></div>
              <p>{String(selected.properties.sub ?? "")}</p>
              <span>{selected.origin_label} · 活跃于 {selected.active_from ?? "未知"}—{selected.active_to ?? "至今"}</span>
            </div>
            <button type="button" onClick={() => onGraph(selected)}><Network size={16} />打开组织全景图谱</button>
          </div>
          <div className="profile-score-row">
            <div><span>来源评级</span><strong>{Math.round(selected.source_grade * 100)}%</strong><i><b style={{ width: `${selected.source_grade * 100}%` }} /></i></div>
            <div><span>历史战役</span><strong>{selectedStats.events}</strong></div>
            <div><span>恶意工具</span><strong>{selectedStats.tools}</strong></div>
            <div><span>攻击步骤</span><strong>{selectedStats.steps}</strong></div>
          </div>
          <div className="profile-grid">
            <article className="profile-summary">
              <div className="card-heading"><div><span className="kicker">PROFILE</span><h3>组织画像</h3></div></div>
              <p>{selected.public_attribution}</p>
              <div className="profile-tags"><span>动机</span>{selected.motivations.map((item) => <i key={item}>{item}</i>)}</div>
              <div className="profile-tags"><span>目标行业</span>{selected.target_sectors.map((item) => <i key={item}>{item}</i>)}</div>
            </article>
            <article className="timeline-card">
              <div className="card-heading"><div><span className="kicker">TIMELINE</span><h3>发展时间线</h3></div><span>{reports.length} 个来源节点</span></div>
              <div className="timeline">
                {reports.slice(0, 5).map((report) => (
                  <div key={report.id}>
                    <time>{report.report_date || "时间未记录"}</time>
                    <span className="timeline-dot" />
                    <div><strong>{report.title}</strong><p>{report.assessment}</p><small>{report.source_ref} · {report.reliability}</small></div>
                  </div>
                ))}
              </div>
            </article>
          </div>
          <article className="capability-card">
            <div className="card-heading"><div><span className="kicker">CAPABILITY MATRIX</span><h3>手段、IOC 与攻击链节点</h3></div></div>
            <div className="capability-groups">
              {["恶意软件/工具", "ATT&CK 技术", "IOC/基础设施", "攻击步骤"].map((type) => (
                <div key={type}>
                  <span>{type}</span>
                  <div>{relatedEntities.filter((entity) => entity.entity_type === type).slice(0, 8).map((entity) => <i key={entity.id}>{entity.label}</i>)}</div>
                </div>
              ))}
            </div>
          </article>
        </section>
      </div>
    </main>
  );
}

function FullGraph({
  data,
  actor,
  focusId,
  onBack,
}: {
  data: Snapshot;
  actor: Actor;
  focusId?: string;
  onBack: () => void;
}) {
  const [categories, setCategories] = useState(new Set(["chain", "infrastructure", "technique", "attribution"]));
  const [selected, setSelected] = useState<GraphNode | undefined>();
  const seedIds = [actor.id, ...(focusId ? [focusId] : [])];
  const graph = useMemo(
    () => buildSubgraph(data, seedIds, 48, categories),
    [data, actor.id, focusId, [...categories].sort().join("|")],
  );
  const selectedEntity = selected?.entity ?? data.entities.find((entity) => entity.id === actor.id);
  const directEdges = selectedEntity
    ? data.relationships.filter(
        (edge) =>
          edge.source_entity_id === selectedEntity.id ||
          edge.target_entity_id === selectedEntity.id,
      )
    : [];
  const directEvidence = data.evidence.filter((item) =>
    directEdges.some((edge) => edge.id === item.relationship_id),
  );
  const toggleCategory = (category: string) => {
    setCategories((current) => {
      const next = new Set(current);
      if (next.has(category)) next.delete(category);
      else next.add(category);
      return next;
    });
  };
  return (
    <main className="full-graph-page">
      <div className="graph-topbar">
        <button type="button" onClick={onBack}><ArrowLeft size={17} />返回组织档案</button>
        <div><span className="actor-emblem"><Target size={18} /></span><div><strong>{actor.label} 全景图谱</strong><span>{graph.nodes.length} 节点 · {graph.edges.length} 关系</span></div></div>
        <span className="source-pill"><Database size={13} />真实图谱快照</span>
      </div>
      <div className="full-graph-layout">
        <aside className="graph-left-panel">
          <div className="panel-title"><Layers3 size={17} /><strong>关系图层</strong></div>
          {[
            ["chain", "攻击链", GitBranch],
            ["infrastructure", "基础设施", Globe2],
            ["technique", "技术手段", Zap],
            ["attribution", "归因关系", Target],
          ].map(([id, label, Icon]) => (
            <label key={id as string}>
              <input type="checkbox" checked={categories.has(id as string)} onChange={() => toggleCategory(id as string)} />
              <span><Icon size={16} />{label}</span>
              <small>{data.relationships.filter((edge) => edge.category === id).length}</small>
            </label>
          ))}
          <div className="panel-title second"><Filter size={17} /><strong>节点类型</strong></div>
          {[...new Set(graph.nodes.map((node) => node.type))].map((type) => (
            <div className="type-count" key={type}><span>{type}</span><small>{graph.nodes.filter((node) => node.type === type).length}</small></div>
          ))}
        </aside>
        <section className="graph-canvas-panel">
          <div className="canvas-actions"><Search size={16} /><span>点击节点查看证据详情</span><div><span><i className="hot" />高置信</span><span><i className="partial" />部分</span><span><i className="negative" />反证</span></div></div>
          <NetworkGraph
            nodes={graph.nodes}
            edges={graph.edges}
            rootId={actor.id}
            selectedId={selected?.id ?? focusId}
            onSelect={setSelected}
          />
        </section>
        <aside className="graph-right-panel">
          <div className="panel-title"><PanelRight size={17} /><strong>节点详情</strong></div>
          {selectedEntity && (
            <>
              <div className="detail-identity">
                <span className={`detail-icon status-${propString(selectedEntity, "status") || "hot"}`}><CircleDot size={20} /></span>
                <div><small>{selectedEntity.entity_type}</small><h3>{selectedEntity.label}</h3></div>
                <RiskBadge status={propString(selectedEntity, "status") || "hot"} />
              </div>
              <p className="detail-description">{selectedEntity.description || propString(selectedEntity, "sub")}</p>
              <dl className="detail-list">
                <div><dt>规范 ID</dt><dd>{selectedEntity.id}</dd></div>
                <div><dt>所属组织</dt><dd>{actorForEntity(selectedEntity) || actor.label}</dd></div>
                <div><dt>历史事件</dt><dd>{propString(selectedEntity, "event") || "组织中心"}</dd></div>
                <div><dt>来源数量</dt><dd>{selectedEntity.source_count}</dd></div>
                <div><dt>置信度</dt><dd>{Math.round(propNumber(selectedEntity, "confidence", actor.source_grade) * 100)}%</dd></div>
              </dl>
              <div className="relation-section">
                <div className="panel-title"><Link2 size={16} /><strong>直接关系</strong><small>{directEdges.length}</small></div>
                {directEdges.slice(0, 8).map((edge) => {
                  const otherId = edge.source_entity_id === selectedEntity.id ? edge.target_entity_id : edge.source_entity_id;
                  const other = data.entities.find((entity) => entity.id === otherId);
                  return (
                    <button type="button" key={edge.id} onClick={() => other && setSelected(entityToNode(other))}>
                      <span>{edge.relation_type}</span><strong>{other?.label ?? otherId}</strong><small>{Math.round(edge.confidence * 100)}%</small>
                    </button>
                  );
                })}
              </div>
              <div className="relation-section source-relations">
                <div className="panel-title"><FileText size={16} /><strong>来源证据</strong><small>{directEvidence.length}</small></div>
                {directEvidence
                  .filter((item, index, all) => all.findIndex((entry) => entry.report_id === item.report_id) === index)
                  .slice(0, 4)
                  .map((item) => (
                    <article key={item.id}><strong>{item.report_title}</strong><span>{item.source_ref || "内部来源"} · {formatDate(item.report_date)}</span></article>
                  ))}
              </div>
            </>
          )}
        </aside>
      </div>
    </main>
  );
}

export function ArgusApp({ data }: { data: Snapshot }) {
  const [page, setPage] = useState<Page>("search");
  const [searchMode, setSearchMode] = useState<SearchMode>("intel");
  const [query, setQuery] = useState("");
  const [submittedQuery, setSubmittedQuery] = useState("");
  const [analysisText, setAnalysisText] = useState("");
  const [analysisFilename, setAnalysisFilename] = useState("");
  const [analysisReady, setAnalysisReady] = useState(false);
  const [graphActor, setGraphActor] = useState<Actor>(data.actors[0]);
  const [graphFocus, setGraphFocus] = useState<string | undefined>();
  const [previousPage, setPreviousPage] = useState<Page>("actors");

  const submitSearch = (forcedMode?: SearchMode) => {
    if (!query.trim()) return;
    const mode = forcedMode ?? searchMode;
    if (mode === "gpt") {
      setPage("gpt");
      return;
    }
    setSearchMode(mode);
    setSubmittedQuery(query.trim());
    setPage("search");
  };

  const openGraph = (actor?: Actor, focusId?: string) => {
    const inferred =
      actor ??
      data.actors.find((item) =>
        data.entities
          .filter((entity) => entity.id === focusId)
          .some((entity) => actorForEntity(entity) === item.label),
      ) ??
      data.actors[0];
    setGraphActor(inferred);
    setGraphFocus(focusId);
    setPreviousPage(page);
    setPage("graph");
  };

  return (
    <div className="argus-app">
      {page !== "graph" && (
        <AppHeader
          page={page}
          query={query}
          onQuery={setQuery}
          onSubmit={() => submitSearch("intel")}
          onNavigate={(next) => {
            setPage(next);
            if (next === "search" && !submittedQuery) setQuery("");
          }}
        />
      )}
      {page === "search" &&
        (submittedQuery ? (
          <SearchResults
            key={`${submittedQuery}-${searchMode}`}
            data={data}
            query={submittedQuery}
            mode={searchMode}
            onGraphActor={openGraph}
          />
        ) : (
          <SearchHome
            data={data}
            query={query}
            mode={searchMode}
            onQuery={setQuery}
            onMode={setSearchMode}
            onSubmit={() => submitSearch()}
          />
        ))}
      {page === "analysis" &&
        (analysisReady ? (
          <AnalysisWorkspace
            data={data}
            text={analysisText}
            filename={analysisFilename}
            onReset={() => setAnalysisReady(false)}
          />
        ) : (
          <AnalysisInput
            data={data}
            value={analysisText}
            filename={analysisFilename}
            onValue={setAnalysisText}
            onFilename={setAnalysisFilename}
            onAnalyze={() => setAnalysisReady(true)}
          />
        ))}
      {page === "gpt" && <GPTPage initialPrompt={query} />}
      {page === "actors" && <ActorOverview data={data} onGraph={(actor) => openGraph(actor)} />}
      {page === "graph" && (
        <FullGraph
          data={data}
          actor={graphActor}
          focusId={graphFocus}
          onBack={() => setPage(previousPage === "graph" ? "actors" : previousPage)}
        />
      )}
    </div>
  );
}
