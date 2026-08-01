"use client";

import {
  Activity,
  ArrowLeft,
  ArrowRight,
  BookOpen,
  Bug,
  CornerDownRight,
  Database,
  ExternalLink,
  Filter,
  Fingerprint,
  GitBranch,
  LocateFixed,
  Network,
  Search,
  ShieldCheck,
  Target,
  Undo2,
  Users,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  formatDate,
  historicalPathCandidate,
} from "../argus-domain";
import {
  adaptPanoramicNeighborhood,
  panoramicIndexNodeToEntity,
  requestPanoramicGraphIndex,
  requestPanoramicGraphNeighborhood,
} from "../panoramic-graph";
import type {
  GraphEdge,
  GraphNode,
  PathCandidate,
  Report,
  PathWorkspace,
} from "../types";
import { NetworkGraph } from "../NetworkGraph";
import { EmptyState, StatusBadge } from "./Primitives";

export function ReportAnalysisView({
  report,
  backLabel,
  onBack,
  onOpenAnalysis,
}: {
  report?: Report;
  backLabel: string;
  onBack: () => void;
  onOpenAnalysis: (report: Report) => void;
}) {
  return (
    <main className="page-frame report-analysis-page">
      <div className="page-toolbar">
        <button type="button" className="back-link" onClick={onBack}>
          <ArrowLeft size={16} /> {backLabel}
        </button>
        <span className="report-analysis-state">
          <ShieldCheck size={15} /> 已完成研判
        </span>
      </div>
      <ReportDetail report={report} onOpenAnalysis={onOpenAnalysis} />
    </main>
  );
}

function ReportDetail({
  report,
  onOpenAnalysis,
}: {
  report?: Report;
  onOpenAnalysis: (report: Report) => void;
}) {
  if (!report) {
    return (
      <EmptyState title="没有可展示的报告" description="当前情报快照尚未包含报告。" />
    );
  }
  return (
    <section className="report-detail">
      <header>
        <div>
          <span className="eyebrow">{report.source_ref || "ARCHIVED SOURCE"}</span>
          <h1>{report.title}</h1>
          <p>
            {report.source} · {formatDate(report.report_date)} · {report.reliability}
          </p>
        </div>
        <StatusBadge status={report.external_url ? "positive" : "partial"}>
          {report.external_url ? "真实外部来源" : "内部归档"}
        </StatusBadge>
      </header>
      <div className="report-assessment">
        <span>研判摘要</span>
        <p>{report.assessment || report.extraction_note || "当前报告暂无结构化摘要。"}</p>
      </div>
      <div className="report-excerpt">
        <span>报告内容预览</span>
        <ReportDocumentPreview text={report.extracted_text} />
      </div>
      <dl className="report-meta-grid">
        <div>
          <dt>分类</dt>
          <dd>{report.classification}</dd>
        </div>
        <div>
          <dt>语言</dt>
          <dd>{report.language}</dd>
        </div>
        <div>
          <dt>可靠性</dt>
          <dd>{report.reliability || "未评级"}</dd>
        </div>
        <div>
          <dt>来源编号</dt>
          <dd>{report.source_ref || "未记录"}</dd>
        </div>
      </dl>
      <footer>
        <button
          type="button"
          className="report-open-analysis"
          onClick={() => onOpenAnalysis(report)}
        >
          进入完整研判 <ArrowRight size={14} />
        </button>
        {report.external_url ? (
          <a href={report.external_url} target="_blank" rel="noreferrer">
            查看原始来源 <ExternalLink size={14} />
          </a>
        ) : (
          <span className="muted">当前归档没有外部原文链接</span>
        )}
      </footer>
    </section>
  );
}

function ReportDocumentPreview({ text }: { text: string }) {
  const lines = (text.slice(0, 900) || "未保存可展示的报告正文。")
    .split(/\n+/)
    .map((line) => line.trim())
    .filter(Boolean);
  const sectionHeading = /^(?:[一二三四五六七八九十]+[、.]|材料说明|研判要求)/;

  return (
    <div className="report-document-preview">
      {lines.map((line, index) => {
        if (index === 0 && line.length <= 72) {
          return <h2 key={`${index}-${line}`}>{line}</h2>;
        }
        if (sectionHeading.test(line) && line.length <= 72) {
          return <h3 key={`${index}-${line}`}>{line}</h3>;
        }
        if (/^来源[：:]/.test(line)) {
          return <p className="report-document-source" key={`${index}-${line}`}>{line}</p>;
        }
        return <p key={`${index}-${line}`}>{line}</p>;
      })}
    </div>
  );
}

export function FullGraphView({
  data,
  rootId,
  backLabel,
  showBack,
  onBack,
  onStartPath,
  onOpenActor,
}: {
  data: PathWorkspace;
  rootId?: string;
  backLabel: string;
  showBack: boolean;
  onBack: () => void;
  onStartPath: (candidates: PathCandidate[], contextLabel: string) => void;
  onOpenActor: (actorId: string) => void;
}) {
  const [currentRootId, setCurrentRootId] = useState(rootId ?? "");
  const [runtimeIndex, setRuntimeIndex] = useState<Awaited<ReturnType<typeof requestPanoramicGraphIndex>>>();
  const [runtimeGraph, setRuntimeGraph] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] }>({ nodes: [], edges: [] });
  const [indexStatus, setIndexStatus] = useState<"loading" | "ready" | "offline">("loading");
  const [indexError, setIndexError] = useState("");
  const [neighborhoodStatus, setNeighborhoodStatus] = useState<"loading" | "ready" | "offline">(
    rootId ? "loading" : "ready",
  );
  const [neighborhoodError, setNeighborhoodError] = useState("");
  const [graphRetryVersion, setGraphRetryVersion] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const searchRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const curatedRootLabels = useMemo(
    () => [
      "APT28",
      "Jaguar Tooth",
      "cdn-meeting-update.com",
      "194.32.78.245",
      "PowerRatankba",
    ],
    [],
  );
  const [recentRootIds, setRecentRootIds] = useState<string[]>(() => {
    return rootId ? [rootId] : [];
  });
  const graph = runtimeGraph;
  const root = graph.nodes.find((node) => node.id === currentRootId);
  const runtimeEntities = useMemo(
    () => runtimeIndex?.nodes?.map(panoramicIndexNodeToEntity) ?? [],
    [runtimeIndex],
  );
  const graphEntityMap = useMemo(
    () =>
      new Map(
        runtimeEntities
          .map((entity) => [entity.id, entity]),
      ),
    [runtimeEntities],
  );
  const directRelationCounts = useMemo(() => {
    return new Map(runtimeIndex?.nodes.map((node) => [node.id, node.relation_count]) ?? []);
  }, [runtimeIndex]);
  const recentRoots = recentRootIds
    .map((id) => graphEntityMap.get(id))
    .filter((entity) => Boolean(entity));
  const curatedRoots = curatedRootLabels
    .map((label) => runtimeEntities.find((entity) => entity.label === label))
    .filter((entity) => Boolean(entity));
  const entityTypeCounts = useMemo(() => {
    const counts = new Map<string, number>();
    graphEntityMap.forEach((entity) => {
      counts.set(entity.entity_type, (counts.get(entity.entity_type) ?? 0) + 1);
    });
    return [...counts.entries()]
      .sort((left, right) => right[1] - left[1])
      .slice(0, 6);
  }, [graphEntityMap]);
  const featuredEntities = useMemo(() => {
    const seenTypes = new Set<string>();
    return [...graphEntityMap.values()]
      .sort(
        (left, right) =>
          (directRelationCounts.get(right.id) ?? 0) -
            (directRelationCounts.get(left.id) ?? 0) ||
          right.source_count - left.source_count ||
          left.label.localeCompare(right.label),
      )
      .filter((entity) => {
        if (seenTypes.has(entity.entity_type)) return false;
        seenTypes.add(entity.entity_type);
        return true;
      })
      .slice(0, 6);
  }, [graphEntityMap, directRelationCounts]);
  const normalizedSearch = searchQuery.trim().toLocaleLowerCase();
  const matchRank = (entity: (typeof data.entities)[number]) => {
    const label = entity.label.toLocaleLowerCase();
    const normalizedValue = entity.normalized_value.toLocaleLowerCase();
    if (label === normalizedSearch || normalizedValue === normalizedSearch) return 0;
    if (
      label.startsWith(normalizedSearch) ||
      normalizedValue.startsWith(normalizedSearch)
    ) {
      return 1;
    }
    if (
      label.includes(normalizedSearch) ||
      normalizedValue.includes(normalizedSearch)
    ) {
      return 2;
    }
    return 3;
  };
  const searchMatches = normalizedSearch
    ? [...graphEntityMap.values()]
        .filter((entity) =>
          `${entity.label} ${entity.normalized_value} ${entity.description}`
            .toLocaleLowerCase()
            .includes(normalizedSearch),
        )
        .sort(
          (left, right) =>
            matchRank(left) - matchRank(right) ||
            right.source_count - left.source_count ||
            left.label.localeCompare(right.label),
        )
        .slice(0, 6)
    : [];
  const recommendationCopy: Record<string, string> = {
    APT28: "查看组织、工具、技战术与历史活动",
    "Jaguar Tooth": "查看漏洞利用、路由器驻留与设备侧收集关系",
    "cdn-meeting-update.com": "查看 C2 基础设施与 APT28 历史活动",
    "194.32.78.245": "沿真实 C2、Zebrocy 活动与 APT28 逐跳核验",
    PowerRatankba: "查看招聘诱饵、PowerShell 后门与关联 IOC",
  };

  const loadIndex = useCallback(() => {
    requestPanoramicGraphIndex()
      .then((index) => {
        setRuntimeIndex(index);
        setIndexStatus("ready");
      })
      .catch((error) => {
        setRuntimeIndex(undefined);
        setIndexStatus("offline");
        setIndexError(error instanceof Error ? error.message : "无法加载运行时图谱索引。");
      });
  }, []);

  const selectRoot = (id: string) => {
    setNeighborhoodStatus("loading");
    setNeighborhoodError("");
    setCurrentRootId(id);
    setRecentRootIds((current) =>
      [id, ...current.filter((rootId) => rootId !== id)].slice(0, 3),
    );
    setSearchQuery("");
    setSearchOpen(false);
    searchInputRef.current?.blur();
  };

  useEffect(() => {
    loadIndex();
  }, [loadIndex]);

  useEffect(() => {
    if (!currentRootId) {
      return;
    }
    let active = true;
    requestPanoramicGraphNeighborhood(currentRootId)
      .then((neighborhood) => {
        if (!active) return;
        setRuntimeGraph(adaptPanoramicNeighborhood(neighborhood));
        setNeighborhoodStatus("ready");
      })
      .catch((error) => {
        if (!active) return;
        setRuntimeGraph({ nodes: [], edges: [] });
        setNeighborhoodStatus("offline");
        setNeighborhoodError(error instanceof Error ? error.message : "无法展开当前图谱节点。");
      });
    return () => {
      active = false;
    };
  }, [currentRootId, graphRetryVersion]);

  useEffect(() => {
    const closeOnOutsidePress = (event: PointerEvent) => {
      if (
        searchRef.current &&
        !searchRef.current.contains(event.target as Node)
      ) {
        setSearchOpen(false);
      }
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setSearchOpen(false);
        searchInputRef.current?.blur();
      }
    };

    document.addEventListener("pointerdown", closeOnOutsidePress);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsidePress);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, []);

  useEffect(() => {
    if (root?.id && !navigator.userAgent.toLowerCase().includes("jsdom")) {
      window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    }
  }, [root?.id]);

  const hasRoot = Boolean(root);
  const graphStatus = currentRootId ? neighborhoodStatus : indexStatus;
  const graphError = currentRootId ? neighborhoodError : indexError;

  return (
    <main
      className={`graph-explorer-page${hasRoot ? "" : " is-overview"}`}
    >
      <header
      className={`graph-explorer-hero${hasRoot ? " is-compact" : ""}`}
      >
        {showBack && (
          <button type="button" className="graph-explorer-back" onClick={onBack}>
            <ArrowLeft size={16} /> {backLabel}
          </button>
        )}

        <div className="graph-explorer-title">
          <span className="graph-emblem" aria-hidden="true">
            <Network size={22} />
          </span>
          <div>
            <h1>情报关系探索</h1>
            <p>从线索发现关联，并验证每一条关系的来源。</p>
          </div>
        </div>

        <div
          className={`graph-root-search${searchOpen ? " is-expanded" : ""}`}
          ref={searchRef}
        >
          <Search size={16} />
          <input
            ref={searchInputRef}
            aria-label="搜索图谱根实体"
            aria-controls="graph-search-assist-panel"
            value={searchQuery}
            onChange={(event) => {
              setSearchQuery(event.target.value);
              setSearchOpen(true);
            }}
            onClick={() => setSearchOpen(true)}
            onFocus={() => setSearchOpen(true)}
            placeholder="搜索 IOC、漏洞、工具、组织或报告"
          />
          {searchOpen && (
            <div
              className="graph-search-assist-panel"
              id="graph-search-assist-panel"
              role="region"
              aria-label="图谱搜索提示"
            >
              {normalizedSearch ? (
                <>
                  <div className="graph-search-panel-heading">
                    <div>
                      <span>匹配实体</span>
                      <small>选择后立即切换图谱调查中心</small>
                    </div>
                    <strong>{searchMatches.length} 个结果</strong>
                  </div>
                  {searchMatches.length > 0 ? (
                    <div className="graph-search-match-list">
                      {searchMatches.map((entity) => (
                        <button
                          type="button"
                          key={entity.id}
                          onClick={() => selectRoot(entity.id)}
                        >
                          <span className="graph-search-entity-type">
                            {entity.entity_type}
                          </span>
                          <span className="graph-search-entity-copy">
                            <strong>{entity.label}</strong>
                            <small>
                              {entity.description || entity.normalized_value}
                            </small>
                          </span>
                          <span className="graph-search-entity-meta">
                            <small>
                              {directRelationCounts.get(entity.id) ?? 0} 条关系
                            </small>
                            <small>{entity.source_count} 个来源</small>
                          </span>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <div className="graph-search-empty">
                      <strong>没有匹配的知识实体</strong>
                      <span>可尝试输入完整 IP、CVE 编号、组织或工具名称</span>
                    </div>
                  )}
                </>
              ) : (
                <>
                  <div className="graph-search-supported">
                    <span>可搜索</span>
                    {[
                      "IP",
                      "域名",
                      "Hash",
                      "CVE",
                      "攻击组织",
                      "工具",
                      "ATT&CK 技术",
                    ].map((type) => (
                      <small key={type}>{type}</small>
                    ))}
                  </div>
                  <div
                    className={`graph-search-start-grid${
                      recentRoots.length ? "" : " is-single"
                    }`}
                  >
                    {recentRoots.length > 0 && (
                      <section
                        aria-labelledby="graph-search-recent-title"
                        aria-label="最近调查"
                      >
                        <div className="graph-search-section-title">
                          <span id="graph-search-recent-title">最近调查</span>
                          <small>本次会话</small>
                        </div>
                        <div className="graph-search-shortcuts">
                          {recentRoots.map((entity) => (
                            <button
                              type="button"
                              key={entity!.id}
                              onClick={() => selectRoot(entity!.id)}
                            >
                              <span>{entity!.entity_type}</span>
                              <strong>{entity!.label}</strong>
                              <small>
                                {directRelationCounts.get(entity!.id) ?? 0} 条直接关系
                              </small>
                            </button>
                          ))}
                        </div>
                      </section>
                    )}
                    <section aria-labelledby="graph-search-recommended-title">
                      <div className="graph-search-section-title">
                        <span id="graph-search-recommended-title">
                          推荐调查入口
                        </span>
                        <small>典型关联结构</small>
                      </div>
                      <div className="graph-search-shortcuts">
                        {curatedRoots.map((entity) => (
                          <button
                            type="button"
                            key={entity!.id}
                            onClick={() => selectRoot(entity!.id)}
                          >
                            <span>{entity!.entity_type}</span>
                            <strong>{entity!.label}</strong>
                            <small>
                              {recommendationCopy[entity!.label] ??
                                entity!.description}
                            </small>
                          </button>
                        ))}
                      </div>
                    </section>
                  </div>
                </>
              )}
            </div>
          )}
        </div>

        <span className="graph-source-scope">
          <BookOpen size={14} />
          跨报告知识库
        </span>
      </header>

      {graphStatus === "loading" ? (
        <EmptyState title="正在加载运行时图谱" description="正在读取规范节点、原子关系与证据路径。" />
      ) : graphStatus === "offline" ? (
        <section className="graph-overview-home">
          <EmptyState title="运行时图谱不可用" description={graphError || "当前无法连接图谱后端。"} />
          <button
            type="button"
            className="graph-start-path"
            onClick={() => {
              setIndexStatus("loading");
              setIndexError("");
              if (currentRootId) {
                setNeighborhoodStatus("loading");
                setNeighborhoodError("");
              }
              loadIndex();
              setGraphRetryVersion((version) => version + 1);
            }}
          >
            重新加载
          </button>
        </section>
      ) : root ? (
        <GraphExplorerWorkspace
          key={currentRootId}
          data={data}
          nodes={graph.nodes}
          edges={graph.edges}
          root={root}
          onSetRoot={selectRoot}
          onStartPath={onStartPath}
          onOpenActor={onOpenActor}
        />
      ) : (
        <GraphExplorerOverview
          data={data}
          curatedRoots={curatedRoots}
          featuredEntities={featuredEntities}
          entityTypeCounts={entityTypeCounts}
          directRelationCounts={directRelationCounts}
          graphStats={{
            entities: runtimeIndex?.node_count ?? 0,
            relationships:
              (runtimeIndex?.atomic_edge_count ?? 0) +
              (runtimeIndex?.aggregate_edge_count ?? 0),
            evidence: Math.max(
              (runtimeIndex?.node_count ?? 0) - (runtimeIndex?.nodes.length ?? 0),
              0,
            ),
          }}
          recommendationCopy={recommendationCopy}
          onSelectRoot={selectRoot}
          onFocusSearch={() => {
            setSearchOpen(true);
            searchInputRef.current?.focus();
          }}
        />
      )}
    </main>
  );
}

function GraphExplorerOverview({
  data,
  curatedRoots,
  featuredEntities,
  entityTypeCounts,
  directRelationCounts,
  graphStats,
  recommendationCopy,
  onSelectRoot,
  onFocusSearch,
}: {
  data: PathWorkspace;
  curatedRoots: Array<PathWorkspace["entities"][number] | undefined>;
  featuredEntities: PathWorkspace["entities"];
  entityTypeCounts: Array<[string, number]>;
  directRelationCounts: Map<string, number>;
  graphStats: {
    entities: number;
    relationships: number;
    evidence: number;
  };
  recommendationCopy: Record<string, string>;
  onSelectRoot: (id: string) => void;
  onFocusSearch: () => void;
}) {
  const entryMeta: Record<
    string,
    {
      title: string;
      description: string;
      icon: typeof Fingerprint;
    }
  > = {
    "194.32.78.245": {
      title: "从 IOC 追踪基础设施",
      description: "从 C2 回到 Zebrocy 活动、攻击步骤与来源证据。",
      icon: Fingerprint,
    },
    PowerRatankba: {
      title: "从工具还原攻击过程",
      description: "连接招聘诱饵、PowerShell 后门、IOC 与历史活动。",
      icon: Bug,
    },
    APT28: {
      title: "从组织查看技战术",
      description: "浏览组织使用的工具、TTP 与历史攻击活动。",
      icon: Users,
    },
  };

  return (
    <section className="graph-overview-home" aria-label="情报图谱综合入口">
      <header className="graph-overview-intro">
        <div>
          <span className="graph-overview-mark">
            <Network size={25} />
          </span>
          <div>
            <h2>从一个真实实体开始探索</h2>
            <p>
              选择 IOC、漏洞、组织、工具或技战术作为起点，再逐跳验证关系与来源证据。
            </p>
          </div>
        </div>
        <button type="button" onClick={onFocusSearch}>
          <Search size={16} />
          搜索知识库
        </button>
      </header>

      <div className="graph-overview-primary">
        <section
          className="graph-exploration-entry"
          aria-labelledby="graph-entry-title"
        >
          <header>
            <div>
              <h2 id="graph-entry-title">选择探索方式</h2>
              <p>这些入口均来自当前知识库，只有选择后才会生成真实图谱。</p>
            </div>
          </header>
          <div className="graph-exploration-entry-list">
            {curatedRoots.map((entity) => {
              if (!entity) return null;
              const meta = entryMeta[entity.label];
              const Icon = meta?.icon ?? Activity;
              return (
                <button
                  type="button"
                  key={entity.id}
                  onClick={() => onSelectRoot(entity.id)}
                >
                  <span className="graph-entry-icon">
                    <Icon size={19} />
                  </span>
                  <span className="graph-entry-copy">
                    <strong>{meta?.title || entity.label}</strong>
                    <small>
                      {meta?.description ||
                        recommendationCopy[entity.label] ||
                        entity.description}
                    </small>
                  </span>
                  <span className="graph-entry-example">
                    <small>示例实体</small>
                    <strong>{entity.label}</strong>
                  </span>
                  <ArrowRight size={16} />
                </button>
              );
            })}
          </div>
        </section>

        <aside
          className="graph-knowledge-summary"
          aria-labelledby="graph-summary-title"
        >
          <header>
            <Database size={17} />
            <div>
              <h2 id="graph-summary-title">知识库概览</h2>
              <p>当前加载的来源化知识快照</p>
            </div>
          </header>
          <dl className="graph-overview-stats">
            <div>
              <dt>知识实体</dt>
              <dd>{graphStats.entities}</dd>
            </div>
            <div>
              <dt>攻击知识关系</dt>
              <dd>{graphStats.relationships}</dd>
            </div>
            <div>
              <dt>来源证据</dt>
              <dd>{graphStats.evidence}</dd>
            </div>
            <div>
              <dt>情报报告</dt>
              <dd>{data.stats.reports}</dd>
            </div>
          </dl>
          <div className="graph-type-coverage">
            <div>
              <strong>主要实体覆盖</strong>
              <small>{entityTypeCounts.length} 类</small>
            </div>
            {entityTypeCounts.map(([type, count]) => (
              <div key={type}>
                <span>{type}</span>
                <strong>{count}</strong>
              </div>
            ))}
          </div>
        </aside>
      </div>

      <section
        className="graph-featured-entities"
        aria-labelledby="graph-featured-title"
      >
        <header>
          <div>
            <h2 id="graph-featured-title">高关联实体</h2>
            <p>按当前知识库中的直接关系数量排序，并覆盖不同实体类型。</p>
          </div>
          <button type="button" onClick={onFocusSearch}>
            查看更多 <ArrowRight size={14} />
          </button>
        </header>
        <div className="graph-featured-list">
          {featuredEntities.map((entity) => (
            <button
              type="button"
              key={entity.id}
              onClick={() => onSelectRoot(entity.id)}
            >
              <span>{entity.entity_type}</span>
              <strong>{entity.label}</strong>
              <small>
                {directRelationCounts.get(entity.id) ?? 0} 条直接关系
              </small>
              <ArrowRight size={14} />
            </button>
          ))}
        </div>
      </section>
    </section>
  );
}

type GraphInspectorTab = "overview" | "evidence" | "relations";

const relationCategoryLabels: Record<string, string> = {
  chain: "攻击过程",
  evidence: "检测证据",
  technique: "技战术映射",
  attribution: "组织关联",
  association: "一般关联",
  infrastructure: "基础设施",
  context: "行为上下文",
};

function GraphExplorerWorkspace({
  data,
  nodes,
  edges,
  root,
  onSetRoot,
  onStartPath,
  onOpenActor,
}: {
  data: PathWorkspace;
  nodes: GraphNode[];
  edges: GraphEdge[];
  root?: GraphNode;
  onSetRoot: (id: string) => void;
  onStartPath: (candidates: PathCandidate[], contextLabel: string) => void;
  onOpenActor: (actorId: string) => void;
}) {
  const rootIds = useMemo(() => (root ? [root.id] : []), [root]);
  const initialIds = useMemo(() => {
    const next = new Set(rootIds);
    if (root) next.add(root.id);
    const firstHop = edges
      .filter(
        (edge) => edge.source === root?.id || edge.target === root?.id,
      )
      .sort(
        (left, right) =>
          (right.confidence ?? 0) - (left.confidence ?? 0),
      )
      .slice(0, 12)
      .map((edge) => {
        next.add(edge.source);
        next.add(edge.target);
        return edge.source === root?.id ? edge.target : edge.source;
      });

    if (next.size < 14) {
      edges
        .filter(
          (edge) =>
            firstHop.includes(edge.source) ||
            firstHop.includes(edge.target),
        )
        .sort(
          (left, right) =>
            (right.confidence ?? 0) - (left.confidence ?? 0),
        )
        .some((edge) => {
          next.add(edge.source);
          next.add(edge.target);
          return next.size >= 14;
        });
    }

    return [...next];
  }, [edges, root, rootIds]);

  const [visibleIds, setVisibleIds] = useState(initialIds);
  const [expansionHistory, setExpansionHistory] = useState<string[][]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState(root?.id);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string>();
  const [inspectorTab, setInspectorTab] =
    useState<GraphInspectorTab>("overview");
  const entityTypes = [...new Set(nodes.map((node) => node.type))];
  const relationCategories = [
    ...new Set(edges.map((edge) => edge.category || "association")),
  ];
  const [activeTypes, setActiveTypes] = useState(
    () => new Set(entityTypes),
  );
  const [activeCategories, setActiveCategories] = useState(
    () => new Set(relationCategories),
  );
  const [onlySourced, setOnlySourced] = useState(false);

  const visibleSet = new Set(visibleIds);
  const visibleNodes = nodes.filter((node) => visibleSet.has(node.id));
  const visibleEdges = edges.filter(
    (edge) => visibleSet.has(edge.source) && visibleSet.has(edge.target),
  );
  const selectedNode = nodes.find((node) => node.id === selectedNodeId);
  const selectedEdge = edges.find((edge) => edge.id === selectedEdgeId);
  const selectedRelationship = selectedEdge?.relationship;
  const selectedEdgeEvidence = selectedEdge?.evidence?.length
    ? selectedEdge.evidence
    : selectedRelationship
      ? data.evidence.filter(
        (evidence) =>
          evidence.relationship_id === selectedRelationship.id,
        )
      : [];
  const selectedNodeEdges = selectedNode
    ? visibleEdges.filter(
        (edge) =>
          edge.source === selectedNode.id ||
          edge.target === selectedNode.id,
      )
    : [];
  const selectedNodeEvidence = selectedNode
    ? [...new Map(
        [
          ...selectedNodeEdges.flatMap((edge) => edge.evidence ?? []),
          ...data.evidence.filter((evidence) =>
            selectedNodeEdges.some(
              (edge) => edge.relationship?.id === evidence.relationship_id,
            ),
          ),
        ].map((evidence) => [evidence.id, evidence]),
      ).values()]
    : [];
  const currentEvidence = selectedEdge
    ? selectedEdgeEvidence
    : selectedNodeEvidence;
  const selectedSource = selectedEdge
    ? nodes.find((node) => node.id === selectedEdge.source)
    : undefined;
  const selectedTarget = selectedEdge
    ? nodes.find((node) => node.id === selectedEdge.target)
    : undefined;
  const hiddenNeighborIds = selectedNode
    ? [
        ...new Set(
          edges
            .filter(
              (edge) =>
                edge.source === selectedNode.id ||
                edge.target === selectedNode.id,
            )
            .map((edge) =>
              edge.source === selectedNode.id ? edge.target : edge.source,
            )
            .filter((id) => !visibleSet.has(id)),
        ),
      ]
    : [];
  const hiddenNeighborCounts = Object.fromEntries(
    visibleNodes.map((node) => [
      node.id,
      new Set(
        edges
          .filter(
            (edge) => edge.source === node.id || edge.target === node.id,
          )
          .map((edge) =>
            edge.source === node.id ? edge.target : edge.source,
          )
          .filter((id) => !visibleSet.has(id)),
      ).size,
    ]),
  );
  const mutedIds = visibleNodes
    .filter((node) => !activeTypes.has(node.type))
    .map((node) => node.id);
  const mutedEdgeIds = visibleEdges
    .filter(
      (edge) =>
        !activeCategories.has(edge.category || "association") ||
        (onlySourced &&
          !(edge.evidence?.length || edge.relationship?.evidence_count)),
    )
    .map((edge) => edge.id);
  const highlightedNodeIds = selectedEdge
    ? [selectedEdge.source, selectedEdge.target]
    : selectedNode
      ? [
          selectedNode.id,
          ...selectedNodeEdges.flatMap((edge) => [
            edge.source,
            edge.target,
          ]),
        ]
      : rootIds;
  const highlightedEdgeIds = selectedEdge
    ? [selectedEdge.id]
    : selectedNodeEdges.map((edge) => edge.id);

  const revealOneHop = () => {
    if (!hiddenNeighborIds.length) return;
    setExpansionHistory((history) => [...history, visibleIds]);
    setVisibleIds((ids) => [...new Set([...ids, ...hiddenNeighborIds])]);
  };
  const undoExpansion = () => {
    const previous = expansionHistory.at(-1);
    if (!previous) return;
    setVisibleIds(previous);
    setExpansionHistory((history) => history.slice(0, -1));
  };
  const resetScope = () => {
    setVisibleIds(initialIds);
    setExpansionHistory([]);
    setSelectedNodeId(root?.id);
    setSelectedEdgeId(undefined);
  };
  const selectNode = (node: GraphNode) => {
    setSelectedNodeId(node.id);
    setSelectedEdgeId(undefined);
    setInspectorTab("overview");
  };
  const selectEdge = (edge: GraphEdge) => {
    setSelectedEdgeId(edge.id);
    setInspectorTab("overview");
  };
  const selectedHistoricalPathId =
    selectedNode?.historicalPathId ?? selectedEdge?.historicalPathId;
  const selectedEntityIds = [
    selectedNode?.entity?.id,
    selectedNode && !selectedNode.virtual ? selectedNode.id : undefined,
    root?.entity?.id,
  ].filter((id): id is string => Boolean(id));
  const matchedHistoricalPaths = selectedHistoricalPathId
    ? data.historicalPaths.filter(
        (path) => path.id === selectedHistoricalPathId,
      )
    : data.historicalPaths
        .filter((path) =>
          path.contextLinks.some((link) =>
            selectedEntityIds.includes(link.entity_id),
          ),
        )
        .sort(
          (left, right) =>
            right.confidence - left.confidence ||
            left.id.localeCompare(right.id),
        );
  const matchedPathCandidates = matchedHistoricalPaths.map(
    historicalPathCandidate,
  );
  const pathContextLabel =
    selectedNode?.label ?? selectedEdge?.label ?? root?.label ?? "当前图谱上下文";

  return (
    <>
      <div className="graph-explorer-context">
        <div className="graph-root-context">
          <LocateFixed size={15} />
          <span>当前调查种子</span>
          <strong>{root?.label || "未选择实体"}</strong>
          <small>{root?.type || "未知类型"}</small>
        </div>
        <div className="graph-explorer-context-actions">
          <span>{visibleNodes.length} 节点</span>
          <span>{visibleEdges.length} 关系</span>
          <button
            type="button"
            disabled={!expansionHistory.length}
            onClick={undoExpansion}
          >
            <Undo2 size={14} />
            撤销展开
          </button>
          <button type="button" onClick={resetScope}>
            <Target size={14} />
            回到初始范围
          </button>
        </div>
      </div>

      <div className="graph-explorer-layout">
        <aside className="graph-filter-panel">
          <header>
            <Filter size={15} />
            <div>
              <strong>调查筛选</strong>
              <small>筛选只降低视觉权重，不改变节点位置</small>
            </div>
          </header>

          <section>
            <h2>实体类型</h2>
            <div className="graph-filter-list">
              {entityTypes
                .filter((type) =>
                  visibleNodes.some((node) => node.type === type),
                )
                .map((type) => (
                <button
                  type="button"
                  className={activeTypes.has(type) ? "is-active" : ""}
                  key={type}
                  onClick={() =>
                    setActiveTypes((current) => {
                      const next = new Set(current);
                      if (next.has(type)) next.delete(type);
                      else next.add(type);
                      return next;
                    })
                  }
                >
                  <span>{type}</span>
                  <strong>
                    {visibleNodes.filter((node) => node.type === type).length}
                  </strong>
                </button>
                ))}
            </div>
          </section>

          <section>
            <h2>关系类型</h2>
            <div className="graph-filter-list">
              {relationCategories
                .filter((category) =>
                  visibleEdges.some(
                    (edge) =>
                      (edge.category || "association") === category,
                  ),
                )
                .map((category) => (
                <button
                  type="button"
                  className={
                    activeCategories.has(category) ? "is-active" : ""
                  }
                  key={category}
                  onClick={() =>
                    setActiveCategories((current) => {
                      const next = new Set(current);
                      if (next.has(category)) next.delete(category);
                      else next.add(category);
                      return next;
                    })
                  }
                >
                  <span>
                    {relationCategoryLabels[category] || category}
                  </span>
                  <strong>
                    {
                      visibleEdges.filter(
                        (edge) =>
                          (edge.category || "association") === category,
                      ).length
                    }
                  </strong>
                </button>
                ))}
            </div>
          </section>

          <section>
            <h2>证据范围</h2>
            <button
              type="button"
              className={`graph-evidence-filter ${
                onlySourced ? "is-active" : ""
              }`}
              onClick={() => setOnlySourced((value) => !value)}
            >
              <ShieldCheck size={14} />
              <span>
                <strong>仅强调有原文证据的关系</strong>
                <small>其他关系保留在画布中作为上下文</small>
              </span>
            </button>
          </section>
        </aside>

        <section className="analysis-graph-panel graph-explorer-canvas">
          <header>
            <div>
              <h2>关联知识图谱</h2>
              <p>放射拓扑展示真实关联，点击节点或关系验证来源并继续探索。</p>
            </div>
            <div className="graph-canvas-legend">
              <span><i className="is-direct" />直接证据</span>
              <span><i className="is-inferred" />推断关系</span>
              <span><i className="is-candidate" />候选关系</span>
            </div>
          </header>
          <NetworkGraph
            nodes={visibleNodes}
            edges={visibleEdges}
            rootId={root?.id}
            selectedId={selectedEdge ? undefined : selectedNode?.id}
            selectedEdgeId={selectedEdge?.id}
            highlightIds={highlightedNodeIds}
            highlightEdgeIds={highlightedEdgeIds}
            mutedIds={mutedIds}
            mutedEdgeIds={mutedEdgeIds}
            hiddenNeighborCounts={hiddenNeighborCounts}
            focusMode={Boolean(
              selectedEdge ||
                (selectedNode && selectedNode.id !== root?.id),
            )}
            layout="radial"
            stabilizeExpansion
            onSelect={selectNode}
            onSelectEdge={selectEdge}
          />
        </section>

        <aside className="analysis-context-panel graph-explorer-inspector">
          <section className="analysis-investigation-panel">
            <header className="investigation-panel-heading">
              <div>
                <span>{selectedEdge ? "当前关系" : "当前实体"}</span>
                <h2>
                  {selectedEdge
                    ? `${selectedSource?.label || "未知实体"} → ${
                        selectedTarget?.label || "未知实体"
                      }`
                    : selectedNode?.label || "请选择节点"}
                </h2>
              </div>
              <StatusBadge
                status={
                  selectedEdge
                    ? selectedEdgeEvidence.length
                      ? "positive"
                      : "partial"
                    : selectedNode?.status ?? "positive"
                }
              />
            </header>

            <div className="investigation-verdict-bar">
              <div>
                <span>{selectedEdge ? "关系" : "类型"}</span>
                <strong>{selectedEdge?.label || selectedNode?.type || "-"}</strong>
              </div>
              <div>
                <span>置信度</span>
                <strong>
                  {Math.round(
                    (selectedEdge?.confidence ??
                      selectedNode?.confidence ??
                      0) * 100,
                  )}
                  %
                </strong>
              </div>
              <div>
                <span>{selectedEdge ? "来源报告" : "直接关系"}</span>
                <strong>
                  {selectedEdge
                    ? selectedEdgeEvidence.length
                    : selectedNodeEdges.length}
                </strong>
              </div>
            </div>

            <div className="investigation-tabs" role="tablist" aria-label="图谱调查内容">
              {[
                ["overview", "概览"],
                ["evidence", "证据"],
                ["relations", "关联"],
              ].map(([id, label]) => (
                <button
                  type="button"
                  role="tab"
                  key={id}
                  aria-selected={inspectorTab === id}
                  className={inspectorTab === id ? "is-active" : ""}
                  onClick={() => setInspectorTab(id as GraphInspectorTab)}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="investigation-tab-content">
              {inspectorTab === "overview" && (
                <div className="graph-inspector-overview">
                  {selectedEdge ? (
                    <>
                      <div className="verdict-statement">
                        <GitBranch size={15} />
                        <div>
                          <strong>
                            {selectedEdge.aggregate
                              ? "该捷径由底层原子关系动态聚合"
                              : selectedEdgeEvidence.length
                                ? "来源报告直接支持这条关系"
                                : "当前关系缺少原文级直接证据"}
                          </strong>
                          <p>
                            {selectedSource?.label} 通过“
                            {selectedEdge.label}”连接到{" "}
                            {selectedTarget?.label}。
                          </p>
                          {selectedEdge.explanation && (
                            <p>
                              解释路径：{selectedEdge.explanation.nodeIds
                                .map((id) => nodes.find((node) => node.id === id)?.label || id)
                                .join(" → ")}
                            </p>
                          )}
                        </div>
                      </div>
                      <dl className="graph-relation-meta">
                        <div>
                          <dt>首次出现</dt>
                          <dd>
                            {formatDate(
                              selectedRelationship?.first_seen || "",
                            )}
                          </dd>
                        </div>
                        <div>
                          <dt>最后出现</dt>
                          <dd>
                            {formatDate(
                              selectedRelationship?.last_seen || "",
                            )}
                          </dd>
                        </div>
                        <div>
                          <dt>证据记录</dt>
                          <dd>
                            {selectedEdgeEvidence.length}
                          </dd>
                        </div>
                      </dl>
                    </>
                  ) : (
                    <>
                      <div className="verdict-statement">
                        <Target size={15} />
                        <div>
                          <strong>围绕该实体继续验证关联</strong>
                          <p>
                            {selectedNode?.description ||
                              selectedNode?.entity?.description ||
                              "选择图谱节点后，可以检查其来源、关系和未展开邻居。"}
                          </p>
                        </div>
                      </div>
                      <dl className="graph-relation-meta">
                        <div>
                          <dt>首次出现</dt>
                          <dd>
                            {formatDate(
                              selectedNode?.entity?.first_seen || "",
                            )}
                          </dd>
                        </div>
                        <div>
                          <dt>最后出现</dt>
                          <dd>
                            {formatDate(
                              selectedNode?.entity?.last_seen || "",
                            )}
                          </dd>
                        </div>
                        <div>
                          <dt>来源数量</dt>
                          <dd>
                            {selectedNodeEvidence.length}
                          </dd>
                        </div>
                      </dl>
                    </>
                  )}
                </div>
              )}

              {inspectorTab === "evidence" && (
                <div className="graph-evidence-list">
                  {currentEvidence.length ? (
                    currentEvidence.map((evidence) => {
                      const report = data.reports.find(
                        (item) => item.id === evidence.report_id,
                      );
                      return (
                        <article key={evidence.id}>
                          <header>
                            <BookOpen size={14} />
                            <div>
                              <strong>{evidence.report_title}</strong>
                              <small>
                                {evidence.publisher} ·{" "}
                                {formatDate(evidence.report_date)}
                              </small>
                            </div>
                          </header>
                          <p>{evidence.excerpt}</p>
                          <footer>
                            <span>{evidence.location || "报告正文"}</span>
                            {(report?.external_url || evidence.canonical_url) && (
                              <a
                                href={report?.external_url || evidence.canonical_url}
                                target="_blank"
                                rel="noreferrer"
                              >
                                原始来源 <ExternalLink size={12} />
                              </a>
                            )}
                          </footer>
                        </article>
                      );
                    })
                  ) : (
                    <p className="graph-inspector-empty">
                      当前选择没有可展示的原文级证据。它仍可作为候选关系继续核验。
                    </p>
                  )}
                </div>
              )}

              {inspectorTab === "relations" && (
                <div className="graph-relation-list">
                  {(selectedEdge
                    ? [selectedSource, selectedTarget].filter(
                        (node): node is GraphNode => Boolean(node),
                      )
                    : selectedNodeEdges
                        .map((edge) =>
                          nodes.find(
                            (node) =>
                              node.id ===
                              (edge.source === selectedNode?.id
                                ? edge.target
                                : edge.source),
                          ),
                        )
                        .filter(
                          (node): node is GraphNode => Boolean(node),
                        )
                  ).map((node) => (
                    <button
                      type="button"
                      key={node.id}
                      onClick={() => selectNode(node)}
                    >
                      <span>{node.type}</span>
                      <strong>{node.label}</strong>
                      <ArrowRight size={13} />
                    </button>
                  ))}
                </div>
              )}

              {!selectedEdge && selectedNode && (
                <div className="graph-inspector-actions">
                  {selectedNode.type === "攻击组织" && (
                    <button
                      type="button"
                      onClick={() => onOpenActor(selectedNode.id)}
                    >
                      <Users size={14} />
                      <span>
                        <strong>查看组织画像</strong>
                        <small>进入长期对手档案</small>
                      </span>
                    </button>
                  )}
                  <button
                    type="button"
                    disabled={!hiddenNeighborIds.length}
                    onClick={revealOneHop}
                  >
                    <CornerDownRight size={14} />
                    <span>
                      <strong>展开一跳关联</strong>
                      <small>
                        {hiddenNeighborIds.length
                          ? `将增加 ${hiddenNeighborIds.length} 个节点`
                          : "直接关联已全部显示"}
                      </small>
                    </span>
                  </button>
                  <button
                    type="button"
                    disabled={
                      selectedNode.id === root?.id || selectedNode.virtual
                    }
                    onClick={() => onSetRoot(selectedNode.id)}
                  >
                    <LocateFixed size={14} />
                    <span>
                      <strong>以此重新调查</strong>
                      <small>设为新的图谱根实体</small>
                    </span>
                  </button>
                </div>
              )}

              {matchedPathCandidates.length > 0 && (
                <button
                  type="button"
                  className="graph-start-path"
                  onClick={() =>
                    onStartPath(matchedPathCandidates, pathContextLabel)
                  }
                >
                  <GitBranch size={15} />
                  {matchedPathCandidates.length === 1
                    ? "打开唯一攻击路径"
                    : `研判 ${matchedPathCandidates.length} 条候选路径`}
                  <ArrowRight size={14} />
                </button>
              )}
            </div>
          </section>
        </aside>
      </div>
    </>
  );
}
