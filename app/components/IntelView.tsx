"use client";

import {
  ArrowLeft,
  ArrowRight,
  CalendarDays,
  Database,
  ExternalLink,
  FileText,
  Fingerprint,
  GitBranch,
  Link2,
  Network,
  Quote,
  ShieldAlert,
} from "lucide-react";
import { useMemo, useState } from "react";
import {
  buildSubgraph,
  citationsForEntity,
  detectQueryType,
  formatDate,
  historicalPathCandidate,
  propNumber,
  propString,
  searchSnapshot,
} from "../argus-domain";
import type {
  Entity,
  PathCandidate,
  IntelligenceWorkspace,
  SourceCitation,
} from "../types";
import { NetworkGraph } from "../NetworkGraph";
import {
  Confidence,
  EmptyState,
  SourceCard,
  SourceViewer,
  StatusBadge,
} from "./Primitives";

type Tab = "overview" | "evidence" | "history" | "chains";

const IOC_QUERY_TYPES = new Set([
  "IPv4",
  "文件哈希",
  "域名",
  "URL",
  "CVE",
]);

function iocVerdict(status: string) {
  if (status === "hot" || status === "confirmed") {
    return { label: "恶意", tone: "critical" };
  }
  if (status === "partial" || status === "candidate") {
    return { label: "待复核", tone: "warning" };
  }
  if (status === "negative" || status === "excluded") {
    return { label: "未发现恶意", tone: "negative" };
  }
  return { label: "已关联威胁", tone: "positive" };
}

function actionRoleLabel(role: string) {
  return (
    {
      opens: "打开",
      extracts: "解压",
      "identified-by": "由此哈希识别",
      "uses-malware": "使用恶意软件",
      "copies-as": "复制为",
      "mapped-to-technique": "映射技战术",
      "exfiltrates-to": "向其外传",
      "connects-to": "连接",
      "targets-asset": "作用于资产",
      "monitors-communications": "监控通信",
      "delivers-to": "投递至",
      "downloads-from": "从其下载",
      "executes-file": "执行文件",
      uses: "行为使用",
      "communicates-with": "与其通信",
      exploits: "利用",
      enables: "促成",
      "drops-on": "投放至",
    }[role] ?? role.replaceAll("-", " ")
  );
}

export function IntelView({
  data,
  query,
  backLabel,
  onBack,
  onOpenGraph,
  onOpenPath,
}: {
  data: IntelligenceWorkspace;
  query: string;
  backLabel: string;
  onBack: () => void;
  onOpenGraph: (entity: Entity) => void;
  onOpenPath: (candidate: PathCandidate) => void;
}) {
  const result = useMemo(() => searchSnapshot(data, query), [data, query]);
  const queryEntity = result.entities[0]?.entity;
  const [selectedEntity, setSelectedEntity] = useState<Entity | undefined>(
    queryEntity,
  );
  const [tab, setTab] = useState<Tab>("overview");
  const [source, setSource] = useState<SourceCitation>();
  const entity = selectedEntity ?? result.entities[0]?.entity;
  const isIocResult = Boolean(
    IOC_QUERY_TYPES.has(result.queryType) ||
      queryEntity?.entity_type.includes("IOC"),
  );

  if (!entity) {
    return (
      <main className="page-frame">
        <button type="button" className="back-link" onClick={onBack}>
          <ArrowLeft size={16} /> {backLabel}
        </button>
        <EmptyState
          title="数据库中没有直接匹配"
          description="ARGUS 不会为未入库的指标生成模拟情报。请调整查询条件或检查指标格式。"
        />
      </main>
    );
  }

  const relatedEdges = data.relationships.filter(
    (edge) =>
      edge.source_entity_id === entity.id || edge.target_entity_id === entity.id,
  );
  const contextPathMatches = data.historicalPaths.flatMap((path) => {
    const links = path.contextLinks.filter(
      (link) => link.entity_id === entity.id,
    );
    if (!links.length) return [];
    const actionIds = new Set(links.map((link) => link.action_node_id));
    const sortedNodes = [...path.nodes].sort(
      (left, right) =>
        Number(left.sequence_hint ?? 0) - Number(right.sequence_hint ?? 0),
    );
    const nodeById = new Map(
      sortedNodes.map((node) => [String(node.id), node]),
    );
    const mainlineIds =
      path.projection?.mainline_action_refs ??
      sortedNodes.map((node) => String(node.id));
    const focusId =
      mainlineIds.find((id) => actionIds.has(id)) ?? links[0].action_node_id;
    const focusIndex = mainlineIds.indexOf(focusId);
    const localIds =
      focusIndex >= 0
        ? mainlineIds.slice(
            Math.max(0, focusIndex - 1),
            Math.min(mainlineIds.length, focusIndex + 2),
          )
        : [focusId];
    return [
      {
        path,
        links,
        actionIds,
        focusId,
        localNodes: localIds
          .map((id) => nodeById.get(id))
          .filter((node): node is Record<string, unknown> => Boolean(node)),
      },
    ];
  });
  const contextEvidence = contextPathMatches.flatMap(({ path }) =>
    path.contextEvidence.filter((item) => item.entity_id === entity.id),
  );
  const artifactById = new Map(
    data.sourceArtifacts.map((artifact) => [artifact.id, artifact]),
  );
  const contextCitations: SourceCitation[] = contextEvidence.map(
    (item, index) => {
      const artifactId = String(item.artifact_id ?? "");
      const artifact = artifactById.get(artifactId);
      return {
        id: String(item.id ?? `${entity.id}-context-${index}`),
        reportId: artifactId,
        title: String(item.report_title ?? artifact?.title ?? "公开情报报告"),
        publisher: String(item.publisher ?? artifact?.publisher ?? "未知来源"),
        reportDate: String(artifact?.published_at ?? ""),
        sourceRef: String(item.source_span_id ?? ""),
        excerpt: String(item.quote ?? ""),
        location: String(item.locator ?? ""),
        confidence: Number(item.confidence ?? 0),
        externalUrl: String(
          item.canonical_url ?? artifact?.canonical_url ?? "",
        ),
      };
    },
  );
  const canonicalCitations = citationsForEntity(data, entity.id);
  const citations = [...canonicalCitations, ...contextCitations].filter(
    (citation, index, items) =>
      items.findIndex((item) => item.id === citation.id) === index,
  );
  const relatedIds = relatedEdges.flatMap((edge) => [
    edge.source_entity_id,
    edge.target_entity_id,
  ]);
  const graph = buildSubgraph(
    data,
    [entity.id],
    isIocResult ? 10 : 18,
    undefined,
    isIocResult ? 1 : 2,
  );
  const reportIds = new Set(citations.map((citation) => citation.reportId));
  const reports = data.reports.filter((report) => reportIds.has(report.id));
  const chainEdges = relatedEdges.filter((edge) => edge.category === "chain");
  const confidence = Math.round(propNumber(entity, "confidence") * 100);
  const status = propString(entity, "status") || "positive";
  const verdict = iocVerdict(status);
  const actor = propString(entity, "actor");
  const subtype = propString(entity, "sub");
  const entityQueryType = detectQueryType(
    propString(entity, "entity_value") || entity.label,
  );
  const evidenceCount = citations.length;
  const sourceCount = new Set(citations.map((citation) => citation.reportId))
    .size;
  const relatedEntityMap = new Map(data.entities.map((item) => [item.id, item]));
  const relationHighlights = [...relatedEdges]
    .sort(
      (left, right) =>
        right.evidence_count - left.evidence_count ||
        right.confidence - left.confidence,
    )
    .slice(0, 3)
    .map((edge) => {
      const outbound = edge.source_entity_id === entity.id;
      const otherId = outbound
        ? edge.target_entity_id
        : edge.source_entity_id;
      return {
        edge,
        outbound,
        other: relatedEntityMap.get(otherId),
      };
    });
  const contextRelatedIds = new Set(
    contextPathMatches.flatMap(({ path }) =>
      path.contextLinks
        .filter((link) => link.entity_id !== entity.id)
        .map((link) => link.entity_id),
    ),
  );
  const aggregatedRelatedCount = new Set([
    ...relatedIds.filter((id) => id !== entity.id),
    ...contextRelatedIds,
  ]).size;
  const judgement = actor
    ? `${entity.label} 已在 ${sourceCount} 份公开来源中被记录，并通过 ${contextPathMatches.length} 个攻击活动关联到 ${actor}。当前判定来自可回溯的报告证据，不代表本地环境已经命中。`
    : `${entity.label} 已关联 ${sourceCount} 份公开来源、${evidenceCount} 条证据和 ${contextPathMatches.length} 个攻击活动。仍需结合本地告警上下文确认是否实际发生。`;
  const contextRelations = contextPathMatches.flatMap(
    ({ path, actionIds }) => {
      const nodeById = new Map(
        path.nodes.map((node) => [String(node.id), node]),
      );
      return path.contextLinks.flatMap((link) => {
        if (
          link.entity_id === entity.id ||
          !actionIds.has(link.action_node_id)
        ) {
          return [];
        }
        const other = relatedEntityMap.get(link.entity_id);
        if (!other) return [];
        return [
          {
            id: link.id,
            other,
            relation: actionRoleLabel(link.role),
            action: String(
              nodeById.get(link.action_node_id)?.label ?? "关联行为",
            ),
            confidence: link.confidence,
            evidenceCount: path.contextEvidence.filter(
              (item) => item.context_link_id === link.id,
            ).length,
          },
        ];
      });
    },
  );
  const rankedContextRelations = [...new Map(
    contextRelations.map((item) => [
      `${item.other.id}:${item.action}:${item.relation}`,
      item,
    ]),
  ).values()].sort((left, right) => {
    const typePriority = (item: (typeof contextRelations)[number]) =>
      ({
        "恶意软件/工具": 5,
        CVE: 4,
        "攻击组织": 3,
        "ATT&CK 技术": 2,
        "IOC/基础设施": 1,
      })[item.other.entity_type] ?? 0;
    return (
      typePriority(right) - typePriority(left) ||
      right.evidenceCount - left.evidenceCount ||
      left.other.label.localeCompare(right.other.label)
    );
  });
  const historyItems = [
    ...reports.map((report) => ({
      id: report.id,
      title: report.title,
      publisher: report.source,
      date: report.report_date,
      reliability: report.reliability,
      summary: report.assessment,
      url: report.external_url,
      evidenceCount: citations.filter(
        (citation) => citation.reportId === report.id,
      ).length,
      activity: "",
    })),
    ...contextPathMatches.flatMap(({ path }) => {
      const artifact = path.primary_artifact_id
        ? artifactById.get(path.primary_artifact_id)
        : undefined;
      if (!artifact) return [];
      return [
        {
          id: artifact.id,
          title: artifact.title,
          publisher: artifact.publisher,
          date: artifact.published_at,
          reliability:
            artifact.canonical_verification_state === "verified"
              ? "原始来源已核验"
              : "公开来源",
          summary: path.description,
          url: artifact.canonical_url,
          evidenceCount: citations.filter(
            (citation) => citation.reportId === artifact.id,
          ).length,
          activity: path.name,
        },
      ];
    }),
  ].filter(
    (item, index, items) =>
      items.findIndex(
        (candidate) =>
          candidate.id === item.id ||
          (candidate.title === item.title && candidate.url === item.url),
      ) === index,
  );

  if (isIocResult) {
    return (
      <main className="page-frame intel-page ioc-detail-page">
        <div className="page-toolbar">
          <button type="button" className="back-link" onClick={onBack}>
            <ArrowLeft size={16} /> {backLabel}
          </button>
          <div className="toolbar-actions">
            <button
              type="button"
              className="secondary-button"
              onClick={() => onOpenGraph(entity)}
            >
              <Network size={16} /> 打开完整图谱
            </button>
          </div>
        </div>

        <section className="ioc-identity">
          <div className={`ioc-verdict-mark is-${verdict.tone}`}>
            <ShieldAlert size={24} />
            <strong>{verdict.label}</strong>
          </div>
          <div className="ioc-identity-main">
            <div className="ioc-identity-kicker">
              <span>{entityQueryType}</span>
              <span>{entity.entity_type}</span>
            </div>
            <h1>{entity.label}</h1>
            <p>{entity.description || judgement}</p>
            <div className="ioc-tags">
              <StatusBadge status={status} />
              {subtype && <span>{subtype}</span>}
              {actor && <span>关联 {actor}</span>}
              {propString(entity, "event") && (
                <span>{propString(entity, "event")}</span>
              )}
            </div>
          </div>
          <dl className="ioc-score-summary">
            <div>
              <dt>情报置信度</dt>
              <dd>
                {confidence}
                <small>/100</small>
              </dd>
            </div>
            <div>
              <dt>公开来源</dt>
              <dd>
                {sourceCount}
                <small>份</small>
              </dd>
            </div>
            <div>
              <dt>攻击活动</dt>
              <dd>
                {contextPathMatches.length}
                <small>个</small>
              </dd>
            </div>
          </dl>
        </section>

        <div className="ioc-single-page">
          <section className="ioc-page-section ioc-overview-section">
            <header className="ioc-section-heading">
              <div>
                <h2>情报概览</h2>
                <p>先确认当前情报实体的公开情报角色，再决定是否进入本地告警核查。</p>
              </div>
              <span>{aggregatedRelatedCount} 个关联实体</span>
            </header>

            <div className="ioc-overview-grid">
              <article className="ioc-judgement">
                <header>
                  <div>
                    <span className="ioc-section-label">当前判定</span>
                    <h3>{verdict.label}</h3>
                  </div>
                  <span className={`ioc-verdict-text is-${verdict.tone}`}>
                    {confidence}% 置信度
                  </span>
                </header>
                <p>{judgement}</p>
                <div className="ioc-verdict-basis">
                  <span>{sourceCount} 份公开来源</span>
                  <span>{evidenceCount} 条证据锚点</span>
                  <span>{contextPathMatches.length} 个攻击活动</span>
                </div>
              </article>

              <dl className="ioc-fact-matrix">
                <div>
                  <dt>情报对象类型</dt>
                  <dd>{entityQueryType}</dd>
                </div>
                <div>
                  <dt>情报角色</dt>
                  <dd>{subtype || entity.entity_type}</dd>
                </div>
                <div>
                  <dt>关联组织</dt>
                  <dd>{actor || "暂未归因"}</dd>
                </div>
                <div>
                  <dt>首次发现</dt>
                  <dd>{formatDate(entity.first_seen)}</dd>
                </div>
                <div>
                  <dt>最后观察</dt>
                  <dd>{formatDate(entity.last_seen)}</dd>
                </div>
                <div>
                  <dt>规范标识</dt>
                  <dd>{entity.canonical_key}</dd>
                </div>
              </dl>
            </div>

            <div className="ioc-related-context">
              <div className="ioc-related-heading">
                <div>
                  <h3>同步骤关联情报</h3>
                  <p>仅显示与当前实体出现在同一攻击步骤中的工具、漏洞、组织与 IOC。</p>
                </div>
                <button type="button" onClick={() => onOpenGraph(entity)}>
                  查看完整关系 <ArrowRight size={14} />
                </button>
              </div>
              <div className="ioc-context-list">
                {rankedContextRelations.slice(0, 6).map((item) => (
                  <button
                    type="button"
                    key={item.id}
                    onClick={() => setSelectedEntity(item.other)}
                  >
                    <span className="ioc-relation-icon">
                      <Fingerprint size={16} />
                    </span>
                    <span>
                      <strong>{item.other.label}</strong>
                      <small>{item.other.entity_type}</small>
                    </span>
                    <span>
                      <strong>{item.relation}</strong>
                      <small>{item.action}</small>
                    </span>
                    <b>{Math.round(item.confidence * 100)}%</b>
                  </button>
                ))}
                {!rankedContextRelations.length &&
                  relationHighlights.map(({ edge, outbound, other }) => (
                    <button
                      type="button"
                      key={edge.id}
                      onClick={() => other && setSelectedEntity(other)}
                    >
                      <span className="ioc-relation-icon">
                        <Link2 size={16} />
                      </span>
                      <span>
                        <strong>{other?.label || "关联实体"}</strong>
                        <small>{other?.entity_type || "待分类"}</small>
                      </span>
                      <span>
                        <strong>{edge.relation_type}</strong>
                        <small>{outbound ? "当前实体指向" : "指向当前实体"}</small>
                      </span>
                      <b>{Math.round(edge.confidence * 100)}%</b>
                    </button>
                  ))}
                {!rankedContextRelations.length && !relationHighlights.length && (
                  <p className="ioc-inline-empty">
                    当前没有可验证的一跳关联，系统不会用弱相关实体填充结果。
                  </p>
                )}
              </div>
            </div>
          </section>

          <section className="ioc-page-section ioc-source-section">
            <header className="ioc-section-heading">
              <div>
                <h2>来源证据</h2>
                <p>每项判断都保留原文摘录和位置，可直接回到发布机构核验。</p>
              </div>
              <span>{citations.length} 条证据</span>
            </header>
            <div className="ioc-source-ledger">
              {citations.map((citation) => (
                <button
                  type="button"
                  key={citation.id}
                  onClick={() => setSource(citation)}
                >
                  <span className="ioc-source-icon">
                    <Quote size={16} />
                  </span>
                  <span className="ioc-source-copy">
                    <span>
                      <strong>{citation.publisher}</strong>
                      <small>{formatDate(citation.reportDate)}</small>
                    </span>
                    <b>{citation.title}</b>
                    <p>{citation.excerpt}</p>
                  </span>
                  <span className="ioc-source-location">
                    <strong>{citation.location || "原文位置已记录"}</strong>
                    <small>{Math.round(citation.confidence * 100)}% 可信度</small>
                  </span>
                  <ArrowRight size={15} />
                </button>
              ))}
              {!citations.length && (
                <div className="ioc-section-empty">
                  <Quote size={20} />
                  <div>
                    <strong>当前没有可定位的来源证据</strong>
                    <p>该实体可以继续作为查询线索，但不应据此直接升级处置。</p>
                  </div>
                </div>
              )}
            </div>
          </section>

          <section className="ioc-page-section ioc-history-section">
            <header className="ioc-section-heading">
              <div>
                <h2>历史报告</h2>
                <p>按文档查看实体出现时的完整攻击背景，避免脱离上下文解释单点指标。</p>
              </div>
              <span>{historyItems.length} 份报告</span>
            </header>
            <div className="ioc-report-ledger">
              {historyItems.map((item) => (
                <article key={item.id}>
                  <span className="ioc-report-date">
                    {formatDate(item.date)}
                  </span>
                  <span className="ioc-report-icon">
                    <FileText size={17} />
                  </span>
                  <div>
                    <h3>{item.title}</h3>
                    <p>{item.summary}</p>
                    <span>
                      {item.publisher}
                      <b>{item.reliability}</b>
                      {item.activity && <b>{item.activity}</b>}
                    </span>
                  </div>
                  <span className="ioc-report-count">
                    <strong>{item.evidenceCount}</strong>
                    <small>证据锚点</small>
                  </span>
                  {item.url && (
                    <a
                      href={item.url}
                      target="_blank"
                      rel="noreferrer"
                      aria-label={`打开报告 ${item.title}`}
                    >
                      <ExternalLink size={15} />
                    </a>
                  )}
                </article>
              ))}
              {!historyItems.length && (
                <div className="ioc-section-empty">
                  <FileText size={20} />
                  <div>
                    <strong>暂无独立历史报告</strong>
                    <p>当前 IOC 只有实体记录，没有足够的文档上下文。</p>
                  </div>
                </div>
              )}
            </div>
          </section>

          <section className="ioc-page-section ioc-chain-section">
            <header className="ioc-section-heading">
              <div>
                <h2>关联攻击链</h2>
                <p>默认只展示当前实体所在行为的前后步骤，完整路径进入攻击链研判查看。</p>
              </div>
              <span>{contextPathMatches.length} 个攻击活动</span>
            </header>
            <div className="ioc-chain-list">
              {contextPathMatches.map(
                ({ path, links, actionIds, localNodes, focusId }) => (
                  <article key={path.id}>
                    <header>
                      <div>
                        <span>
                          {String(path.metadata.actor ?? "未知组织")} ·{" "}
                          {path.victim_scope || "目标范围见报告"}
                        </span>
                        <h3>{path.name}</h3>
                        <p>{path.description}</p>
                      </div>
                      <button
                        type="button"
                        onClick={() =>
                          onOpenPath(historicalPathCandidate(path))
                        }
                      >
                        查看完整攻击路径 <ArrowRight size={14} />
                      </button>
                    </header>
                    <div className="ioc-local-path">
                      {localNodes.map((node, index) => (
                        <div key={String(node.id)} className="ioc-local-step-wrap">
                          <div
                            className={
                              String(node.id) === focusId
                                ? "ioc-local-step is-focus"
                                : "ioc-local-step"
                            }
                          >
                            <span>{String(node.phase ?? "攻击行为")}</span>
                            <strong>{String(node.label ?? "未命名行为")}</strong>
                            {actionIds.has(String(node.id)) && (
                              <small>
                                {links
                                  .filter(
                                    (link) =>
                                      link.action_node_id === String(node.id),
                                  )
                                  .map((link) => actionRoleLabel(link.role))
                                  .join("、")}
                                当前实体
                              </small>
                            )}
                          </div>
                          {index < localNodes.length - 1 && (
                            <ArrowRight size={17} />
                          )}
                        </div>
                      ))}
                    </div>
                    <footer>
                      <span>
                        <GitBranch size={14} />
                        主干 {path.projection?.mainline_action_refs.length ?? path.nodes.length} 步
                      </span>
                      <span>{path.edges.length} 条过程依赖</span>
                      <span>{Math.round(path.confidence * 100)}% 路径置信度</span>
                    </footer>
                  </article>
                ),
              )}
              {!contextPathMatches.length && chainEdges.length > 0 &&
                chainEdges.map((edge) => {
                  const sourceEntity = data.entities.find(
                    (item) => item.id === edge.source_entity_id,
                  );
                  const targetEntity = data.entities.find(
                    (item) => item.id === edge.target_entity_id,
                  );
                  return (
                    <div className="chain-relation-row" key={edge.id}>
                      <span>{sourceEntity?.label ?? edge.source_entity_id}</span>
                      <strong>{edge.relation_type}</strong>
                      <span>{targetEntity?.label ?? edge.target_entity_id}</span>
                    </div>
                  );
                })}
              {!contextPathMatches.length && !chainEdges.length && (
                <div className="ioc-section-empty">
                  <GitBranch size={20} />
                  <div>
                    <strong>暂无可解释的攻击路径位置</strong>
                    <p>该实体尚未连接到有证据支持的行为步骤，因此不展示推测链路。</p>
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>
        {source && (
          <SourceViewer
            citation={source}
            onClose={() => setSource(undefined)}
          />
        )}
      </main>
    );
  }

  return (
    <main className="page-frame intel-page">
      <div className="page-toolbar">
        <button type="button" className="back-link" onClick={onBack}>
          <ArrowLeft size={16} /> {backLabel}
        </button>
        <div className="toolbar-actions">
          <button type="button" className="secondary-button" onClick={() => onOpenGraph(entity)}>
            <Network size={16} /> 全屏图谱
          </button>
        </div>
      </div>

      <div className="intel-layout">
        <div className="intel-detail-column">
          <section className="intel-identity">
            <span className="identity-icon">
              <ShieldAlert size={25} />
            </span>
            <div className="identity-main">
              <span className="eyebrow">
                {result.queryType} · THREAT INTELLIGENCE
              </span>
              <h1>{entity.label}</h1>
              <p>{entity.description || "当前实体暂无补充描述。"}</p>
              <div className="identity-tags">
                <StatusBadge
                  status={propString(entity, "status") || "positive"}
                />
                <span>{entity.entity_type}</span>
                {propString(entity, "actor") && (
                  <span>{propString(entity, "actor")}</span>
                )}
                {propString(entity, "event") && (
                  <span>{propString(entity, "event")}</span>
                )}
              </div>
            </div>
            <div className="identity-score">
              <small>情报置信度</small>
              <strong>
                {Math.round(propNumber(entity, "confidence") * 100)}
              </strong>
              <span>/ 100</span>
            </div>
          </section>

          <section className="intel-main-panel">
          <div className="section-tabs" role="tablist" aria-label="情报详情">
            {[
              ["overview", "情报概览", aggregatedRelatedCount],
              ["evidence", "来源证据", citations.length],
              ["history", "历史报告", historyItems.length],
              ["chains", "关联攻击链", contextPathMatches.length + chainEdges.length],
            ].map(([id, label, count]) => (
              <button
                type="button"
                role="tab"
                aria-selected={tab === id}
                className={tab === id ? "active" : ""}
                key={id}
                onClick={() => setTab(id as Tab)}
              >
                {label} <span>{count}</span>
              </button>
            ))}
          </div>

          {tab === "overview" && (
            <div className="intel-tab-content">
              <div className="fact-grid">
                <article>
                  <CalendarDays size={17} />
                  <span>首次发现</span>
                  <strong>{formatDate(entity.first_seen)}</strong>
                </article>
                <article>
                  <CalendarDays size={17} />
                  <span>最后观察</span>
                  <strong>{formatDate(entity.last_seen)}</strong>
                </article>
                <article>
                  <Database size={17} />
                  <span>来源数量</span>
                  <strong>{entity.source_count}</strong>
                </article>
                <article>
                  <Link2 size={17} />
                  <span>关联实体</span>
                  <strong>{aggregatedRelatedCount}</strong>
                </article>
              </div>
              <div className="entity-table">
                <header>
                  <div>
                    <span className="eyebrow">RELATED ENTITIES</span>
                    <h2>相关情报实体</h2>
                  </div>
                  <span>
                    优先展示 {Math.min(10, aggregatedRelatedCount)} / {aggregatedRelatedCount} 个
                  </span>
                </header>
                {relatedEdges.slice(0, 10).map((edge) => {
                  const otherId =
                    edge.source_entity_id === entity.id
                      ? edge.target_entity_id
                      : edge.source_entity_id;
                  const other = data.entities.find((item) => item.id === otherId);
                  if (!other) return null;
                  return (
                    <button
                      type="button"
                      key={edge.id}
                      onClick={() => setSelectedEntity(other)}
                    >
                      <span className="relation-direction">
                        {edge.source_entity_id === entity.id ? "OUT" : "IN"}
                      </span>
                      <span>
                        <strong>{other.label}</strong>
                        <small>{other.entity_type}</small>
                      </span>
                      <span className="relation-label">{edge.relation_type}</span>
                      <Confidence value={edge.confidence} />
                    </button>
                  );
                })}
                {!relatedEdges.length &&
                  rankedContextRelations.slice(0, 10).map((item) => (
                    <button
                      type="button"
                      key={item.id}
                      onClick={() => setSelectedEntity(item.other)}
                    >
                      <span className="relation-direction">CTX</span>
                      <span>
                        <strong>{item.other.label}</strong>
                        <small>{item.other.entity_type}</small>
                      </span>
                      <span className="relation-label">
                        {item.action} · {item.relation}
                      </span>
                      <Confidence value={item.confidence} />
                    </button>
                  ))}
              </div>
            </div>
          )}

          {tab === "evidence" && (
            <div className="intel-tab-content source-list">
              {citations.length ? (
                citations.map((citation) => (
                  <SourceCard
                    key={citation.id}
                    citation={citation}
                    active={source?.id === citation.id}
                    onOpen={setSource}
                  />
                ))
              ) : (
                <EmptyState
                  title="当前关系暂无来源摘录"
                  description="实体仍可来自已入库报告，但当前直接关系没有可展示的证据记录。"
                />
              )}
            </div>
          )}

          {tab === "history" && (
            <div className="intel-tab-content report-cards">
              {historyItems.map((report) => (
                <article key={report.id}>
                  <FileText size={18} />
                  <div>
                    <h3>{report.title}</h3>
                    <p>{report.summary}</p>
                    <span>
                      {report.publisher} · {formatDate(report.date)} ·{" "}
                      {report.reliability}
                    </span>
                  </div>
                  {report.url && (
                    <a href={report.url} target="_blank" rel="noreferrer">
                      <ExternalLink size={15} />
                    </a>
                  )}
                </article>
              ))}
            </div>
          )}

          {tab === "chains" && (
            <div className="intel-tab-content chain-context">
              <header>
                <div>
                  <span className="eyebrow">CHAIN CONTEXT</span>
                  <h2>该实体在攻击链中的位置</h2>
                </div>
              </header>
              {contextPathMatches.length ? (
                <div className="ioc-chain-list">
                  {contextPathMatches.map(({ path, localNodes, focusId }) => (
                    <article key={path.id}>
                      <header>
                        <div>
                          <span>
                            {String(path.metadata.actor ?? "未知组织")} ·{" "}
                            {path.victim_scope || "目标范围见报告"}
                          </span>
                          <h3>{path.name}</h3>
                          <p>{path.description}</p>
                        </div>
                        <button
                          type="button"
                          onClick={() => onOpenPath(historicalPathCandidate(path))}
                        >
                          查看完整攻击路径 <ArrowRight size={14} />
                        </button>
                      </header>
                      <div className="ioc-local-path">
                        {localNodes.map((node, index) => (
                          <div key={String(node.id)} className="ioc-local-step-wrap">
                            <div
                              className={
                                String(node.id) === focusId
                                  ? "ioc-local-step is-focus"
                                  : "ioc-local-step"
                              }
                            >
                              <span>{String(node.phase ?? "攻击行为")}</span>
                              <strong>{String(node.label ?? "未命名行为")}</strong>
                            </div>
                            {index < localNodes.length - 1 && (
                              <ArrowRight size={17} />
                            )}
                          </div>
                        ))}
                      </div>
                      <footer>
                        <span>
                          <GitBranch size={14} />
                          主干 {path.projection?.mainline_action_refs.length ?? path.nodes.length} 步
                        </span>
                        <span>{path.edges.length} 条过程依赖</span>
                        <span>{Math.round(path.confidence * 100)}% 路径置信度</span>
                      </footer>
                    </article>
                  ))}
                </div>
              ) : chainEdges.length ? (
                chainEdges.map((edge) => {
                  const sourceEntity = data.entities.find(
                    (item) => item.id === edge.source_entity_id,
                  );
                  const targetEntity = data.entities.find(
                    (item) => item.id === edge.target_entity_id,
                  );
                  return (
                    <div className="chain-relation-row" key={edge.id}>
                      <span>{sourceEntity?.label ?? edge.source_entity_id}</span>
                      <strong>{edge.relation_type}</strong>
                      <span>{targetEntity?.label ?? edge.target_entity_id}</span>
                    </div>
                  );
                })
              ) : (
                <EmptyState
                  title="暂无直接攻击链关系"
                  description="该实体仍可作为案件输入，但当前快照没有记录直接时序关系。"
                />
              )}
            </div>
          )}
          </section>
        </div>

        <aside className="intel-graph-panel">
          <header>
            <div>
              <span className="eyebrow">RELATION GRAPH</span>
              <h2>关系图谱</h2>
            </div>
            <button type="button" className="icon-link" onClick={() => onOpenGraph(entity)}>
              <ExternalLink size={15} />
            </button>
          </header>
          <NetworkGraph
            compact
            nodes={graph.nodes}
            edges={graph.edges}
            rootId={entity.id}
            selectedId={entity.id}
            onSelect={(node) => node.entity && setSelectedEntity(node.entity)}
          />
          <div className="graph-panel-note">
            点击关联节点可切换当前实体；图谱只展示两跳内真实关系。
          </div>
        </aside>
      </div>
      {source && <SourceViewer citation={source} onClose={() => setSource(undefined)} />}
    </main>
  );
}
