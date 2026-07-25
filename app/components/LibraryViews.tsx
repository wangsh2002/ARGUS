"use client";

import {
  ArrowLeft,
  ArrowRight,
  BriefcaseBusiness,
  ExternalLink,
  FileText,
  GitBranch,
  Network,
  Search,
  ShieldCheck,
  Target,
  Trash2,
  Users,
} from "lucide-react";
import { useState } from "react";
import {
  actorGraph,
  formatDate,
  propString,
} from "../argus-domain";
import type {
  Actor,
  GraphEdge,
  GraphNode,
  InvestigationCase,
  Report,
  Snapshot,
} from "../types";
import { NetworkGraph } from "../NetworkGraph";
import { EmptyState, StatusBadge } from "./Primitives";

export function CasesView({
  cases,
  onOpen,
  onDelete,
  onCreate,
}: {
  cases: InvestigationCase[];
  onOpen: (investigation: InvestigationCase) => void;
  onDelete: (caseId: string) => void;
  onCreate: () => void;
}) {
  return (
    <main className="page-frame library-page">
      <section className="page-heading">
        <div>
          <span className="eyebrow">LOCAL INVESTIGATIONS</span>
          <h1>调查案件</h1>
          <p>保存攻击链匹配结果、来源证据与报告摘要。</p>
        </div>
        <button type="button" className="primary-button" onClick={onCreate}>
          新建调查 <ArrowRight size={16} />
        </button>
      </section>
      <div className="library-notice">
        <BriefcaseBusiness size={17} />
        当前案件保存在本机浏览器中，属于 Demo 草稿，不代表正式多人协作记录。
      </div>
      {cases.length ? (
        <div className="case-library-grid">
          {cases.map((item) => (
            <article key={item.id}>
              <header>
                <span className="case-icon">
                  <GitBranch size={19} />
                </span>
                <StatusBadge status="matched">匹配结果</StatusBadge>
                <button
                  type="button"
                  className="delete-case"
                  aria-label={`删除案件 ${item.title}`}
                  onClick={() => onDelete(item.id)}
                >
                  <Trash2 size={15} />
                </button>
              </header>
              <span className="eyebrow">{item.id}</span>
              <h2>{item.title}</h2>
              <p>{item.summary}</p>
              <dl>
                <div>
                  <dt>攻击步骤</dt>
                  <dd>{item.steps.length}</dd>
                </div>
                <div>
                  <dt>证据覆盖</dt>
                  <dd>{item.steps.filter((step) => step.evidenceCount > 0).length}/{item.steps.length}</dd>
                </div>
                <div>
                  <dt>候选组织</dt>
                  <dd>{item.actor ?? "未确认"}</dd>
                </div>
              </dl>
              <footer>
                <span>更新于 {formatDate(item.updatedAt)}</span>
                <button type="button" onClick={() => onOpen(item)}>
                  查看匹配 <ArrowRight size={14} />
                </button>
              </footer>
            </article>
          ))}
        </div>
      ) : (
        <EmptyState
          title="还没有调查案件"
          description="从历史报告、攻击链输入或综合查询创建第一个本机草稿。"
        />
      )}
    </main>
  );
}

export function ReportsView({
  data,
  onCreateCase,
}: {
  data: Snapshot;
  onCreateCase: (reportId: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState(data.reports[0]?.id);
  const reports = data.reports.filter((report) =>
    `${report.title} ${report.source} ${report.assessment}`
      .toLocaleLowerCase()
      .includes(query.trim().toLocaleLowerCase()),
  );
  const selected = data.reports.find((report) => report.id === selectedId) ?? reports[0];
  return (
    <main className="page-frame reports-page">
      <section className="page-heading compact-heading">
        <div>
          <span className="eyebrow">TRACEABLE SOURCE LIBRARY</span>
          <h1>历史报告</h1>
          <p>浏览已归档来源，并从真实报告开始构建攻击链研判。</p>
        </div>
        <label className="library-search">
          <Search size={16} />
          <input
            aria-label="搜索历史报告"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="搜索标题、来源或摘要"
          />
        </label>
      </section>
      <div className="reports-layout">
        <section className="report-library-list">
          <header>
            <span>{reports.length} 份报告</span>
            <small>按报告日期排序</small>
          </header>
          {reports.map((report) => (
            <button
              type="button"
              key={report.id}
              className={selected?.id === report.id ? "active" : ""}
              onClick={() => setSelectedId(report.id)}
            >
              <span className="report-list-icon">
                <FileText size={17} />
              </span>
              <span>
                <strong>{report.title}</strong>
                <small>
                  {report.source} · {formatDate(report.report_date)}
                </small>
              </span>
              {report.external_url && <span className="real-source-dot" title="具有外部原文链接" />}
            </button>
          ))}
        </section>
        <ReportDetail report={selected} onCreateCase={onCreateCase} />
      </div>
    </main>
  );
}

function ReportDetail({
  report,
  onCreateCase,
}: {
  report?: Report;
  onCreateCase: (reportId: string) => void;
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
          <h2>{report.title}</h2>
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
        <p>{report.extracted_text.slice(0, 900) || "未保存可展示的报告正文。"}</p>
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
        {report.external_url ? (
          <a href={report.external_url} target="_blank" rel="noreferrer">
            查看原始来源 <ExternalLink size={14} />
          </a>
        ) : (
          <span className="muted">当前归档没有外部原文链接</span>
        )}
        <button type="button" className="primary-button" onClick={() => onCreateCase(report.id)}>
          从此报告创建攻击链 <ArrowRight size={15} />
        </button>
      </footer>
    </section>
  );
}

export function ActorsView({
  data,
  onOpenGraph,
}: {
  data: Snapshot;
  onOpenGraph: (actor: Actor) => void;
}) {
  const [selectedId, setSelectedId] = useState(data.actors[0]?.id);
  const selected = data.actors.find((actor) => actor.id === selectedId) ?? data.actors[0];
  const graph = selected ? actorGraph(data, selected) : { nodes: [], edges: [] };
  const relatedReports = selected
    ? data.reports.filter(
        (report) =>
          selected.source_refs.includes(report.source_ref) ||
          report.extracted_text.includes(selected.label),
      )
    : [];
  return (
    <main className="page-frame actors-page">
      <section className="page-heading compact-heading">
        <div>
          <span className="eyebrow">THREAT ACTOR ARCHIVE</span>
          <h1>攻击组织总揽</h1>
          <p>组织画像作为攻击链与历史证据的索引，不代表独立归因结论。</p>
        </div>
        <span className="honesty-pill">
          <Users size={15} /> {data.actors.length} 个已归并档案
        </span>
      </section>
      <div className="actors-layout">
        <section className="actor-list">
          {data.actors.map((actor) => (
            <button
              type="button"
              key={actor.id}
              className={selected?.id === actor.id ? "active" : ""}
              onClick={() => setSelectedId(actor.id)}
            >
              <span className="actor-monogram">{actor.label.slice(0, 2)}</span>
              <span>
                <strong>{actor.label}</strong>
                <small>{actor.origin_label}</small>
              </span>
              <StatusBadge status={actor.profile_status === "verified" ? "positive" : "partial"} />
            </button>
          ))}
        </section>
        {selected && (
          <section className="actor-profile">
            <header>
              <span className="actor-hero-icon"><Target size={22} /></span>
              <div>
                <span className="eyebrow">ACTOR PROFILE</span>
                <h2>{selected.label}</h2>
                <p>{selected.origin_label}</p>
              </div>
              <button type="button" className="secondary-button" onClick={() => onOpenGraph(selected)}>
                全景图谱 <Network size={15} />
              </button>
            </header>
            <p className="actor-description">{selected.description}</p>
            <div className="actor-facts">
              <article>
                <span>公开归因</span>
                <p>{selected.public_attribution}</p>
              </article>
              <article>
                <span>目标行业</span>
                <p>{selected.target_sectors.join("、") || "未记录"}</p>
              </article>
              <article>
                <span>主要动机</span>
                <p>{selected.motivations.join("、") || "未记录"}</p>
              </article>
              <article>
                <span>来源质量</span>
                <strong>{Math.round(selected.source_grade * 100)}%</strong>
              </article>
            </div>
            <div className="actor-profile-bottom">
              <div className="actor-graph-preview">
                <NetworkGraph
                  compact
                  nodes={graph.nodes}
                  edges={graph.edges}
                  rootId={selected.id}
                />
              </div>
              <div className="actor-report-list">
                <span className="eyebrow">RELATED SOURCES</span>
                {relatedReports.slice(0, 4).map((report) => (
                  <article key={report.id}>
                    <FileText size={15} />
                    <span>
                      <strong>{report.title}</strong>
                      <small>{formatDate(report.report_date)}</small>
                    </span>
                  </article>
                ))}
              </div>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}

export function FullGraphView({
  title,
  subtitle,
  nodes,
  edges,
  rootId,
  onBack,
}: {
  title: string;
  subtitle: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  rootId?: string;
  onBack: () => void;
}) {
  const [selected, setSelected] = useState<GraphNode>();
  return (
    <main className="full-graph-view">
      <header className="full-graph-toolbar">
        <button type="button" onClick={onBack}>
          <ArrowLeft size={16} /> 返回
        </button>
        <div>
          <span className="graph-emblem"><Network size={18} /></span>
          <span>
            <strong>{title}</strong>
            <small>{subtitle}</small>
          </span>
        </div>
        <span className="honesty-pill">
          <ShieldCheck size={14} /> 真实图谱快照
        </span>
      </header>
      <div className="full-graph-layout">
        <aside>
          <span className="eyebrow">GRAPH OVERVIEW</span>
          <dl>
            <div><dt>节点</dt><dd>{nodes.length}</dd></div>
            <div><dt>关系</dt><dd>{edges.length}</dd></div>
            <div><dt>高置信</dt><dd>{nodes.filter((node) => node.status === "hot").length}</dd></div>
          </dl>
          <div className="graph-type-list">
            {[...new Set(nodes.map((node) => node.type))].map((type) => (
              <div key={type}>
                <span>{type}</span>
                <strong>{nodes.filter((node) => node.type === type).length}</strong>
              </div>
            ))}
          </div>
        </aside>
        <section className="full-graph-canvas">
          <NetworkGraph
            nodes={nodes}
            edges={edges}
            rootId={rootId}
            selectedId={selected?.id}
            onSelect={setSelected}
          />
        </section>
        <aside className="graph-inspector">
          <span className="eyebrow">NODE INSPECTOR</span>
          {selected ? (
            <>
              <span className="selected-node-icon"><Target size={19} /></span>
              <h2>{selected.label}</h2>
              <StatusBadge status={selected.status ?? "positive"} />
              <p>{selected.entity?.description || "当前节点没有补充描述。"}</p>
              <dl>
                <div><dt>类型</dt><dd>{selected.type}</dd></div>
                <div><dt>置信度</dt><dd>{Math.round((selected.confidence ?? 0) * 100)}%</dd></div>
                <div><dt>所属事件</dt><dd>{selected.entity ? propString(selected.entity, "event") || "未记录" : "草稿节点"}</dd></div>
              </dl>
            </>
          ) : (
            <p className="muted">点击图谱节点查看真实属性与关系。</p>
          )}
        </aside>
      </div>
    </main>
  );
}
