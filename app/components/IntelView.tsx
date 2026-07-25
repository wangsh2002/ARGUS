"use client";

import {
  ArrowLeft,
  ArrowRight,
  CalendarDays,
  Database,
  ExternalLink,
  FileText,
  Link2,
  Network,
  ShieldAlert,
} from "lucide-react";
import { useMemo, useState } from "react";
import {
  buildSubgraph,
  citationsForEntity,
  formatDate,
  propNumber,
  propString,
  searchSnapshot,
} from "../argus-domain";
import type { Entity, Snapshot, SourceCitation } from "../types";
import { NetworkGraph } from "../NetworkGraph";
import {
  Confidence,
  EmptyState,
  SourceCard,
  SourceViewer,
  StatusBadge,
} from "./Primitives";

type Tab = "overview" | "evidence" | "history" | "chains";

export function IntelView({
  data,
  query,
  onBack,
  onCreateCase,
  onOpenGraph,
}: {
  data: Snapshot;
  query: string;
  onBack: () => void;
  onCreateCase: (query: string) => void;
  onOpenGraph: (entity: Entity) => void;
}) {
  const result = useMemo(() => searchSnapshot(data, query), [data, query]);
  const [selectedEntity, setSelectedEntity] = useState<Entity | undefined>(
    result.entities[0]?.entity,
  );
  const [tab, setTab] = useState<Tab>("overview");
  const [source, setSource] = useState<SourceCitation>();
  const entity = selectedEntity ?? result.entities[0]?.entity;

  const relatedEdges = entity
    ? data.relationships.filter(
        (edge) =>
          edge.source_entity_id === entity.id || edge.target_entity_id === entity.id,
      )
    : [];
  const relatedIds = entity
    ? relatedEdges.flatMap((edge) => [edge.source_entity_id, edge.target_entity_id])
    : [];
  const graph = entity
    ? buildSubgraph(data, [entity.id], 18)
    : { nodes: [], edges: [] };
  const citations = entity ? citationsForEntity(data, entity.id) : [];
  const reportIds = new Set(citations.map((citation) => citation.reportId));
  const reports = data.reports.filter((report) => reportIds.has(report.id));
  const chainEdges = relatedEdges.filter((edge) => edge.category === "chain");

  if (!entity) {
    return (
      <main className="page-frame">
        <button type="button" className="back-link" onClick={onBack}>
          <ArrowLeft size={16} /> 返回查询
        </button>
        <EmptyState
          title="数据库中没有直接匹配"
          description="ARGUS 不会为未入库的指标生成模拟情报。你可以调整查询，或进入攻击链模式创建待确认草稿。"
        />
      </main>
    );
  }

  return (
    <main className="page-frame intel-page">
      <div className="page-toolbar">
        <button type="button" className="back-link" onClick={onBack}>
          <ArrowLeft size={16} /> 综合查询
        </button>
        <div className="toolbar-actions">
          <button type="button" className="secondary-button" onClick={() => onOpenGraph(entity)}>
            <Network size={16} /> 全屏图谱
          </button>
          <button type="button" className="primary-button" onClick={() => onCreateCase(query)}>
            创建调查 <ArrowRight size={16} />
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
              ["overview", "情报概览", relatedEdges.length],
              ["evidence", "来源证据", citations.length],
              ["history", "历史报告", reports.length],
              ["chains", "关联攻击链", chainEdges.length],
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
                  <span>直接关系</span>
                  <strong>{relatedEdges.length}</strong>
                </article>
              </div>
              <div className="entity-table">
                <header>
                  <div>
                    <span className="eyebrow">RELATED ENTITIES</span>
                    <h2>相关情报实体</h2>
                  </div>
                  <span>{new Set(relatedIds).size - 1} 个节点</span>
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
              {reports.map((report) => (
                <article key={report.id}>
                  <FileText size={18} />
                  <div>
                    <h3>{report.title}</h3>
                    <p>{report.assessment}</p>
                    <span>
                      {report.source} · {formatDate(report.report_date)} ·{" "}
                      {report.reliability}
                    </span>
                  </div>
                  {report.external_url && (
                    <a href={report.external_url} target="_blank" rel="noreferrer">
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
                <button type="button" className="text-button" onClick={() => onCreateCase(entity.label)}>
                  进入攻击链研判 <ArrowRight size={14} />
                </button>
              </header>
              {chainEdges.length ? (
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
