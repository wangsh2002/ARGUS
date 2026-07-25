"use client";

import {
  ArrowDownToLine,
  ArrowLeft,
  Bot,
  Check,
  Clock3,
  Database,
  ExternalLink,
  FileJson,
  FileText,
  GitBranch,
  Printer,
  Save,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  actorForCase,
  adviceForCase,
  caseGraph,
  citationsForCase,
  historicalFindings,
} from "../argus-domain";
import { NetworkGraph } from "../NetworkGraph";
import {
  buildInvestigationExport,
  downloadJson,
  downloadMarkdown,
  printInvestigation,
} from "../report-export";
import type {
  ChainStep,
  InvestigationCase,
  Snapshot,
  SourceCitation,
} from "../types";
import {
  Confidence,
  EmptyState,
  SourceCard,
  SourceViewer,
  StatusBadge,
} from "./Primitives";

function stepOriginLabel(step: ChainStep) {
  return {
    database: "情报库匹配",
    log: "日志内容匹配",
    manual: "输入顺序匹配",
    gpt: "GPT 候选建议",
  }[step.origin];
}

function sourceKindLabel(investigation: InvestigationCase) {
  return {
    report: "报告匹配",
    query: "查询匹配",
    log: "日志匹配",
    manual: "人工线索",
    gpt: "GPT 辅助",
  }[investigation.sourceKind];
}

export function ChainWorkspace({
  data,
  investigation,
  onSave,
  onBack,
  onOpenGraph,
  onOpenGpt,
}: {
  data: Snapshot;
  investigation: InvestigationCase;
  onSave: () => void;
  onBack: () => void;
  onOpenGraph: () => void;
  onOpenGpt: () => void;
}) {
  const [selectedId, setSelectedId] = useState(investigation.steps[0]?.id);
  const [source, setSource] = useState<SourceCitation>();
  const [savedNotice, setSavedNotice] = useState(false);
  const graph = useMemo(
    () => caseGraph(data, investigation),
    [data, investigation],
  );
  const citations = useMemo(
    () => citationsForCase(data, investigation),
    [data, investigation],
  );
  const findings = useMemo(
    () => historicalFindings(data, investigation, citations),
    [data, investigation, citations],
  );
  const advice = useMemo(
    () => adviceForCase(data, investigation),
    [data, investigation],
  );
  const actor = actorForCase(data, investigation);
  const selected =
    investigation.steps.find((step) => step.id === selectedId) ??
    investigation.steps[0];
  const selectedIndex = selected
    ? investigation.steps.findIndex((step) => step.id === selected.id)
    : -1;
  const selectedCitationIds = new Set(
    investigation.links
      .filter(
        (link) =>
          link.source === selected?.id || link.target === selected?.id,
      )
      .map((link) => link.relationshipId)
      .filter(Boolean),
  );
  const selectedSources = citations.filter(
    (citation) =>
      selectedCitationIds.size === 0 ||
      data.evidence.some(
        (evidence) =>
          evidence.id === citation.id &&
          selectedCitationIds.has(evidence.relationship_id),
      ),
  );
  const exportBundle = buildInvestigationExport(
    investigation,
    findings,
    advice,
    citations,
  );
  const coveredSteps = investigation.steps.filter(
    (step) => step.evidenceCount > 0,
  ).length;
  const phases = new Set(investigation.steps.map((step) => step.phase)).size;
  const averageConfidence = investigation.steps.length
    ? investigation.steps.reduce((sum, step) => sum + step.confidence, 0) /
      investigation.steps.length
    : 0;

  useEffect(() => {
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
  }, [investigation.id]);

  const save = () => {
    onSave();
    setSavedNotice(true);
    window.setTimeout(() => setSavedNotice(false), 1800);
  };

  return (
    <main className="chain-workspace chain-workspace-readonly">
      <div className="workspace-toolbar">
        <div className="workspace-case-heading">
          <button
            type="button"
            className="icon-button"
            aria-label="返回"
            onClick={onBack}
          >
            <ArrowLeft size={17} />
          </button>
          <div>
            <span>
              {sourceKindLabel(investigation)} · {investigation.id}
            </span>
            <h1>{investigation.title}</h1>
            <p title={investigation.sourceLabel}>{investigation.sourceLabel}</p>
          </div>
          <StatusBadge status="matched">匹配结果</StatusBadge>
        </div>
        <div className="workspace-actions">
          {savedNotice && (
            <span className="save-notice">
              <Check size={14} />
              已保存在本机
            </span>
          )}
          <button
            type="button"
            className="secondary-button"
            onClick={onOpenGpt}
          >
            <Bot size={15} /> GPT 辅助
          </button>
          <button type="button" className="secondary-button" onClick={save}>
            <Save size={15} /> 保存匹配
          </button>
          <div className="export-actions">
            <button
              type="button"
              aria-label="打印或导出 PDF"
              onClick={printInvestigation}
            >
              <Printer size={15} />
            </button>
            <button
              type="button"
              aria-label="导出 Markdown"
              onClick={() => downloadMarkdown(exportBundle)}
            >
              <ArrowDownToLine size={15} />
              MD
            </button>
            <button
              type="button"
              aria-label="导出 JSON"
              onClick={() => downloadJson(exportBundle)}
            >
              <FileJson size={15} />
              JSON
            </button>
          </div>
        </div>
      </div>

      <section className="match-summary" aria-label="攻击链匹配概览">
        <div className="match-summary-copy">
          <div className="match-summary-icon">
            <GitBranch size={22} />
          </div>
          <div>
            <span className="eyebrow">CHAIN MATCH</span>
            <h2>已匹配到一条可追溯攻击路径</h2>
            <p>{investigation.summary}</p>
          </div>
        </div>
        <dl className="match-metrics">
          <div>
            <dt>真实节点</dt>
            <dd>{investigation.steps.length}</dd>
          </div>
          <div>
            <dt>证据覆盖</dt>
            <dd>
              {coveredSteps}/{investigation.steps.length}
            </dd>
          </div>
          <div>
            <dt>阶段跨度</dt>
            <dd>{phases}</dd>
          </div>
          <div>
            <dt>平均置信度</dt>
            <dd>{Math.round(averageConfidence * 100)}%</dd>
          </div>
        </dl>
        <p className="match-boundary">
          当前版本用于匹配查询和证据阅读，不在此页面修改情报事实或攻击链顺序。
        </p>
      </section>

      <section className="path-panel">
        <header className="section-heading">
          <div>
            <span className="eyebrow">MATCHED ATTACK PATH</span>
            <h2>完整攻击路径</h2>
            <p>真实节点名称与输入时序为主，ATT&amp;CK 仅补充阶段定义。</p>
          </div>
          <div className="path-legend" aria-label="节点状态说明">
            <span>
              <i className="legend-matched" />
              情报匹配
            </span>
            <span>
              <i className="legend-candidate" />
              待补证据
            </span>
          </div>
        </header>
        {investigation.steps.length ? (
          <ol
            className="path-overview"
            aria-label="攻击链步骤"
            style={{
              gridTemplateColumns: `repeat(${investigation.steps.length}, minmax(108px, 1fr))`,
            }}
          >
            {investigation.steps.map((step, index) => (
              <li
                key={step.id}
                className={`path-step ${
                  step.reviewStatus === "excluded" ? "is-excluded" : ""
                }`}
              >
                {index > 0 && (
                  <span className="path-relation" title={step.relation}>
                    {step.relation}
                  </span>
                )}
                <button
                  type="button"
                  aria-label={`攻击链节点：${step.label}`}
                  className={selected?.id === step.id ? "is-selected" : ""}
                  onClick={() => setSelectedId(step.id)}
                >
                  <span className="path-node-number">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <strong>{step.label}</strong>
                  <span className="path-node-phase">{step.phase}</span>
                  <small>
                    {step.evidenceCount
                      ? `${step.evidenceCount} 份证据`
                      : "暂无直接证据"}
                  </small>
                </button>
              </li>
            ))}
          </ol>
        ) : (
          <EmptyState
            title="未匹配到攻击链节点"
            description="请返回查询页补充可识别的时序线索。"
          />
        )}
      </section>

      <div className="evidence-graph-grid">
        <section className="node-evidence-panel" aria-label="当前节点匹配依据">
          <header className="section-heading compact">
            <div>
              <span className="eyebrow">
                NODE {Math.max(selectedIndex + 1, 0)} /{" "}
                {investigation.steps.length}
              </span>
              <h2>当前节点匹配依据</h2>
            </div>
            {selected && <StatusBadge status={selected.reviewStatus} />}
          </header>
          {selected ? (
            <div className="node-evidence-body">
              <div className="node-evidence-title">
                <span className="match-source-icon">
                  <Database size={17} />
                </span>
                <div>
                  <span>{stepOriginLabel(selected)}</span>
                  <h3>{selected.label}</h3>
                </div>
              </div>
              <p className="node-description">
                {selected.description ||
                  "该节点根据当前查询内容与已入库威胁情报进行匹配。"}
              </p>
              <div className="node-provenance">
                <span>{selected.type}</span>
                <span>{selected.phase}</span>
                {selected.attackId && <span>{selected.attackId}</span>}
              </div>
              <div className="node-confidence-row">
                <span>匹配置信度</span>
                <Confidence value={selected.confidence} />
              </div>
              {selectedSources[0] ? (
                <button
                  type="button"
                  className="selected-source"
                  onClick={() => setSource(selectedSources[0])}
                >
                  <FileText size={16} />
                  <span>
                    <strong>{selectedSources[0].title}</strong>
                    <small>
                      {selectedSources[0].location || "查看来源证据"}
                    </small>
                  </span>
                  <ExternalLink size={14} />
                </button>
              ) : (
                <div className="evidence-gap">
                  <TriangleAlert size={16} />
                  <span>
                    当前节点暂无可点击的直接关系摘录，仅作为输入时序中的匹配候选展示。
                  </span>
                </div>
              )}
            </div>
          ) : (
            <EmptyState
              title="请选择路径节点"
              description="点击上方真实节点名称即可查看匹配依据。"
            />
          )}
        </section>

        <section className="supporting-graph" aria-label="攻击链关系图谱">
          <header className="section-heading compact">
            <div>
              <span className="eyebrow">ALWAYS VISIBLE</span>
              <h2>攻击链关系图谱</h2>
              <p>图谱用于补充查看节点关系，不替代上方完整路径。</p>
            </div>
            <button
              type="button"
              className="secondary-button"
              onClick={onOpenGraph}
            >
              <ExternalLink size={14} /> 全屏查看
            </button>
          </header>
          <NetworkGraph
            chainMode
            nodes={graph.nodes}
            edges={graph.edges}
            rootId={investigation.steps[0]?.id}
            selectedId={selected?.id}
            onSelect={(node) => setSelectedId(node.id)}
          />
        </section>
      </div>

      <nav className="analysis-index" aria-label="结果目录">
        <span>结果目录</span>
        <a href="#history-summary">历史总结</a>
        <a href="#response-advice">处置建议</a>
        <a href="#attribution-assist">归因辅助</a>
        <a href="#all-sources">全部来源</a>
      </nav>

      <div className="analysis-stack">
        <section
          id="history-summary"
          className="analysis-section"
          aria-labelledby="history-title"
        >
          <header className="section-heading">
            <div>
              <span className="eyebrow">HISTORICAL SYNTHESIS</span>
              <h2 id="history-title">历史总结</h2>
              <p>按攻击阶段合并已入库报告中的一致事实与差异。</p>
            </div>
            <span className="section-count">{findings.length} 条观察</span>
          </header>
          <div className="analysis-pane history-pane">
            <div className="history-findings">
              {findings.length ? (
                findings.map((finding) => (
                  <article
                    key={finding.id}
                    className={`finding-${finding.tone}`}
                  >
                    <div className="finding-marker">
                      {finding.tone === "difference" ? (
                        <TriangleAlert size={16} />
                      ) : (
                        <Clock3 size={16} />
                      )}
                    </div>
                    <div>
                      <span>{finding.phase}</span>
                      <h3>{finding.title}</h3>
                      <p>{finding.summary}</p>
                      <div className="inline-citations">
                        {finding.citationIds.map((citationId, index) => {
                          const citation = citations.find(
                            (item) => item.id === citationId,
                          );
                          if (!citation) return null;
                          return (
                            <button
                              type="button"
                              key={citationId}
                              onClick={() => setSource(citation)}
                            >
                              [{index + 1}] {citation.publisher}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  </article>
                ))
              ) : (
                <EmptyState
                  title="暂无可综合的历史发现"
                  description="当前查询尚未关联到可追溯的历史报告结论。"
                />
              )}
            </div>
            <aside className="history-overview">
              <span className="eyebrow">SOURCE COVERAGE</span>
              <strong>{citations.length}</strong>
              <p>条可点击来源证据支持当前攻击链</p>
              <div>
                <span>主链覆盖</span>
                <strong>
                  {coveredSteps}/{investigation.steps.length}
                </strong>
              </div>
              <small>
                摘要按攻击阶段组织，不代表不同来源之间完全一致。
              </small>
            </aside>
          </div>
        </section>

        <section
          id="response-advice"
          className="analysis-section"
          aria-labelledby="advice-title"
        >
          <header className="section-heading">
            <div>
              <span className="eyebrow">RESPONSE GUIDANCE</span>
              <h2 id="advice-title">处置建议</h2>
              <p>建议按条件提供，仅供安全负责人结合本地环境复核。</p>
            </div>
            <span className="section-count">{advice.length} 条建议</span>
          </header>
          <div className="analysis-pane advice-grid">
            {advice.map((item) => (
              <article key={item.id}>
                <header>
                  <span
                    className={`priority priority-${item.priority.toLowerCase()}`}
                  >
                    {item.priority}
                  </span>
                  <span>{item.group}</span>
                </header>
                <h3>{item.title}</h3>
                <p>{item.recommendation}</p>
                <small>{item.condition}</small>
                {item.sourceUrl && (
                  <a href={item.sourceUrl} target="_blank" rel="noreferrer">
                    参考来源 <ExternalLink size={13} />
                  </a>
                )}
              </article>
            ))}
            <div className="advice-disclaimer">
              <ShieldCheck size={16} />
              ARGUS 仅提供参考建议，不直接执行封禁、隔离或配置变更。
            </div>
          </div>
        </section>

        <section
          id="attribution-assist"
          className="analysis-section"
          aria-labelledby="attribution-title"
        >
          <header className="section-heading">
            <div>
              <span className="eyebrow">ATTRIBUTION SUPPORT</span>
              <h2 id="attribution-title">归因辅助</h2>
              <p>归因仅作为辅助假设，不把单一 IOC 或行为相似视为结论。</p>
            </div>
          </header>
          <div className="analysis-pane attribution-pane">
            {actor ? (
              <>
                <div className="attribution-candidate">
                  <span className="candidate-rank">01</span>
                  <div>
                    <span>候选假设</span>
                    <h3>{actor.label}</h3>
                    <p>{actor.public_attribution}</p>
                  </div>
                  <div className="candidate-score">
                    <strong>{Math.round(actor.source_grade * 100)}</strong>
                    <span>来源质量分</span>
                  </div>
                </div>
                <div className="attribution-evidence">
                  <article>
                    <ShieldCheck size={17} />
                    <div>
                      <strong>支持路径</strong>
                      <p>
                        {
                          investigation.steps.filter(
                            (step) =>
                              step.reviewStatus === "matched" ||
                              step.reviewStatus === "confirmed",
                          ).length
                        }{" "}
                        个节点与历史事件路径存在一致性。
                      </p>
                    </div>
                  </article>
                  <article>
                    <TriangleAlert size={17} />
                    <div>
                      <strong>不确定性</strong>
                      <p>工具、技术或单一 IOC 的重合不构成独立归因结论。</p>
                    </div>
                  </article>
                </div>
              </>
            ) : (
              <EmptyState
                title="当前链路没有组织候选"
                description="ARGUS 不会因为行为相似自动生成攻击组织结论。"
              />
            )}
          </div>
        </section>

        <section
          id="all-sources"
          className="analysis-section"
          aria-labelledby="sources-title"
        >
          <header className="section-heading">
            <div>
              <span className="eyebrow">VERIFIABLE SOURCES</span>
              <h2 id="sources-title">全部来源</h2>
              <p>所有可用来源均可打开查看摘录，并继续访问公开原文。</p>
            </div>
            <span className="section-count">{citations.length} 条来源</span>
          </header>
          <div className="analysis-pane source-grid">
            {citations.length ? (
              citations.map((citation) => (
                <SourceCard
                  key={citation.id}
                  citation={citation}
                  onOpen={setSource}
                />
              ))
            ) : (
              <EmptyState
                title="当前匹配暂无可点击来源"
                description="该路径来自查询时序匹配，结果会明确保留证据缺口。"
              />
            )}
          </div>
        </section>
      </div>

      <section className="print-report" aria-hidden="true">
        <h1>{investigation.title}</h1>
        <p>{investigation.summary}</p>
        <h2>攻击链</h2>
        <ol>
          {investigation.steps
            .filter((step) => step.reviewStatus !== "excluded")
            .map((step) => (
              <li key={step.id}>
                <strong>{step.label}</strong> — {step.phase} — {step.relation}
              </li>
            ))}
        </ol>
        <h2>历史报告综合总结</h2>
        {findings.map((finding) => (
          <article key={finding.id}>
            <h3>{finding.title}</h3>
            <p>{finding.summary}</p>
          </article>
        ))}
        <h2>参考处置建议</h2>
        {advice.map((item) => (
          <article key={item.id}>
            <h3>
              {item.priority} · {item.title}
            </h3>
            <p>{item.recommendation}</p>
            <small>{item.condition}</small>
          </article>
        ))}
        <p className="print-disclaimer">
          本报告仅供安全分析参考，不构成自动处置或确定性归因结论。
        </p>
      </section>
      {source && (
        <SourceViewer
          citation={source}
          onClose={() => setSource(undefined)}
        />
      )}
    </main>
  );
}
