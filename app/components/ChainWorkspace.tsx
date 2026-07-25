"use client";

import {
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  Bot,
  Check,
  ChevronLeft,
  ChevronRight,
  CirclePlus,
  Clock3,
  ExternalLink,
  FileJson,
  FileText,
  ListChecks,
  Pencil,
  Printer,
  Save,
  ShieldCheck,
  Trash2,
  TriangleAlert,
  X,
} from "lucide-react";
import { useMemo, useState } from "react";
import {
  actorForCase,
  adviceForCase,
  caseGraph,
  citationsForCase,
  historicalFindings,
} from "../argus-domain";
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
import { NetworkGraph } from "../NetworkGraph";
import {
  Confidence,
  EmptyState,
  SourceCard,
  SourceViewer,
  StatusBadge,
} from "./Primitives";

type AnalysisTab = "history" | "advice" | "attribution" | "sources";

const tabLabels: Array<[AnalysisTab, string]> = [
  ["history", "历史总结"],
  ["advice", "处置建议"],
  ["attribution", "归因辅助"],
  ["sources", "全部来源"],
];

function stepOriginLabel(step: ChainStep) {
  return {
    database: "情报库匹配",
    log: "日志提取",
    manual: "人工创建",
    gpt: "GPT 建议",
  }[step.origin];
}

export function ChainWorkspace({
  data,
  investigation,
  onChange,
  onSave,
  onBack,
  onOpenGraph,
  onOpenGpt,
}: {
  data: Snapshot;
  investigation: InvestigationCase;
  onChange: (investigation: InvestigationCase) => void;
  onSave: () => void;
  onBack: () => void;
  onOpenGraph: () => void;
  onOpenGpt: () => void;
}) {
  const [selectedId, setSelectedId] = useState(investigation.steps[0]?.id);
  const [tab, setTab] = useState<AnalysisTab>("history");
  const [source, setSource] = useState<SourceCitation>();
  const [savedNotice, setSavedNotice] = useState(false);
  const [editor, setEditor] = useState<{
    mode: "create" | "edit";
    draft: ChainStep;
  }>();
  const graph = useMemo(() => caseGraph(data, investigation), [data, investigation]);
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
  const selected = investigation.steps.find((step) => step.id === selectedId);
  const selectedCitationIds = new Set(
    investigation.links
      .filter((link) => link.source === selectedId || link.target === selectedId)
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

  const updateStep = (stepId: string, patch: Partial<ChainStep>) => {
    onChange({
      ...investigation,
      steps: investigation.steps.map((step) =>
        step.id === stepId ? { ...step, ...patch } : step,
      ),
    });
  };

  const rebuildSequentialLinks = (
    steps: ChainStep[],
    links = investigation.links,
  ) =>
    steps.slice(1).map((step, index) => {
      const previous = steps[index];
      const existing =
        links.find(
          (link) => link.source === previous.id && link.target === step.id,
        ) ?? links.find((link) => link.target === step.id);
      return {
        id:
          existing?.id ??
          `manual-link-${Date.now().toString(36)}-${index.toString(36)}`,
        source: previous.id,
        target: step.id,
        label: step.relation || existing?.label || "待确认关系",
        confidence:
          existing?.confidence ??
          Math.min(previous.confidence, step.confidence),
        status: existing?.status ?? step.status,
        relationshipId: existing?.relationshipId,
      };
    });

  const moveStep = (stepId: string, direction: -1 | 1) => {
    const index = investigation.steps.findIndex((step) => step.id === stepId);
    const nextIndex = index + direction;
    if (index < 0 || nextIndex < 0 || nextIndex >= investigation.steps.length) return;
    const steps = [...investigation.steps];
    [steps[index], steps[nextIndex]] = [steps[nextIndex], steps[index]];
    onChange({
      ...investigation,
      steps,
      links: rebuildSequentialLinks(steps),
    });
  };

  const openStepCreator = () => {
    const id = `manual-${Date.now().toString(36)}`;
    setEditor({
      mode: "create",
      draft: {
        id,
        label: "新建候选节点",
        type: "输入步骤",
        relation: investigation.steps.length ? "待确认关系" : "链路起点",
        phase: "待研判",
        confidence: 0.4,
        evidenceCount: 0,
        status: "partial",
        origin: "manual",
        reviewStatus: "candidate",
        description: "人工创建的候选节点，需要补充真实名称与证据。",
      },
    });
  };

  const openStepEditor = (step: ChainStep) => {
    setEditor({ mode: "edit", draft: { ...step } });
  };

  const saveStepEditor = () => {
    if (!editor?.draft.label.trim()) return;
    const draft = {
      ...editor.draft,
      label: editor.draft.label.trim(),
      relation: editor.draft.relation.trim() || "待确认关系",
      phase: editor.draft.phase.trim() || "待研判",
      type: editor.draft.type.trim() || "输入步骤",
    };
    const steps =
      editor.mode === "create"
        ? [...investigation.steps, draft]
        : investigation.steps.map((step) =>
            step.id === draft.id ? draft : step,
          );
    onChange({
      ...investigation,
      steps,
      links: rebuildSequentialLinks(steps),
    });
    setSelectedId(draft.id);
    setEditor(undefined);
  };

  const deleteStep = (stepId: string) => {
    const currentIndex = investigation.steps.findIndex(
      (step) => step.id === stepId,
    );
    const steps = investigation.steps.filter((step) => step.id !== stepId);
    onChange({
      ...investigation,
      steps,
      links: rebuildSequentialLinks(
        steps,
        investigation.links.filter(
          (link) => link.source !== stepId && link.target !== stepId,
        ),
      ),
    });
    setSelectedId(steps[Math.min(currentIndex, steps.length - 1)]?.id);
    setEditor(undefined);
  };

  const pendingReviewCount = investigation.steps.filter(
    (step) => step.reviewStatus === "candidate",
  ).length;
  const evidenceGapCount = investigation.steps.filter(
    (step) => step.evidenceCount === 0,
  ).length;
  const selectedIndex = investigation.steps.findIndex(
    (step) => step.id === selectedId,
  );

  const save = () => {
    onSave();
    setSavedNotice(true);
    window.setTimeout(() => setSavedNotice(false), 1800);
  };

  return (
    <main className="chain-workspace">
      <div className="workspace-toolbar">
        <div className="workspace-title">
          <button type="button" className="icon-button" aria-label="返回" onClick={onBack}>
            <ArrowLeft size={17} />
          </button>
          <div>
            <span>
              {investigation.id} · 本机 Demo 草稿
            </span>
            <input
              aria-label="案件标题"
              value={investigation.title}
              onChange={(event) =>
                onChange({ ...investigation, title: event.target.value })
              }
            />
          </div>
          <StatusBadge status="partial">研判中</StatusBadge>
        </div>
        <div className="workspace-actions">
          {savedNotice && <span className="save-notice"><Check size={14} />已保存在本机</span>}
          <button type="button" className="secondary-button" onClick={onOpenGpt}>
            <Bot size={15} /> GPT 辅助
          </button>
          <button type="button" className="secondary-button" onClick={save}>
            <Save size={15} /> 保存
          </button>
          <div className="export-actions">
            <button type="button" aria-label="打印或导出 PDF" onClick={printInvestigation}>
              <Printer size={15} />
            </button>
            <button type="button" aria-label="导出 Markdown" onClick={() => downloadMarkdown(exportBundle)}>
              <ArrowDownToLine size={15} />
              MD
            </button>
            <button type="button" aria-label="导出 JSON" onClick={() => downloadJson(exportBundle)}>
              <FileJson size={15} />
              JSON
            </button>
          </div>
        </div>
      </div>

      <section className="investigation-flow" aria-label="研判流程">
        <div className="flow-objective">
          <span className="eyebrow">CURRENT OBJECTIVE</span>
          <strong>先确认主攻击路径，再形成结论</strong>
          <p>{investigation.summary}</p>
        </div>
        <ol className="review-stages">
          <li className="active">
            <span>1</span>
            <div>
              <strong>整理主线</strong>
              <small>{investigation.steps.length} 个真实节点</small>
            </div>
          </li>
          <li className={pendingReviewCount ? "attention" : "complete"}>
            <span>2</span>
            <div>
              <strong>逐节点核验</strong>
              <small>
                {pendingReviewCount
                  ? `${pendingReviewCount} 个候选待处理`
                  : "候选节点已处理"}
              </small>
            </div>
          </li>
          <li className={evidenceGapCount ? "" : "complete"}>
            <span>3</span>
            <div>
              <strong>总结与建议</strong>
              <small>{evidenceGapCount} 个证据缺口需说明</small>
            </div>
          </li>
        </ol>
      </section>

      <div className="workspace-primary">
        <section className="timeline-panel">
          <header className="panel-header">
            <div>
              <span className="eyebrow">PRIMARY ATTACK PATH</span>
              <h2>主攻击路径</h2>
            </div>
            <div className="panel-header-actions">
              <span>真实时序为主 · ATT&amp;CK 为补充</span>
              <button type="button" className="primary-button" onClick={openStepCreator}>
                <CirclePlus size={15} /> 添加节点
              </button>
            </div>
          </header>
          <div className="chain-stage-strip">
            {[...new Set(investigation.steps.map((step) => step.phase))].map((phase) => (
              <span key={phase}>{phase}</span>
            ))}
          </div>
          <div className="chain-timeline" role="list" aria-label="攻击链步骤">
            {investigation.steps.map((step, index) => (
              <div
                key={step.id}
                className={`chain-step-wrap ${step.reviewStatus === "excluded" ? "is-excluded" : ""}`}
              >
                {index > 0 && (
                  <div className={`chain-connector connector-${step.status}`}>
                    <span>{step.relation}</span>
                    <ArrowRight size={17} />
                  </div>
                )}
                <button
                  type="button"
                  role="listitem"
                  aria-label={`攻击链节点：${step.label}`}
                  className={`chain-step-card ${selectedId === step.id ? "is-selected" : ""}`}
                  onClick={() => setSelectedId(step.id)}
                >
                  <span className="step-number">{String(index + 1).padStart(2, "0")}</span>
                  <div className="step-card-head">
                    <span>{step.phase}</span>
                    <StatusBadge status={step.reviewStatus} />
                  </div>
                  <strong>{step.label}</strong>
                  <p>{step.description || step.type}</p>
                  <div className="step-tags">
                    <span>{step.type}</span>
                    {step.attackId && <span>{step.attackId}</span>}
                  </div>
                  <footer>
                    <span>
                      <ShieldCheck size={13} />
                      {step.evidenceCount} 份证据
                    </span>
                    <span>{Math.round(step.confidence * 100)}%</span>
                  </footer>
                </button>
              </div>
            ))}
          </div>
          <div className="chain-legend">
            <span><i className="legend-confirmed" />人工确认</span>
            <span><i className="legend-matched" />情报匹配</span>
            <span><i className="legend-candidate" />候选节点</span>
            <span><i className="legend-negative" />反证/排除</span>
          </div>
        </section>

        <aside className="workspace-context" aria-label="当前节点研判">
          <div className="selected-step-panel">
            {selected ? (
              <>
                <header>
                  <div>
                    <span className="eyebrow">
                      NODE {selectedIndex + 1} / {investigation.steps.length}
                    </span>
                    <h3>{selected.label}</h3>
                  </div>
                  <StatusBadge status={selected.reviewStatus} />
                </header>
                <div className="node-next-action">
                  <ListChecks size={16} />
                  <div>
                    <strong>
                      {selected.reviewStatus === "candidate"
                        ? "下一步：核对并处理此节点"
                        : selected.reviewStatus === "excluded"
                          ? "此节点已从主线排除"
                          : "此节点已完成核验"}
                    </strong>
                    <span>
                      {selected.reviewStatus === "candidate"
                        ? "检查名称、前序关系与来源证据，然后确认或排除。"
                        : "继续选择主线中的下一个节点。"}
                    </span>
                  </div>
                </div>
                <div className="node-provenance">
                  <span>{stepOriginLabel(selected)}</span>
                  <span>{selected.phase}</span>
                  {selected.attackId && <span>{selected.attackId}</span>}
                </div>
                <Confidence value={selected.confidence} />
                <div className="node-review-actions">
                  <button
                    type="button"
                    className="edit"
                    onClick={() => openStepEditor(selected)}
                  >
                    <Pencil size={14} /> 编辑节点
                  </button>
                  <button
                    type="button"
                    className={selected.reviewStatus === "confirmed" ? "active" : ""}
                    onClick={() => updateStep(selected.id, { reviewStatus: "confirmed" })}
                  >
                    <Check size={14} /> 确认
                  </button>
                  <button
                    type="button"
                    className={selected.reviewStatus === "excluded" ? "negative active" : "negative"}
                    onClick={() => updateStep(selected.id, { reviewStatus: "excluded" })}
                  >
                    <X size={14} /> 排除
                  </button>
                  <button type="button" aria-label="向前移动" onClick={() => moveStep(selected.id, -1)}>
                    <ChevronLeft size={14} />
                  </button>
                  <button type="button" aria-label="向后移动" onClick={() => moveStep(selected.id, 1)}>
                    <ChevronRight size={14} />
                  </button>
                </div>
                {selectedSources[0] ? (
                  <button
                    type="button"
                    className="selected-source"
                    onClick={() => setSource(selectedSources[0])}
                  >
                    <FileText size={15} />
                    <span>
                      <strong>{selectedSources[0].title}</strong>
                      <small>{selectedSources[0].location || "来源摘录"}</small>
                    </span>
                    <ArrowRight size={14} />
                  </button>
                ) : (
                  <p className="muted">
                    当前节点暂无直接关系摘录，应保留为待补充证据。
                  </p>
                )}
              </>
            ) : (
              <EmptyState title="选择主线节点" description="从左侧主攻击路径选择一个节点开始研判。" />
            )}
          </div>
          <div className="context-graph">
            <header className="panel-header compact">
              <div>
                <span className="eyebrow">SUPPORTING VIEW</span>
                <h2>辅助关系图谱</h2>
              </div>
              <button type="button" className="icon-link" aria-label="全屏图谱" onClick={onOpenGraph}>
                <ExternalLink size={15} />
              </button>
            </header>
            <NetworkGraph
              compact
              nodes={graph.nodes}
              edges={graph.edges}
              rootId={investigation.steps[0]?.id}
              selectedId={selectedId}
              onSelect={(node) => setSelectedId(node.id)}
            />
          </div>
        </aside>
      </div>

      <section className="workspace-analysis">
        <div className="analysis-tabs" role="tablist" aria-label="研判结果">
          {tabLabels.map(([id, label]) => (
            <button
              type="button"
              role="tab"
              aria-selected={tab === id}
              className={tab === id ? "active" : ""}
              key={id}
              onClick={() => setTab(id)}
            >
              {label}
              {id === "sources" && <span>{citations.length}</span>}
            </button>
          ))}
        </div>

        {tab === "history" && (
          <div className="analysis-pane history-pane">
            <div className="history-findings">
              {findings.map((finding) => (
                <article key={finding.id} className={`finding-${finding.tone}`}>
                  <div className="finding-marker">
                    {finding.tone === "difference" ? (
                      <TriangleAlert size={15} />
                    ) : (
                      <Clock3 size={15} />
                    )}
                  </div>
                  <div>
                    <span>{finding.phase}</span>
                    <h3>{finding.title}</h3>
                    <p>{finding.summary}</p>
                    <div className="inline-citations">
                      {finding.citationIds.map((citationId, index) => {
                        const citation = citations.find((item) => item.id === citationId);
                        if (!citation) return null;
                        return (
                          <button type="button" key={citationId} onClick={() => setSource(citation)}>
                            [{index + 1}] {citation.publisher}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                </article>
              ))}
            </div>
            <aside className="history-overview">
              <span className="eyebrow">HISTORICAL ALIGNMENT</span>
              <strong>{citations.length}</strong>
              <p>条可点击来源证据支持当前攻击链</p>
              <div>
                <span>主链覆盖</span>
                <strong>
                  {investigation.steps.filter((step) => step.evidenceCount > 0).length}/
                  {investigation.steps.length}
                </strong>
              </div>
              <small>摘要按攻击阶段组织，不代表来源之间完全一致。</small>
            </aside>
          </div>
        )}

        {tab === "advice" && (
          <div className="analysis-pane advice-grid">
            {advice.map((item) => {
              const completed = investigation.completedAdviceIds.includes(item.id);
              return (
                <article key={item.id} className={completed ? "is-completed" : ""}>
                  <header>
                    <span className={`priority priority-${item.priority.toLowerCase()}`}>
                      {item.priority}
                    </span>
                    <span>{item.group}</span>
                    <button
                      type="button"
                      aria-label={completed ? "标记为未完成" : "标记为完成"}
                      onClick={() =>
                        onChange({
                          ...investigation,
                          completedAdviceIds: completed
                            ? investigation.completedAdviceIds.filter((id) => id !== item.id)
                            : [...investigation.completedAdviceIds, item.id],
                        })
                      }
                    >
                      <Check size={14} />
                    </button>
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
              );
            })}
            <div className="advice-disclaimer">
              <ShieldCheck size={16} />
              ARGUS 仅提供参考建议，不直接执行封禁、隔离或配置变更。
            </div>
          </div>
        )}

        {tab === "attribution" && (
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
                      <p>{investigation.steps.filter((step) => step.reviewStatus === "matched" || step.reviewStatus === "confirmed").length} 个节点与历史事件路径一致。</p>
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
        )}

        {tab === "sources" && (
          <div className="analysis-pane source-grid">
            {citations.length ? (
              citations.map((citation) => (
                <SourceCard key={citation.id} citation={citation} onOpen={setSource} />
              ))
            ) : (
              <EmptyState
                title="当前草稿暂无可点击来源"
                description="人工输入节点仍可继续编辑，但导出报告会明确标注证据缺口。"
              />
            )}
          </div>
        )}
      </section>

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
            <h3>{item.priority} · {item.title}</h3>
            <p>{item.recommendation}</p>
            <small>{item.condition}</small>
          </article>
        ))}
        <p className="print-disclaimer">
          本报告仅供安全分析参考，不构成自动处置或确定性归因结论。
        </p>
      </section>
      {source && <SourceViewer citation={source} onClose={() => setSource(undefined)} />}
      {editor && (
        <div className="node-editor-backdrop">
          <form
            className="node-editor"
            role="dialog"
            aria-modal="true"
            aria-labelledby="node-editor-title"
            onSubmit={(event) => {
              event.preventDefault();
              saveStepEditor();
            }}
          >
            <header>
              <div>
                <span className="eyebrow">
                  {editor.mode === "create" ? "ADD TO MAIN PATH" : "EDIT MAIN PATH"}
                </span>
                <h2 id="node-editor-title">编辑攻击链节点</h2>
              </div>
              <button
                type="button"
                className="icon-button"
                aria-label="关闭节点编辑器"
                onClick={() => setEditor(undefined)}
              >
                <X size={17} />
              </button>
            </header>

            <div className="node-editor-grid">
              <label className="field-wide">
                <span>节点名称</span>
                <input
                  autoFocus
                  aria-label="节点名称"
                  value={editor.draft.label}
                  onChange={(event) =>
                    setEditor({
                      ...editor,
                      draft: { ...editor.draft, label: event.target.value },
                    })
                  }
                />
                <small>使用真实对象或动作名称，不要只写行为分类。</small>
              </label>
              <label>
                <span>与前序节点的关系</span>
                <input
                  aria-label="与前序节点的关系"
                  value={editor.draft.relation}
                  onChange={(event) =>
                    setEditor({
                      ...editor,
                      draft: { ...editor.draft, relation: event.target.value },
                    })
                  }
                />
              </label>
              <label>
                <span>攻击阶段</span>
                <input
                  aria-label="攻击阶段"
                  list="attack-phases"
                  value={editor.draft.phase}
                  onChange={(event) =>
                    setEditor({
                      ...editor,
                      draft: { ...editor.draft, phase: event.target.value },
                    })
                  }
                />
                <datalist id="attack-phases">
                  <option value="初始访问" />
                  <option value="执行" />
                  <option value="持久化" />
                  <option value="凭据访问" />
                  <option value="横向移动" />
                  <option value="命令与控制" />
                  <option value="数据外传" />
                  <option value="待研判" />
                </datalist>
              </label>
              <label>
                <span>节点类型</span>
                <input
                  aria-label="节点类型"
                  value={editor.draft.type}
                  onChange={(event) =>
                    setEditor({
                      ...editor,
                      draft: { ...editor.draft, type: event.target.value },
                    })
                  }
                />
              </label>
              <label>
                <span>ATT&amp;CK（可选）</span>
                <input
                  aria-label="ATT&CK"
                  value={editor.draft.attackId ?? ""}
                  placeholder="例如 T1059.001"
                  onChange={(event) =>
                    setEditor({
                      ...editor,
                      draft: {
                        ...editor.draft,
                        attackId: event.target.value || undefined,
                      },
                    })
                  }
                />
              </label>
              <label className="field-wide">
                <span>节点说明</span>
                <textarea
                  aria-label="节点说明"
                  rows={3}
                  value={editor.draft.description ?? ""}
                  onChange={(event) =>
                    setEditor({
                      ...editor,
                      draft: {
                        ...editor.draft,
                        description: event.target.value,
                      },
                    })
                  }
                />
              </label>
              <label className="field-wide confidence-field">
                <span>
                  当前置信度
                  <strong>{Math.round(editor.draft.confidence * 100)}%</strong>
                </span>
                <input
                  aria-label="当前置信度"
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={editor.draft.confidence}
                  onChange={(event) =>
                    setEditor({
                      ...editor,
                      draft: {
                        ...editor.draft,
                        confidence: Number(event.target.value),
                      },
                    })
                  }
                />
              </label>
            </div>

            <footer>
              <div>
                {editor.mode === "edit" && (
                  <button
                    type="button"
                    className="danger-button"
                    onClick={() => deleteStep(editor.draft.id)}
                  >
                    <Trash2 size={15} /> 删除节点
                  </button>
                )}
              </div>
              <div>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => setEditor(undefined)}
                >
                  取消
                </button>
                <button
                  type="submit"
                  className="primary-button"
                  disabled={!editor.draft.label.trim()}
                >
                  保存节点
                </button>
              </div>
            </footer>
          </form>
        </div>
      )}
    </main>
  );
}
