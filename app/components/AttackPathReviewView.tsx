"use client";

import {
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  Check,
  CircleDashed,
  GitBranch,
  Link2,
  PencilLine,
  Plus,
  RotateCcw,
  ShieldCheck,
  Split,
  Trash2,
  X,
} from "lucide-react";
import { useMemo, useState } from "react";
import { adaptBackendFlowMatches } from "../backend-path";
import type {
  AttackActivityCluster,
  BackendFlowMatchAnalysis,
  PathCandidate,
  PathCandidateLink,
  PathCandidateStep,
  PathWorkspace,
} from "../types";


const stateLabels: Record<PathCandidateStep["analysisState"], string> = {
  observed: "输入命中",
  reconstructed: "路径补全",
  predicted: "后续预测",
  reference: "历史分支",
  candidate: "待验证",
  blocked: "阻断结果",
};

const dispositionLabels: Record<PathCandidate["disposition"], string> = {
  primary: "优先路径",
  blocked: "阻断分支",
  candidate: "低置信假设",
};


function linksForSteps(steps: PathCandidateStep[]): PathCandidateLink[] {
  return steps.slice(1).map((target, index) => {
    const source = steps[index];
    return {
      id: `edited-link-${source.id}-${target.id}`,
      sourceStepId: source.id,
      targetStepId: target.id,
      label: "待复核推进关系",
      reviewStatus:
        target.analysisState === "predicted"
          ? "predicted"
          : target.analysisState === "reconstructed"
            ? "suggested"
            : "observed",
      confidence: Math.min(source.confidence, target.confidence),
    };
  });
}


function candidateCounts(candidate: PathCandidate) {
  return {
    observed: candidate.steps.filter((step) => step.analysisState === "observed").length,
    inferred: candidate.steps.filter((step) =>
      ["reconstructed", "predicted", "candidate"].includes(step.analysisState),
    ).length,
    suggestedEdges:
      candidate.links?.filter((link) => link.reviewStatus === "suggested").length ?? 0,
  };
}


function PathRail({ steps }: { steps: PathCandidateStep[] }) {
  return (
    <div className="candidate-path-rail" aria-label="路径节点预览">
      {steps.map((step, index) => (
        <div className={`is-${step.analysisState}`} key={step.id}>
          <span>{index + 1}</span>
          <strong>{step.label}</strong>
          <small>{stateLabels[step.analysisState]}</small>
          {index < steps.length - 1 && <ArrowRight size={14} aria-hidden="true" />}
        </div>
      ))}
    </div>
  );
}


export function AttackPathReviewView({
  initialSelection,
  backendAnalysis,
  analysisStatus,
  analysisError,
  backLabel,
  onBack,
  onOpenPath,
}: {
  data: PathWorkspace;
  query: string;
  initialSelection?: PathCandidate;
  backendAnalysis?: BackendFlowMatchAnalysis;
  analysisStatus: "idle" | "loading" | "ready" | "offline";
  analysisError?: string;
  backLabel: string;
  onBack: () => void;
  onOpenPath: (candidate: PathCandidate) => void;
}) {
  const initialClusters = useMemo(
    () => (backendAnalysis ? adaptBackendFlowMatches(backendAnalysis) : []),
    [backendAnalysis],
  );
  const [clusters, setClusters] = useState<AttackActivityCluster[]>(() =>
    initialSelection
      ? initialClusters.map((cluster) =>
          cluster.id === initialSelection.activityId
            ? {
                ...cluster,
                candidates: cluster.candidates.map((candidate) =>
                  candidate.id === initialSelection.id ? initialSelection : candidate,
                ),
              }
            : cluster,
        )
      : initialClusters,
  );
  const [selectedActivityId, setSelectedActivityId] = useState(
    initialSelection?.activityId ?? initialClusters[0]?.id ?? "",
  );
  const [selectedCandidateId, setSelectedCandidateId] = useState(
    initialSelection?.id ?? initialClusters[0]?.candidates[0]?.id ?? "",
  );

  const selectedCluster =
    clusters.find((cluster) => cluster.id === selectedActivityId) ?? clusters[0];
  const selected =
    selectedCluster?.candidates.find((candidate) => candidate.id === selectedCandidateId) ??
    selectedCluster?.candidates[0];

  const updateSelected = (updater: (candidate: PathCandidate) => PathCandidate) => {
    if (!selectedCluster || !selected) return;
    setClusters((current) =>
      current.map((cluster) =>
        cluster.id === selectedCluster.id
          ? {
              ...cluster,
              candidates: cluster.candidates.map((candidate) =>
                candidate.id === selected.id ? updater(candidate) : candidate,
              ),
            }
          : cluster,
      ),
    );
  };

  const replaceSteps = (steps: PathCandidateStep[]) => {
    updateSelected((candidate) => ({
      ...candidate,
      steps,
      links: linksForSteps(steps),
      analysisQuery: steps.map((step) => step.label).join(" → "),
    }));
  };

  if (!selectedCluster || !selected) {
    return (
      <main className="path-review-page activity-review-page">
        <div className="path-review-inner">
          <button type="button" className="back-link" onClick={onBack}>
            <ArrowLeft size={15} /> {backLabel}
          </button>
          <header className="path-review-heading">
            <div>
              <span>AttackFlow Matcher</span>
              <h1>
                {analysisStatus === "loading"
                  ? "正在匹配历史 AttackFlow"
                  : "没有达到阈值的历史攻击流"}
              </h1>
              <p>
                {analysisStatus === "loading"
                  ? "候选只会来自当前后端 AttackFlow，不使用通用攻击步骤实体生成兼容结果。"
                  : analysisError || "系统没有强行选择无关路径。请补充更具体的行为、IOC、工具或漏洞线索。"}
              </p>
            </div>
          </header>
        </div>
      </main>
    );
  }

  const totalCandidates = clusters.reduce(
    (sum, cluster) => sum + cluster.candidates.length,
    0,
  );
  const totalObserved = clusters.reduce(
    (sum, cluster) =>
      sum + cluster.candidates.reduce(
        (candidateSum, candidate) => candidateSum + candidateCounts(candidate).observed,
        0,
      ),
    0,
  );
  const concreteInputSets =
    backendAnalysis?.candidates.map(
      (candidate) =>
        new Set(
          candidate.matches
            .filter((match) => match.match_kind !== "attack")
            .map((match) => match.input_index),
        ),
    ) ?? [];
  const coveredConcreteInputs = new Set(
    concreteInputSets.flatMap((inputSet) => [...inputSet]),
  );
  const isMultiFlowSplit =
    concreteInputSets.length > 1 &&
    coveredConcreteInputs.size > 1 &&
    concreteInputSets.every(
      (inputSet) => inputSet.size < coveredConcreteInputs.size,
    );
  return (
    <main className="path-review-page activity-review-page">
      <div className="path-review-inner">
        <button type="button" className="back-link" onClick={onBack}>
          <ArrowLeft size={15} /> {backLabel}
        </button>

        <header className="path-review-heading">
          <div>
            <span>AttackFlow 匹配结果</span>
            <h1>找到 {totalCandidates} 条达到阈值的历史攻击流候选</h1>
            <p>候选按行为与 Context 命中排序，主干顺序只来自 AttackFlow 的显式 mainline。</p>
          </div>
          <dl aria-label="输入解析摘要">
            <div><dt>攻击活动</dt><dd>{clusters.length}</dd></div>
            <div><dt>输入命中</dt><dd>{totalObserved}</dd></div>
            <div><dt>候选 Flow</dt><dd>{totalCandidates}</dd></div>
          </dl>
        </header>

        <section className="path-review-notice" aria-label="分析说明">
          <Split size={18} />
          <div>
            <strong>
              {isMultiFlowSplit
                ? "检测到多攻击流分流 · 候选需分别复核"
                : `${backendAnalysis?.algorithm_version ?? "AttackFlow Matcher"} · 候选排序可重放`}
            </strong>
            <span>
              {isMultiFlowSplit
                ? `当前没有单条候选解释全部 ${coveredConcreteInputs.size} 条具体输入；不同候选分别覆盖不同线索，分值不可跨候选相加。`
                : `已规范化 ${backendAnalysis?.normalized_inputs.length ?? 0} 条输入；输入命中、路径补全和后续预测只属于本次匹配运行。`}
            </span>
          </div>
          <ShieldCheck size={18} />
        </section>

        <div className="activity-review-layout">
          <nav className="activity-cluster-index" aria-label="攻击活动候选">
            <header><strong>攻击活动</strong><span>{clusters.length} 个匹配结果</span></header>
            {clusters.map((cluster, index) => (
              <button
                type="button"
                key={cluster.id}
                className={cluster.id === selectedCluster.id ? "is-selected" : ""}
                aria-pressed={cluster.id === selectedCluster.id}
                onClick={() => {
                  setSelectedActivityId(cluster.id);
                  setSelectedCandidateId(cluster.candidates[0]?.id ?? "");
                }}
              >
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong>{cluster.title}</strong>
                <small>{Math.round(cluster.confidence * 100)} · {cluster.sourceCount} 个来源</small>
              </button>
            ))}
          </nav>

          <section className="activity-path-composer">
            <header>
              <div><span>历史 AttackFlow</span><h2>{selectedCluster.title}</h2><p>{selectedCluster.summary}</p></div>
              <strong>{Math.round(selectedCluster.confidence * 100)}</strong>
            </header>
            <section className="activity-branch-list" aria-label="路径候选列表">
              {selectedCluster.candidates.map((candidate) => {
                const counts = candidateCounts(candidate);
                return (
                  <article
                    className={`activity-branch is-${candidate.disposition} ${
                      candidate.id === selected.id ? "is-selected" : ""
                    }`}
                    key={candidate.id}
                  >
                    <button
                      type="button"
                      className="activity-branch-select"
                      aria-pressed={candidate.id === selected.id}
                      onClick={() => setSelectedCandidateId(candidate.id)}
                    >
                      <span className="branch-select-mark">{candidate.id === selected.id ? <Check size={13} /> : <CircleDashed size={13} />}</span>
                      <span><small>{dispositionLabels[candidate.disposition]}</small><strong>{candidate.title}</strong><em>{candidate.summary}</em></span>
                      <b>{Math.round(candidate.confidence * 100)}</b>
                    </button>
                    <PathRail steps={candidate.steps} />
                    <footer>
                      <span>{counts.observed} 个输入命中</span>
                      <span>{counts.inferred} 个补全/预测</span>
                      <span><Link2 size={13} /> {counts.suggestedEdges} 条建议关系</span>
                    </footer>
                  </article>
                );
              })}
            </section>
            <aside className="activity-cluster-rationale">
              <GitBranch size={16} />
              <div><strong>匹配依据</strong><p>{selected.reason}</p></div>
              <div><strong>未解释线索</strong><p>{selected.gap}</p></div>
            </aside>
          </section>

          <aside className="path-review-editor" aria-label="路径节点校正">
            <header>
              <div><PencilLine size={17} /><span>路径校正</span></div>
              <button type="button" onClick={() => setClusters(initialClusters)}><RotateCcw size={14} /> 重置</button>
            </header>
            <h2>{selected.title}</h2>
            <p>修改只作用于本次分析，不会回写历史 AttackFlow。</p>
            <div className="path-editor-steps">
              {selected.steps.map((step, index) => (
                <div className="path-editor-step" key={step.id}>
                  <span className={`step-state is-${step.analysisState}`}>{index + 1}</span>
                  <div>
                    <label htmlFor={`step-label-${step.id}`}>节点名称</label>
                    <input
                      id={`step-label-${step.id}`}
                      aria-label="节点名称"
                      value={step.label}
                      onChange={(event) => replaceSteps(selected.steps.map((item) => item.id === step.id ? { ...item, label: event.target.value } : item))}
                    />
                    <small
                      className={`path-editor-status is-${step.analysisState}`}
                    >
                      <span>{stateLabels[step.analysisState]}</span>
                      <b>{Math.round(step.confidence * 100)}%</b>
                    </small>
                  </div>
                  <div className="path-editor-actions">
                    <button type="button" aria-label={`上移${step.label}`} disabled={index === 0} onClick={() => {
                      const steps = [...selected.steps];
                      [steps[index - 1], steps[index]] = [steps[index], steps[index - 1]];
                      replaceSteps(steps);
                    }}><ArrowUp size={13} /></button>
                    <button type="button" aria-label={`下移${step.label}`} disabled={index === selected.steps.length - 1} onClick={() => {
                      const steps = [...selected.steps];
                      [steps[index], steps[index + 1]] = [steps[index + 1], steps[index]];
                      replaceSteps(steps);
                    }}><ArrowDown size={13} /></button>
                    <button type="button" aria-label={`删除${step.label}`} onClick={() => replaceSteps(selected.steps.filter((item) => item.id !== step.id))}><Trash2 size={13} /></button>
                  </div>
                </div>
              ))}
            </div>
            <button type="button" className="path-editor-add" onClick={() => replaceSteps([
              ...selected.steps,
              {
                id: `manual-${Date.now().toString(36)}`,
                label: "待补充节点",
                phase: "待研判",
                analysisState: "candidate",
                confidence: 0.45,
                evidenceCount: 0,
              },
            ])}><Plus size={14} /> 添加节点</button>
            <button type="button" className="path-editor-open" onClick={() => onOpenPath(selected)}>进入所选路径 <ArrowRight size={15} /></button>
            {analysisStatus === "offline" && <p><X size={13} /> {analysisError}</p>}
          </aside>
        </div>
      </div>
    </main>
  );
}
