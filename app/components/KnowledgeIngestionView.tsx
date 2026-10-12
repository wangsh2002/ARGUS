"use client";

import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Database,
  FileCheck2,
  FileText,
  GitBranch,
  GitMerge,
  Layers3,
  LoaderCircle,
  Network,
  RotateCcw,
  ShieldCheck,
  Upload,
} from "lucide-react";
import { useState } from "react";
import type {
  KnowledgeIngestionBatchResult,
  KnowledgeIngestionResult,
} from "../types";

const emptySource = {
  title: "",
  publisher: "",
  canonical_url: "",
  published_at: "",
  content: "",
};


async function ingestionRequest(body: unknown) {
  const response = await fetch("/api/knowledge-ingestion", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = (await response.json()) as
    | KnowledgeIngestionResult
    | KnowledgeIngestionBatchResult
    | {
        status?: string;
        changes?: {
          removed_evidence?: number;
          removed_entity_mentions?: number;
        };
        error?: { message?: string };
      };
  if (!response.ok || "error" in payload) {
    throw new Error(
      "error" in payload
        ? payload.error?.message || "情报入库请求失败。"
        : "情报入库请求失败。",
    );
  }
  return payload;
}


export function KnowledgeIngestionView({
  onOpenGraph,
  onOpenPublishedFlow,
  onKnowledgeChanged,
}: {
  onOpenGraph: () => void;
  onOpenPublishedFlow: (flowId: string) => Promise<void>;
  onKnowledgeChanged: () => Promise<void>;
}) {
  const [source, setSource] = useState(emptySource);
  const [attackFlowCandidate, setAttackFlowCandidate] = useState<
    NonNullable<KnowledgeIngestionResult["attack_flow_candidate"]>
  >();
  const [result, setResult] = useState<KnowledgeIngestionResult>();
  const [batchResult, setBatchResult] = useState<KnowledgeIngestionBatchResult>();
  const [working, setWorking] = useState<
    "stage" | "revise" | "publish" | "reject" | "rollback"
  >();
  const [error, setError] = useState("");

  const setDisplayedResult = (next: KnowledgeIngestionResult) => {
    setResult(next);
    setBatchResult((current) =>
      current
        ? {
            ...current,
            candidates: current.candidates.map((candidate) =>
              candidate.id === next.id ? next : candidate,
            ),
          }
        : current,
    );
  };

  const runStage = async () => {
    setWorking("stage");
    setError("");
    try {
      const payload = await ingestionRequest({
        action: "stage",
        source,
        attack_flow_candidate: attackFlowCandidate,
        extract_attack_flows: !attackFlowCandidate,
      });
      if (
        "ingestion_kind" in payload &&
        payload.ingestion_kind === "attack-flow-batch"
      ) {
        setBatchResult(payload);
        setResult(payload.candidates[0]);
      } else {
        setBatchResult(undefined);
        setResult(payload as KnowledgeIngestionResult);
      }
    } catch (nextError) {
      setError(
        nextError instanceof Error ? nextError.message : "无法生成入库预览。",
      );
    } finally {
      setWorking(undefined);
    }
  };

  const publish = async () => {
    if (!result) return;
    setWorking("publish");
    setError("");
    try {
      const payload = await ingestionRequest({
        action: "publish",
        ingestion_id: result.id,
      });
      setDisplayedResult(payload as KnowledgeIngestionResult);
      await onKnowledgeChanged();
    } catch (nextError) {
      setError(
        nextError instanceof Error ? nextError.message : "发布知识版本失败。",
      );
    } finally {
      setWorking(undefined);
    }
  };

  const confirmSuggestedMerge = async () => {
    const summary = result?.flow_candidate_summary;
    if (
      !result?.attack_flow_candidate ||
      !summary?.merge_target_flow_id ||
      !summary.suggested_action_map
    ) return;
    setWorking("revise");
    setError("");
    try {
      const payload = await ingestionRequest({
        action: "revise-flow",
        ingestion_id: result.id,
        attack_flow_candidate: result.attack_flow_candidate,
        merge_review: {
          target_flow_id: summary.merge_target_flow_id,
          confirmed: true,
          action_map: summary.suggested_action_map,
        },
      });
      setDisplayedResult(payload as KnowledgeIngestionResult);
    } catch (nextError) {
      setError(
        nextError instanceof Error ? nextError.message : "确认合并失败。",
      );
    } finally {
      setWorking(undefined);
    }
  };

  const reject = async () => {
    if (!result) return;
    setWorking("reject");
    setError("");
    try {
      const payload = await ingestionRequest({
        action: "reject-flow",
        ingestion_id: result.id,
      });
      setDisplayedResult(payload as KnowledgeIngestionResult);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "拒绝候选失败。")
    } finally {
      setWorking(undefined);
    }
  };

  const rollback = async () => {
    if (!result?.version) return;
    setWorking("rollback");
    setError("");
    try {
      const payload = (await ingestionRequest({
        action: "rollback",
        version_id: result.version.id,
      })) as {
        status: "rolled_back";
        changes: {
          removed_evidence?: number;
          removed_entity_mentions?: number;
        };
        rolled_back_at?: string;
      };
      setDisplayedResult({
        ...result,
        status: "rolled_back",
        graph_write_performed: false,
        version: {
          ...result.version,
          status: "rolled_back",
          changes: {
            ...result.version.changes,
            removed_evidence: payload.changes.removed_evidence,
            removed_entity_mentions: payload.changes.removed_entity_mentions,
          },
          rolled_back_at: payload.rolled_back_at,
        },
      });
      await onKnowledgeChanged();
    } catch (nextError) {
      setError(
        nextError instanceof Error ? nextError.message : "回滚知识版本失败。",
      );
    } finally {
      setWorking(undefined);
    }
  };

  const updateSource = (key: keyof typeof source, value: string) => {
    setSource((current) => ({ ...current, [key]: value }));
    setAttackFlowCandidate(undefined);
    setBatchResult(undefined);
    setResult(undefined);
  };
  const passedGates =
    result?.quality_gates.filter((gate) => gate.status === "pass").length ?? 0;
  const pathOutcome = result?.path_outcome ?? {
    status: "not-run" as const,
    path_count: 0,
    no_path_reason: null,
    detail: "",
  };
  const canonicalEntities = result?.canonical_entities ?? [];
  const canonicalDelta = result?.canonical_delta ?? {
    create_entities: 0,
    merge_entities: 0,
    mentions: 0,
  };
  const entityOnlyOutcome =
    pathOutcome.status === "no-path" || pathOutcome.path_count === 0;
  const documentScope = result?.document_scope ?? {
    scope: "attack-lifecycle-candidate",
    attack_path_eligible: true,
    reason: "",
  };

  return (
    <main className="knowledge-ingestion-page">
      <header className="knowledge-ingestion-hero">
        <div>
          <span>可信知识建设</span>
          <h1>情报入库</h1>
          <p>
            先生成可审计的图谱增量，再以独立版本发布。在线查询结果不会自动进入历史图谱。
          </p>
        </div>
        <div className="ingestion-boundary">
          <ShieldCheck size={18} />
          <div>
            <strong>当前处于暂存通道</strong>
            <span>点击“发布知识版本”前，实体、关系与证据均不会写入历史图谱。</span>
          </div>
        </div>
      </header>

      <div className="knowledge-ingestion-layout">
        <section className="ingestion-source-card">
          <header>
            <div>
              <FileText size={18} />
              <span>01 · 来源材料</span>
            </div>
          </header>
          <div className="ingestion-source-fields">
            <label>
              <span>标题</span>
              <input
                value={source.title}
                onChange={(event) => updateSource("title", event.target.value)}
              />
            </label>
            <label>
              <span>发布机构</span>
              <input
                value={source.publisher}
                onChange={(event) =>
                  updateSource("publisher", event.target.value)
                }
              />
            </label>
            <label className="is-wide">
              <span>原始来源链接</span>
              <input
                value={source.canonical_url}
                onChange={(event) =>
                  updateSource("canonical_url", event.target.value)
                }
              />
            </label>
            <label>
              <span>发布日期</span>
              <input
                type="date"
                value={source.published_at}
                onChange={(event) =>
                  updateSource("published_at", event.target.value)
                }
              />
            </label>
            <label className="ingestion-file-picker">
              <Upload size={15} />
              <span>导入 TXT / MD / JSON</span>
              <input
                type="file"
                accept=".txt,.md,.json,.log,text/plain,application/json"
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (!file) return;
                  void file.text().then((content) => {
                    setSource((current) => ({
                      ...current,
                      title: current.title || file.name,
                      content,
                    }));
                    setAttackFlowCandidate(undefined);
                    setBatchResult(undefined);
                    setResult(undefined);
                  });
                }}
              />
            </label>
          </div>
          <label className="ingestion-content-field">
            <span>情报正文或告警内容</span>
            <textarea
              value={source.content}
              onChange={(event) => updateSource("content", event.target.value)}
            />
          </label>
          <div className="ingestion-stage-row">
            <button
              type="button"
              className="ingestion-stage-action"
              disabled={
                working !== undefined ||
                !source.content.trim() ||
                !source.canonical_url.trim()
              }
              onClick={runStage}
            >
              {working === "stage" ? (
                <LoaderCircle className="is-spinning" size={17} />
              ) : (
                <FileCheck2 size={17} />
              )}
              {attackFlowCandidate ? "生成入库预览" : "自动抽取 AttackFlow"}
            </button>
          </div>
          {error && <p className="ingestion-error">{error}</p>}
        </section>

        <aside className="ingestion-quality-card">
          <header>
            <ShieldCheck size={18} />
            <div>
              <span>02 · 质量门</span>
              <strong>
                {result
                  ? `${passedGates}/${result.quality_gates.length} 项通过`
                  : "等待解析"}
              </strong>
            </div>
          </header>
          {result ? (
            <div className="ingestion-gates">
              {result.quality_gates.map((gate) => (
                <div className={`is-${gate.status}`} key={gate.id}>
                  {gate.status === "pass" ? (
                    <CheckCircle2 size={16} />
                  ) : (
                    <AlertTriangle size={16} />
                  )}
                  <div>
                    <strong>{gate.label}</strong>
                    <span>{gate.detail}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="ingestion-empty-quality">
              <Database size={30} />
              <p>提交来源后检查哈希、来源等级、证据覆盖、实体消歧与关系支撑。</p>
            </div>
          )}
        </aside>
      </div>

      {batchResult && (
        <section className="ingestion-mainline-section">
          <header>
            <div>
              <Layers3 size={18} />
              <span>多活动候选</span>
            </div>
            <strong>{batchResult.candidates.length} 个独立复核任务</strong>
          </header>
          <div className="ingestion-mainline-summary">
            {batchResult.candidates.map((candidate, index) => (
              <button
                type="button"
                className={result?.id === candidate.id ? "is-active" : ""}
                key={candidate.id}
                onClick={() => setResult(candidate)}
              >
                <strong>{String(index + 1).padStart(2, "0")}</strong>
                <span>{candidate.attack_flow_preview?.title || candidate.id}</span>
                <small>
                  {candidate.status === "rejected"
                    ? "已拒绝"
                    : candidate.status === "published"
                      ? "已发布"
                      : candidate.publishable
                        ? "待发布"
                        : "已阻塞"}
                </small>
              </button>
            ))}
          </div>
        </section>
      )}

      {result && (
        <>
          {result.extraction_audit.method ===
            "schema-first-attack-flow-extraction" && (
            <section className="ingestion-no-path-section">
              <header>
                <div>
                  <FileCheck2 size={18} />
                  <span>02 · 抽取审计</span>
                </div>
                <strong>
                  {result.extraction_audit.candidate_count ?? 0} 个规范候选
                </strong>
              </header>
              <div className="ingestion-no-path-body">
                <div>
                  <span>{result.extraction_audit.model || "未记录模型"}</span>
                  <h2>先校验原文和数据规范，再进入复核</h2>
                  <p>
                    局部 ID 已重写；无效引文、实体型 Action 和无证据关系
                    不会进入发布候选。
                  </p>
                </div>
                <dl>
                  <div>
                    <dt>拒绝事实</dt>
                    <dd>{result.extraction_audit.rejected_facts?.length ?? 0}</dd>
                  </div>
                  <div>
                    <dt>未归属证据</dt>
                    <dd>{result.extraction_audit.unassigned_evidence?.length ?? 0}</dd>
                  </div>
                  <div>
                    <dt>断开待复核片段</dt>
                    <dd>{result.extraction_audit.review_fragments?.length ?? 0}</dd>
                  </div>
                </dl>
              </div>
              {((result.extraction_audit.rejected_facts?.length ?? 0) > 0 ||
                (result.extraction_audit.unassigned_evidence?.length ?? 0) > 0 ||
                (result.extraction_audit.review_fragments?.length ?? 0) > 0) && (
                <div className="ingestion-no-path-contracts">
                  {result.extraction_audit.rejected_facts?.map((fact, index) => (
                    <article key={`rejected-${index}`}>
                      <span className="is-create">已拒绝</span>
                      <div>
                        <strong>{fact.fact_type} · {fact.reason}</strong>
                        <small>{JSON.stringify(fact.item).slice(0, 180)}</small>
                      </div>
                    </article>
                  ))}
                  {result.extraction_audit.unassigned_evidence?.map(
                    (evidence, index) => (
                      <article key={`unassigned-${index}`}>
                        <span className="is-reinforce">待归属</span>
                        <div>
                          <strong>{evidence.reason}</strong>
                          <small>{evidence.quote}</small>
                        </div>
                      </article>
                    ),
                  )}
                  {result.extraction_audit.review_fragments?.map(
                    (fragment, index) => (
                      <article key={`fragment-${index}`}>
                        <span className="is-create">待复核</span>
                        <div>
                          <strong>{fragment.candidate_title}</strong>
                          <small>
                            {fragment.actions.map((action) => action.name).join(" → ")}
                          </small>
                        </div>
                      </article>
                    ),
                  )}
                </div>
              )}
            </section>
          )}
          {result.flow_candidate_summary && (
            <section className="ingestion-no-path-section">
              <header>
                <div>
                  <Layers3 size={18} />
                  <span>候选基数与发布建议</span>
                </div>
                <strong>
                  {result.flow_candidate_summary.candidate_count} 个 Flow 候选
                </strong>
              </header>
              <div className="ingestion-no-path-body">
                <div>
                  <span>{result.flow_candidate_summary.status}</span>
                  <h2>
                    {result.flow_candidate_summary.recommendation === "merge"
                      ? `建议合并到 ${result.flow_candidate_summary.merge_target_flow_id}`
                      : result.flow_candidate_summary.recommendation === "create"
                        ? "建议新建独立 AttackFlow"
                        : result.flow_candidate_summary.recommendation === "no-flow"
                          ? "不创建 AttackFlow"
                          : "多个候选需要逐条复核"}
                  </h2>
                  <p>{result.flow_candidate_summary.reason}</p>
                </div>
                <dl>
                  <div>
                    <dt>发布方式</dt>
                    <dd>
                      {result.flow_candidate_summary.recommendation === "no-flow"
                        ? "仅实体证据"
                        : result.publish_mode === "merge"
                          ? "补充来源"
                          : "新建"}
                    </dd>
                  </div>
                </dl>
              </div>
            </section>
          )}
          {pathOutcome.status === "no-path" && (
            <section className="ingestion-no-path-section">
              <header>
                <div>
                  <FileCheck2 size={18} />
                  <span>03 · 分析结果</span>
                </div>
                <strong>无需生成攻击路径</strong>
              </header>
              <div className="ingestion-no-path-body">
                <div>
                  <span>{documentScope.scope}</span>
                  <h2>来源有效，但没有可验证的攻击过程</h2>
                  <p>{pathOutcome.detail}</p>
                </div>
                <dl>
                  <div>
                    <dt>规范实体</dt>
                    <dd>{canonicalEntities.length}</dd>
                  </div>
                  <div>
                    <dt>证据提及</dt>
                    <dd>{canonicalDelta.mentions}</dd>
                  </div>
                  <div>
                    <dt>攻击路径</dt>
                    <dd>0</dd>
                  </div>
                </dl>
              </div>
              <footer>
                <ShieldCheck size={15} />
                原始报告与实体证据可以入库；系统未补写攻击步骤，也未执行后续行为预测。
              </footer>
            </section>
          )}

          {result.attack_flow_preview && (
            <section className="ingestion-mainline-section">
              <header>
                <div>
                  <GitBranch size={18} />
                  <span>03 · AttackFlow 发布预览</span>
                </div>
                <div className="ingestion-mainline-context">
                  <strong>主干与上下文分层</strong>
                  <p>Action 构成主干；IOC、技术和来源归属只作为相关内容挂接。</p>
                </div>
              </header>
              <div className="ingestion-mainline-track">
                {result.attack_flow_preview.mainline.map((actionId, index) => {
                  const action = result.attack_flow_preview?.actions.find(
                    (item) => item.id === actionId,
                  );
                  if (!action) return null;
                  return (
                    <div className="ingestion-mainline-node" key={action.id}>
                      <span>{String(index + 1).padStart(2, "0")}</span>
                      <strong>{action.name}</strong>
                      <small>{action.phase || "未映射阶段"}</small>
                      {action.contexts.map((context) => (
                        <small key={context.id}>
                          {context.name} · {
                            context.resolution.status === "reuse"
                              ? "复用实体"
                              : context.resolution.status === "create"
                                ? "新建实体"
                                : "待消歧"
                          }
                        </small>
                      ))}
                    </div>
                  );
                })}
              </div>
              {result.attack_flow_preview.reported_actors.length > 0 && (
                <footer className="ingestion-mainline-contract">
                  {result.attack_flow_preview.reported_actors.map((actor) => (
                    <span key={actor.id}>
                      来源报告称：{actor.reported_name}
                      {actor.actor_id ? "（已关联组织实体）" : "（未确认归属）"}
                    </span>
                  ))}
                </footer>
              )}
            </section>
          )}

          <section className="ingestion-delta-section">
            <header>
              <div>
                <GitMerge size={18} />
                <span>04 · 图谱增量预览</span>
              </div>
              <strong className={`is-${result.status}`}>
                {result.status === "staged"
                  ? result.publishable
                    ? "仅暂存"
                    : "已阻塞"
                  : result.status === "published"
                    ? "已发布"
                    : result.status === "rejected"
                      ? "已拒绝"
                      : "已回滚"}
              </strong>
            </header>
            <div className="ingestion-delta-metrics">
              {entityOnlyOutcome ? (
                <>
                  <div><span>新增规范实体</span><strong>{canonicalDelta.create_entities}</strong></div>
                  <div><span>复用已有实体</span><strong>{canonicalDelta.merge_entities}</strong></div>
                  <div><span>来源证据提及</span><strong>{canonicalDelta.mentions}</strong></div>
                  <div><span>生成攻击步骤</span><strong>0</strong></div>
                </>
              ) : (
                <>
                  <div><span>新增实体</span><strong>{result.delta.create_entities}</strong></div>
                  <div><span>归并实体</span><strong>{result.delta.merge_entities}</strong></div>
                  <div><span>新增关系</span><strong>{result.delta.create_relationships}</strong></div>
                  <div><span>补强关系</span><strong>{result.delta.reinforce_relationships}</strong></div>
                </>
              )}
            </div>
            <div className="ingestion-delta-grid">
              <section>
                <header>
                  <strong>
                    {entityOnlyOutcome
                      ? "规范实体结果"
                      : "实体消歧结果"}
                  </strong>
                  <span>
                    {entityOnlyOutcome
                      ? canonicalEntities.length
                      : result.entities.length}{" "}
                    项
                  </span>
                </header>
                {(entityOnlyOutcome
                  ? canonicalEntities
                  : result.entities
                ).map((entity) => (
                  <article key={entity.stage_id}>
                    <span className={`is-${entity.decision}`}>
                      {entity.decision === "merge" ? "归并" : "新增"}
                    </span>
                    <div>
                      <strong>{entity.value}</strong>
                      <small>
                        {entity.merge_target_label || "创建新的规范实体"}
                      </small>
                      <q>
                        {"quotes" in entity ? entity.quotes[0] : entity.quote}
                      </q>
                    </div>
                    <b>{Math.round(entity.confidence * 100)}</b>
                  </article>
                ))}
              </section>
              <section>
                <header>
                  <strong>
                    {entityOnlyOutcome
                      ? "本次入库边界"
                      : "关系与证据"}
                  </strong>
                  <span>
                    {entityOnlyOutcome
                      ? pathOutcome.status === "review"
                        ? "实体可用 · 路径待复核"
                        : "不伪造路径"
                      : `${result.relations.length} 项`}
                  </span>
                </header>
                {entityOnlyOutcome ? (
                  <div className="ingestion-no-path-contracts">
                    <article>
                      <span className="is-reinforce">保留</span>
                      <div>
                        <strong>来源文档与原始写法</strong>
                        <small>每个规范实体都可返回原始报告和证据锚点。</small>
                      </div>
                    </article>
                    <article>
                      <span className="is-reinforce">归并</span>
                      <div>
                        <strong>跨报告共享同一实体身份</strong>
                        <small>报告上下文作为提及保存，不再复制 IOC 实体。</small>
                      </div>
                    </article>
                    <article>
                      <span className="is-create">禁止</span>
                      <div>
                        <strong>
                          {pathOutcome.status === "review"
                            ? "把待复核片段标成可用路径"
                            : "把 IOC 清单补写成攻击过程"}
                        </strong>
                        <small>
                          {pathOutcome.status === "review"
                            ? "规范实体可以入库，候选路径继续保留复核状态。"
                            : "没有行为依赖证据时，路径数量保持为零。"}
                        </small>
                      </div>
                    </article>
                  </div>
                ) : result.relations.map((relation) => {
                  const sourceEntity = result.entities.find(
                    (entity) => entity.stage_id === relation.source_stage_id,
                  );
                  const targetEntity = result.entities.find(
                    (entity) => entity.stage_id === relation.target_stage_id,
                  );
                  return (
                    <article key={relation.stage_id}>
                      <span className="is-reinforce">补强</span>
                      <div>
                        <strong>
                          {sourceEntity?.value} → {targetEntity?.value}
                        </strong>
                        <small>{relation.relation_type}</small>
                        <q>{relation.excerpt}</q>
                      </div>
                      <b>{Math.round(relation.confidence * 100)}</b>
                    </article>
                  );
                })}
              </section>
            </div>
          </section>

          <footer className="ingestion-publish-bar">
            <div>
              {result.status === "staged" ? (
                <Database size={19} />
              ) : result.status === "published" ? (
                <Check size={19} />
              ) : result.status === "rejected" ? (
                <AlertTriangle size={19} />
              ) : (
                <RotateCcw size={19} />
              )}
              <div>
                <strong>
                  {result.status === "staged"
                    ? result.publishable
                      ? "尚未写入历史图谱"
                      : "候选存在阻断项"
                    : result.status === "published"
                      ? `知识版本 ${result.version?.id} 已发布`
                      : result.status === "rejected"
                        ? "该候选已拒绝"
                      : "本次知识增量已回滚"}
                </strong>
                <span>
                  {result.status === "staged"
                    ? result.publishable
                      ? "发布将以单一事务写入，失败时不会产生半成品关系。"
                      : "请先修正质量门问题；阻塞候选不会写入历史图谱。"
                    : result.status === "published"
                      ? "新增证据已经参与后续在线查询，可随时回滚。"
                      : result.status === "rejected"
                        ? "候选未写入历史图谱，其他候选不受影响。"
                      : `已移除 ${
                          (result.version?.changes.removed_evidence ?? 0) +
                          (result.version?.changes.removed_entity_mentions ?? 0)
                        } 条版本证据。`}
                </span>
              </div>
            </div>
            <div>
              {result.status === "published" && (
                <>
                  {result.attack_flow_preview && (
                    <button
                      type="button"
                      className="is-secondary"
                      onClick={() =>
                        void onOpenPublishedFlow(
                          result.attack_flow_preview!.flow_id,
                        )
                      }
                    >
                      <GitBranch size={16} /> 查看已发布攻击流
                    </button>
                  )}
                  <button type="button" className="is-secondary" onClick={onOpenGraph}>
                    <Network size={16} /> 查看历史图谱
                  </button>
                  <button
                    type="button"
                    className="is-danger"
                    disabled={working !== undefined}
                    onClick={rollback}
                  >
                    <RotateCcw size={16} /> 回滚版本
                  </button>
                </>
              )}
              {result.status === "staged" && (
                <>
                  {result.publish_mode === "create" &&
                    result.flow_candidate_summary?.recommendation === "merge" && (
                    <button
                      type="button"
                      className="is-secondary"
                      disabled={working !== undefined}
                      onClick={confirmSuggestedMerge}
                    >
                      <GitMerge size={16} /> 按建议合并
                    </button>
                  )}
                  {result.attack_flow_preview && (
                    <button
                      type="button"
                      className="is-danger"
                      disabled={working !== undefined}
                      onClick={reject}
                    >
                      <AlertTriangle size={16} /> 拒绝候选
                    </button>
                  )}
                  <button
                    type="button"
                    disabled={!result.publishable || working !== undefined}
                    onClick={publish}
                  >
                    {working === "publish" ? (
                      <LoaderCircle className="is-spinning" size={16} />
                    ) : (
                      <Database size={16} />
                    )}
                    发布知识版本
                  </button>
                </>
              )}
            </div>
          </footer>
        </>
      )}
    </main>
  );
}
