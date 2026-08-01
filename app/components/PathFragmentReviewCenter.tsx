"use client";

import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCheck,
  ExternalLink,
  FileText,
  GitBranch,
  LoaderCircle,
  RefreshCw,
  ShieldCheck,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { KnowledgeIngestionResult } from "../types";


type AttackFlowReviewItem = KnowledgeIngestionResult & {
  ingestion_kind: "attack-flow";
  attack_flow_preview: NonNullable<KnowledgeIngestionResult["attack_flow_preview"]>;
};

type AttackFlowReviewQueue = {
  items: AttackFlowReviewItem[];
  summary: {
    pending_flows: number;
    publishable_flows: number;
    blocked_flows: number;
    source_documents: number;
  };
};


async function requestQueue(): Promise<AttackFlowReviewQueue> {
  const response = await fetch("/api/knowledge-ingestion", {
    headers: { accept: "application/json" },
    cache: "no-store",
  });
  const payload = (await response.json()) as
    | AttackFlowReviewQueue
    | { error?: { message?: string } };
  if (!response.ok || !("items" in payload)) {
    throw new Error(
      "error" in payload
        ? payload.error?.message || "AttackFlow 待审队列暂时不可用。"
        : "AttackFlow 待审队列暂时不可用。",
    );
  }
  return payload;
}


async function reviewCandidate(
  action: "publish" | "reject-flow",
  ingestionId: string,
) {
  const response = await fetch("/api/knowledge-ingestion", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      action,
      ingestion_id: ingestionId,
    }),
  });
  const payload = (await response.json()) as {
    error?: { message?: string };
  };
  if (!response.ok || payload.error) {
    throw new Error(payload.error?.message || "AttackFlow 审核操作失败。");
  }
}


export function PathFragmentReviewCenter() {
  const [queue, setQueue] = useState<AttackFlowReviewQueue>();
  const [selectedId, setSelectedId] = useState<string>();
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState<"publish" | "reject-flow">();
  const [error, setError] = useState<string>();

  const refresh = async () => {
    setLoading(true);
    setError(undefined);
    try {
      const next = await requestQueue();
      setQueue(next);
      setSelectedId((current) =>
        next.items.some((item) => item.id === current)
          ? current
          : next.items[0]?.id,
      );
    } catch (nextError) {
      setError(
        nextError instanceof Error
          ? nextError.message
          : "AttackFlow 待审队列暂时不可用。",
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = window.setTimeout(() => void refresh(), 0);
    return () => window.clearTimeout(timer);
  }, []);

  const selected = useMemo(
    () =>
      queue?.items.find((item) => item.id === selectedId) ??
      queue?.items[0],
    [queue, selectedId],
  );

  const act = async (action: "publish" | "reject-flow") => {
    if (!selected) return;
    setWorking(action);
    setError(undefined);
    try {
      await reviewCandidate(action, selected.id);
      await refresh();
    } catch (nextError) {
      setError(
        nextError instanceof Error ? nextError.message : "AttackFlow 审核操作失败。",
      );
    } finally {
      setWorking(undefined);
    }
  };

  return (
    <main className="fragment-review-page">
      <header className="fragment-review-header">
        <div>
          <span className="fragment-review-kicker">
            <ClipboardCheck size={17} />
            AttackFlow 治理
          </span>
          <h1>路径复核</h1>
          <p>只处理已暂存、通过证据质量门的 AttackFlow 候选。</p>
        </div>
        <button type="button" onClick={() => void refresh()} disabled={loading}>
          <RefreshCw size={15} className={loading ? "is-spinning" : ""} />
          刷新队列
        </button>
      </header>

      <section className="fragment-review-summary" aria-label="AttackFlow 复核队列统计">
        <div><span>待复核 Flow</span><strong>{queue?.summary.pending_flows ?? 0}</strong></div>
        <div><span>可发布</span><strong>{queue?.summary.publishable_flows ?? 0}</strong></div>
        <div><span>质量门阻断</span><strong>{queue?.summary.blocked_flows ?? 0}</strong></div>
        <div><span>来源文档</span><strong>{queue?.summary.source_documents ?? 0}</strong></div>
      </section>

      {error && (
        <div className="fragment-review-error" role="alert">
          <AlertTriangle size={16} />
          <span>{error}</span>
          <button type="button" onClick={() => void refresh()}>重试</button>
        </div>
      )}

      {loading && !queue ? (
        <section className="fragment-review-loading" aria-label="正在加载 AttackFlow 复核队列">
          <LoaderCircle size={20} className="is-spinning" />
          <strong>正在读取待复核 AttackFlow</strong>
          <span>系统正在读取主干、Context、证据和质量门。</span>
        </section>
      ) : !selected ? (
        <section className="fragment-review-empty">
          <CheckCircle2 size={34} />
          <strong>当前没有待复核 AttackFlow</strong>
          <span>新的抽取候选会在情报入库暂存后出现。</span>
        </section>
      ) : (
        <section className="fragment-review-workspace">
          <aside className="fragment-review-queue" aria-label="待复核 AttackFlow">
            <header><strong>待审核</strong><span>{queue?.items.length ?? 0} 个 Flow</span></header>
            <div>
              {queue?.items.map((item) => (
                <button
                  type="button"
                  key={item.id}
                  className={item.id === selected.id ? "is-selected" : ""}
                  onClick={() => setSelectedId(item.id)}
                >
                  <span className="fragment-review-source">{item.source_document_id}</span>
                  <strong>{item.attack_flow_preview.title}</strong>
                  <small>{item.attack_flow_preview.actions.length} 个 Action · {item.attack_flow_preview.relations.length} 条关系</small>
                  <footer>
                    <span>{item.publishable ? <CheckCircle2 size={12} /> : <AlertTriangle size={12} />}{item.publishable ? "可发布" : "已阻断"}</span>
                  </footer>
                </button>
              ))}
            </div>
          </aside>

          <section className="fragment-review-canvas">
            <header>
              <div><span>AttackFlow V1</span><h2>{selected.attack_flow_preview.title}</h2></div>
              <strong><GitBranch size={14} />显式主干 {selected.attack_flow_preview.mainline.length} 步</strong>
            </header>
            <div className="fragment-review-path">
              {selected.attack_flow_preview.mainline.map((actionId) => {
                const action = selected.attack_flow_preview.actions.find((item) => item.id === actionId);
                if (!action) return null;
                return (
                  <div className="fragment-review-path-step" key={action.id}>
                    <article>
                      <span>{action.phase || "未映射阶段"}</span>
                      <strong>{action.name}</strong>
                      <small>{action.contexts.map((context) => context.name).join("、") || "无附加 Context"}</small>
                    </article>
                  </div>
                );
              })}
            </div>
            <div className="fragment-review-issues">
              <header><div><ShieldCheck size={15} /><strong>质量门</strong></div><span>发布前确认</span></header>
              <div>
                {selected.quality_gates.map((gate) => (
                  <article key={gate.id}>
                    <span>{gate.status === "pass" ? "通过" : gate.status === "warn" ? "提示" : "阻断"}</span>
                    <div><strong>{gate.label}</strong><small>{gate.detail}</small></div>
                  </article>
                ))}
              </div>
            </div>
          </section>

          <aside className="fragment-review-evidence" aria-label="AttackFlow 审核操作">
            <header><span>来源与证据</span><strong>{selected.publishable ? "可发布" : "需修订或拒绝"}</strong></header>
            <section className="fragment-review-quotes">
              {selected.attack_flow_candidate?.actions.slice(0, 4).map((action) => (
                <article key={action.id}><span>{action.name}</span><q>{action.evidence[0]?.quote || "缺少引文"}</q></article>
              ))}
            </section>
            <section className="fragment-review-report">
              <FileText size={15} />
              <div><strong>{selected.source_document_id}</strong><span>原文已归档并固定哈希</span></div>
              {selected.attack_flow_candidate?.actions[0]?.evidence[0]?.quote && <ExternalLink size={15} />}
            </section>
            <div className="fragment-review-actions">
              <button type="button" className="is-primary" disabled={Boolean(working) || !selected.publishable} onClick={() => void act("publish")}>
                {working === "publish" ? <LoaderCircle size={15} className="is-spinning" /> : <CheckCircle2 size={15} />}
                发布 AttackFlow
              </button>
              <button type="button" className="is-danger" disabled={Boolean(working)} onClick={() => void act("reject-flow")}>
                {working === "reject-flow" ? <LoaderCircle size={15} className="is-spinning" /> : <X size={15} />}
                拒绝候选
              </button>
            </div>
          </aside>
        </section>
      )}
    </main>
  );
}
