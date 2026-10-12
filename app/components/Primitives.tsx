"use client";

import { ExternalLink, FileText, ShieldCheck, TriangleAlert } from "lucide-react";
import type { SourceCitation } from "../types";
import { formatDate } from "../argus-domain";

export function StatusBadge({
  status,
  children,
}: {
  status: string;
  children?: React.ReactNode;
}) {
  const tone =
    status === "hot" || status === "confirmed"
      ? "critical"
      : status === "negative" || status === "excluded"
        ? "negative"
        : status === "partial" || status === "candidate"
          ? "warning"
          : "positive";
  const label =
    children ??
    ({
      hot: "高置信",
      positive: "已匹配",
      partial: "待复核",
      negative: "反证",
      matched: "情报匹配",
      confirmed: "已确认",
      candidate: "候选",
      excluded: "已排除",
    }[status] ||
      status);
  return <span className={`status-badge status-${tone}`}>{label}</span>;
}

export function Confidence({ value }: { value: number }) {
  return (
    <span className="confidence">
      <span style={{ width: `${Math.max(4, Math.min(100, value * 100))}%` }} />
      <strong>{Math.round(value * 100)}%</strong>
    </span>
  );
}

export function EmptyState({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="empty-state">
      <TriangleAlert size={22} />
      <strong>{title}</strong>
      <p>{description}</p>
    </div>
  );
}

export function SourceCard({
  citation,
  active,
  onOpen,
}: {
  citation: SourceCitation;
  active?: boolean;
  onOpen: (citation: SourceCitation) => void;
}) {
  return (
    <button
      type="button"
      className={`source-card ${active ? "is-active" : ""}`}
      onClick={() => onOpen(citation)}
    >
      <span className="source-icon">
        <FileText size={16} />
      </span>
      <span>
        <strong>{citation.title}</strong>
        <small>
          {citation.publisher} · {formatDate(citation.reportDate)}
        </small>
      </span>
      <span className="source-confidence">
        {Math.round(citation.confidence * 100)}%
      </span>
    </button>
  );
}

export function SourceViewer({
  citation,
  onClose,
}: {
  citation: SourceCitation;
  onClose: () => void;
}) {
  return (
    <div className="source-viewer-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="source-viewer"
        role="dialog"
        aria-modal="true"
        aria-label="来源证据查看器"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header>
          <div>
            <span className="eyebrow">SOURCE EVIDENCE</span>
            <h2>{citation.title}</h2>
            <p>
              {citation.publisher} · {formatDate(citation.reportDate)} ·{" "}
              {citation.sourceRef || "内部来源"}
            </p>
          </div>
          <button type="button" className="text-button" onClick={onClose}>
            关闭
          </button>
        </header>
        <div className="source-viewer-body">
          <div className="source-location">
            <ShieldCheck size={16} />
            证据位置：{citation.location || "报告相关内容"}
          </div>
          <blockquote>{citation.excerpt}</blockquote>
          <p className="source-note">
            该内容可能是结构化摘录而非逐字引文；请通过原始来源核对完整上下文。
          </p>
        </div>
        <footer>
          <span>证据置信度 {Math.round(citation.confidence * 100)}%</span>
          {citation.externalUrl ? (
            <a href={citation.externalUrl} target="_blank" rel="noreferrer">
              查看原始来源 <ExternalLink size={14} />
            </a>
          ) : (
            <span className="muted">该归档暂无外部原文链接</span>
          )}
        </footer>
      </section>
    </div>
  );
}
