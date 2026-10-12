"use client";

import {
  BookOpenText,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  FileSearch,
  Focus,
  RefreshCw,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  annotationMatchesSelection,
  buildAnnotatedSourceSegments,
} from "../source-annotations";
import type {
  AttackFlowSourceAnnotation,
  AttackFlowSourceAnnotationKind,
  AttackFlowSourceDocumentView,
} from "../types";

const annotationKinds: Array<{
  kind: AttackFlowSourceAnnotationKind;
  label: string;
  description: string;
}> = [
  { kind: "attack-process", label: "攻击过程", description: "行为节点与过程关系" },
  { kind: "ioc", label: "IOC / 基础设施", description: "IP、域名、URL 与哈希" },
  { kind: "software", label: "恶意软件 / 工具", description: "载荷、工具、文件与进程" },
  { kind: "vulnerability", label: "漏洞", description: "CVE 与利用对象" },
  { kind: "asset", label: "资产 / 账户", description: "受影响系统、设备与身份" },
  { kind: "actor", label: "攻击组织", description: "报告中的组织归因表述" },
];

function annotationTitle(annotations: AttackFlowSourceAnnotation[]) {
  return [
    ...new Set(
      annotations.map(
        (annotation) =>
          `${annotationKinds.find((item) => item.kind === annotation.kind)?.label ?? annotation.kind}：${annotation.label}${annotation.action_ids.length ? "" : "（报告级情报）"}`,
      ),
    ),
  ].join("\n");
}

export function AnnotatedSourcePanel({
  flowId,
  selectedActionId,
  selectedEntityId,
  selectedLabel,
  expanded,
  onExpandedChange,
}: {
  flowId: string;
  selectedActionId?: string;
  selectedEntityId?: string;
  selectedLabel?: string;
  expanded: boolean;
  onExpandedChange: (expanded: boolean) => void;
}) {
  const [resource, setResource] = useState<{
    flowId: string;
    status: "loading" | "ready" | "error";
    documents: AttackFlowSourceDocumentView[];
    error: string;
  }>({ flowId, status: "loading", documents: [], error: "" });
  const [selectedDocumentId, setSelectedDocumentId] = useState("");
  const [enabledKinds, setEnabledKinds] = useState<AttackFlowSourceAnnotationKind[]>(
    annotationKinds.map((item) => item.kind),
  );
  const [reloadToken, setReloadToken] = useState(0);
  const documentViewportRef = useRef<HTMLDivElement>(null);
  const activeResource =
    resource.flowId === flowId
      ? resource
      : { flowId, status: "loading" as const, documents: [], error: "" };
  const { documents, error } = activeResource;
  const loading = activeResource.status === "loading";

  useEffect(() => {
    const controller = new AbortController();
    fetch(
      `/api/attack-flows/${encodeURIComponent(flowId)}/source-documents`,
      { headers: { accept: "application/json" }, signal: controller.signal },
    )
      .then(async (response) => {
        const payload = (await response.json()) as
          | AttackFlowSourceDocumentView[]
          | { error?: { message?: string } };
        if (!response.ok || !Array.isArray(payload)) {
          throw new Error(
            !Array.isArray(payload) && payload.error?.message
              ? payload.error.message
              : "原文标注数据不可用。",
          );
        }
        setResource({
          flowId,
          status: "ready",
          documents: payload,
          error: "",
        });
      })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setResource({
          flowId,
          status: "error",
          documents: [],
          error: reason instanceof Error ? reason.message : "无法读取原始报告。",
        });
      });
    return () => controller.abort();
  }, [flowId, reloadToken]);

  const focusMatcher = useCallback(
    (annotation: AttackFlowSourceAnnotation) =>
      annotationMatchesSelection(annotation, selectedActionId, selectedEntityId),
    [selectedActionId, selectedEntityId],
  );

  const selectedDocument =
    documents.find((document) => document.id === selectedDocumentId) ??
    documents.find((document) => document.annotations.some(focusMatcher)) ??
    documents[0];
  const visibleAnnotations = useMemo(
    () =>
      selectedDocument?.annotations.filter((annotation) =>
        enabledKinds.includes(annotation.kind),
      ) ?? [],
    [enabledKinds, selectedDocument],
  );
  const segments = useMemo(
    () =>
      selectedDocument
        ? buildAnnotatedSourceSegments(selectedDocument.content, visibleAnnotations)
        : [],
    [selectedDocument, visibleAnnotations],
  );
  const focusedAnnotationCount = visibleAnnotations.filter(focusMatcher).length;
  const kindCounts = useMemo(
    () =>
      Object.fromEntries(
        annotationKinds.map(({ kind }) => [
          kind,
          selectedDocument?.annotations.filter(
            (annotation) => annotation.kind === kind,
          ).length ?? 0,
        ]),
      ) as Record<AttackFlowSourceAnnotationKind, number>,
    [selectedDocument],
  );

  useEffect(() => {
    if (!expanded || !focusedAnnotationCount) return;
    const frame = window.requestAnimationFrame(() => {
      const viewport = documentViewportRef.current;
      const target = viewport?.querySelector<HTMLElement>(
        "[data-source-focus='true']",
      );
      if (!viewport || !target) return;
      viewport.scrollTo({
        top: Math.max(0, target.offsetTop - viewport.clientHeight / 2),
        behavior: "smooth",
      });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [expanded, focusMatcher, focusedAnnotationCount, selectedDocumentId]);

  const toggleKind = (kind: AttackFlowSourceAnnotationKind) => {
    setEnabledKinds((current) =>
      current.includes(kind)
        ? current.filter((item) => item !== kind)
        : [...current, kind],
    );
  };

  return (
    <section
      className={`annotated-source-panel ${expanded ? "is-expanded" : "is-collapsed"}`}
      aria-label="原文提取对照"
    >
      <header className="annotated-source-heading">
        <div className="annotated-source-title">
          <span className="annotated-source-icon"><BookOpenText size={18} /></span>
          <div>
            <span>提取结果校验</span>
            <h2>原文提取对照</h2>
            <p>颜色同时标记攻击流证据与报告级实体；报告级情报会保留，但不会被强行挂到攻击节点。</p>
          </div>
        </div>
        <div className="annotated-source-heading-actions">
          {selectedDocument && (
            <div className="annotated-source-summary">
              <strong>{selectedDocument.annotations.length}</strong>
              <span>处情报标注</span>
              <small>{documents.length} 份来源报告</small>
            </div>
          )}
          <button
            type="button"
            className="annotated-source-toggle"
            aria-expanded={expanded}
            onClick={() => onExpandedChange(!expanded)}
          >
            {expanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
            {expanded ? "隐藏原文" : "展开原文"}
          </button>
        </div>
      </header>

      {!expanded ? null : loading ? (
        <div className="annotated-source-loading" aria-label="正在读取原文">
          <span />
          <span />
          <span />
        </div>
      ) : error ? (
        <div className="annotated-source-error">
          <FileSearch size={20} />
          <div><strong>原文暂时无法读取</strong><p>{error}</p></div>
          <button
            type="button"
            onClick={() => {
              setResource({ flowId, status: "loading", documents: [], error: "" });
              setReloadToken((value) => value + 1);
            }}
          >
            <RefreshCw size={14} /> 重试
          </button>
        </div>
      ) : !selectedDocument ? (
        <div className="annotated-source-empty">该攻击流尚未关联可读取的归档原文。</div>
      ) : (
        <div className="annotated-source-workspace">
          <aside className="annotated-source-documents" aria-label="来源报告">
            <span className="annotated-source-aside-label">来源报告</span>
            {documents.map((document, index) => (
              <button
                type="button"
                key={document.id}
                className={document.id === selectedDocument.id ? "is-active" : ""}
                onClick={() => setSelectedDocumentId(document.id)}
              >
                <span>{String(index + 1).padStart(2, "0")}</span>
                <div>
                  <strong>{document.title}</strong>
                  <small>{document.publisher} · {document.annotations.length} 处标注</small>
                </div>
              </button>
            ))}
          </aside>

          <article className="annotated-source-document">
            <div className="annotated-source-document-head">
              <div>
                <span>{selectedDocument.publisher} · {selectedDocument.published_at}</span>
                <h3>{selectedDocument.title}</h3>
              </div>
              {selectedDocument.canonical_url && (
                <a href={selectedDocument.canonical_url} target="_blank" rel="noreferrer">
                  原始来源 <ExternalLink size={13} />
                </a>
              )}
            </div>

            <div className="annotated-source-legend" aria-label="原文标注图例">
              {annotationKinds.map((item) => (
                <button
                  type="button"
                  key={item.kind}
                  className={`annotation-filter annotation-${item.kind} ${
                    enabledKinds.includes(item.kind) ? "is-active" : ""
                  }`}
                  aria-pressed={enabledKinds.includes(item.kind)}
                  title={item.description}
                  onClick={() => toggleKind(item.kind)}
                  disabled={kindCounts[item.kind] === 0}
                >
                  <span /> {item.label} <b>{kindCounts[item.kind]}</b>
                </button>
              ))}
            </div>

            {(selectedActionId || selectedEntityId) && (
              <div className={`annotated-source-focus ${focusedAnnotationCount ? "has-match" : ""}`}>
                <Focus size={15} />
                <span>
                  当前图谱节点：<strong>{selectedLabel || "已选节点"}</strong>
                </span>
                <b>{focusedAnnotationCount ? `定位 ${focusedAnnotationCount} 处` : "当前报告未单独标注"}</b>
              </div>
            )}

            <div className="annotated-source-viewport" ref={documentViewportRef}>
              <div className="annotated-source-content">
                {segments.map((segment) => {
                  if (!segment.primaryKind) {
                    return <span key={`${segment.start}-${segment.end}`}>{segment.text}</span>;
                  }
                  const focused = segment.annotations.some(focusMatcher);
                  return (
                    <mark
                      key={`${segment.start}-${segment.end}`}
                      className={`source-annotation annotation-${segment.primaryKind} ${
                        focused ? "is-focused" : ""
                      } ${segment.annotations.length > 1 ? "has-overlap" : ""}`}
                      data-source-focus={focused ? "true" : undefined}
                      title={annotationTitle(segment.annotations)}
                    >
                      {segment.text}
                    </mark>
                  );
                })}
              </div>
            </div>
          </article>
        </div>
      )}
    </section>
  );
}
