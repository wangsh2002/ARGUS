"use client";

import {
  ArrowRight,
  Bot,
  CalendarDays,
  FileSearch,
  GitBranch,
  Search,
  ShieldAlert,
  Upload,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { formatDate, getChainParts } from "../argus-domain";
import {
  analysisInputForReport,
  buildSearchExamples,
  normalizedFlowSourceRef,
  type SearchExample,
} from "../search-recommendations";
import {
  curatedHomeReports,
  curatedIntelReportTitles,
  curatedPathReportTitles,
} from "../showcase-config";
import type { AttackFlow, Report, RuntimeCatalog, SearchMode } from "../types";

function selectReports(
  reports: Report[],
  titles: string[],
  fallback: Report[],
  limit: number,
) {
  const selected = titles.flatMap((title) => {
    const report = reports.find((candidate) => candidate.title === title);
    return report ? [report] : [];
  });
  fallback.forEach((report) => {
    if (
      selected.length < limit &&
      !selected.some((candidate) => candidate.id === report.id)
    ) {
      selected.push(report);
    }
  });
  return selected.slice(0, limit);
}

const modes: Array<{
  id: SearchMode;
  label: string;
  icon: typeof Search;
}> = [
  {
    id: "intel",
    label: "综合情报查询",
    icon: ShieldAlert,
  },
  {
    id: "path",
    label: "攻击路径研判",
    icon: GitBranch,
  },
  {
    id: "gpt",
    label: "ARGUS GPT",
    icon: Bot,
  },
];

export function SearchView({
  data,
  attackFlows,
  query,
  mode,
  onQuery,
  onMode,
  onSubmit,
  onOpenReport,
}: {
  data: RuntimeCatalog;
  attackFlows: AttackFlow[];
  query: string;
  mode: SearchMode;
  onQuery: (value: string) => void;
  onMode: (mode: SearchMode) => void;
  onSubmit: () => void;
  onOpenReport: (report: Report) => void;
}) {
  const inputRef = useRef<HTMLInputElement | HTMLTextAreaElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const consoleRef = useRef<HTMLDivElement>(null);
  const [assistOpen, setAssistOpen] = useState(false);
  const [uploadedFileName, setUploadedFileName] = useState("");
  const [pathRawOpen, setPathRawOpen] = useState(true);
  const visibleMode = mode === "graph" ? "intel" : mode;
  const examples: SearchExample[] = buildSearchExamples(
    visibleMode,
    data,
    attackFlows,
  );
  const pathParts = visibleMode === "path" ? getChainParts(query) : [];
  const reportFlowQuality = new Map<string, number>();
  const reportFlowCounts = new Map<string, number>();
  const reportActionCounts = new Map<string, number>();
  const reportEvidenceIds = new Map<string, Set<string>>();
  attackFlows.forEach((flow) => {
    const contextCount = flow.actions.reduce(
      (total, action) => total + action.contexts.length,
      0,
    );
    const quality =
      flow.actions.length * 5 +
      Math.min(contextCount, flow.actions.length * 4) +
      flow.reported_actors.length * 5;
    new Set(flow.sources.map((source) => normalizedFlowSourceRef(source.id))).forEach(
      (sourceRef) => {
      reportFlowQuality.set(
          sourceRef,
          (reportFlowQuality.get(sourceRef) ?? 0) + quality,
      );
        reportFlowCounts.set(
          sourceRef,
          (reportFlowCounts.get(sourceRef) ?? 0) + 1,
        );
        reportActionCounts.set(
          sourceRef,
          (reportActionCounts.get(sourceRef) ?? 0) + flow.actions.length,
        );
        const evidenceIds = reportEvidenceIds.get(sourceRef) ?? new Set<string>();
        flow.actions.forEach((action) => {
          action.evidence.forEach((evidence) => evidenceIds.add(evidence.id));
          action.contexts.forEach((context) =>
            context.evidence.forEach((evidence) => evidenceIds.add(evidence.id)),
          );
        });
        flow.reported_actors.forEach((actor) =>
          actor.evidence.forEach((evidence) => evidenceIds.add(evidence.id)),
        );
        reportEvidenceIds.set(sourceRef, evidenceIds);
      },
    );
  });
  const rankedReports = [...data.reports]
    .filter((report) => (reportFlowQuality.get(report.source_ref) ?? 0) > 0)
    .sort(
      (left, right) =>
        (visibleMode === "path"
          ? Number((reportFlowCounts.get(right.source_ref) ?? 0) > 1) -
            Number((reportFlowCounts.get(left.source_ref) ?? 0) > 1)
          : 0) ||
        (reportFlowQuality.get(right.source_ref) ?? 0) -
          (reportFlowQuality.get(left.source_ref) ?? 0) ||
        right.report_date.localeCompare(left.report_date),
    );
  const recommendedReports = selectReports(
    data.reports,
    visibleMode === "path"
      ? curatedPathReportTitles
      : curatedIntelReportTitles,
    rankedReports,
    visibleMode === "path" ? 2 : 5,
  );
  const qualityReports = [...data.reports]
    .filter((report) => (reportFlowQuality.get(report.source_ref) ?? 0) > 0)
    .sort(
      (left, right) =>
        (reportFlowQuality.get(right.source_ref) ?? 0) -
          (reportFlowQuality.get(left.source_ref) ?? 0) ||
        right.report_date.localeCompare(left.report_date),
    );
  const historicalFallback = qualityReports.length
    ? qualityReports
    : [...data.reports]
        .filter((report) => report.assessment)
        .sort((left, right) => right.report_date.localeCompare(left.report_date));
  const historicalReports = selectReports(
    data.reports,
    curatedHomeReports.map((report) => report.title),
    historicalFallback,
    6,
  );
  const reportShowcaseNotes = new Map(
    curatedHomeReports.map((report) => [report.title, report.note]),
  );
  const reportPathInput = (sourceRef: string) => {
    const report = data.reports.find((candidate) => candidate.source_ref === sourceRef);
    return report ? analysisInputForReport(report, attackFlows) : "";
  };
  const loadAnalysisFile = async (file?: File) => {
    if (!file) return;
    onQuery(await file.text());
    setUploadedFileName(file.name);
    setPathRawOpen(false);
    setAssistOpen(true);
  };

  useEffect(() => {
    const closeOnOutsidePress = (event: PointerEvent) => {
      if (
        consoleRef.current &&
        !consoleRef.current.contains(event.target as Node)
      ) {
        setAssistOpen(false);
        inputRef.current?.blur();
      }
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setAssistOpen(false);
      inputRef.current?.blur();
    };

    document.addEventListener("pointerdown", closeOnOutsidePress);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsidePress);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, []);

  const openPathRawInput = () => {
    setPathRawOpen(true);
    window.requestAnimationFrame(() => inputRef.current?.focus());
  };

  const pathModeActive = visibleMode === "path";
  const pathMaterialLoaded = pathModeActive && pathParts.length > 0;
  const heroTitle = pathModeActive
    ? "攻击路径研判"
    : "威胁情报查询与分析平台";
  const heroDescription = pathModeActive
    ? "输入告警、日志或情报报告，关联分散线索，补全缺失步骤并预测后续行为。"
    : "查询真实情报、历史报告与关系证据，并回到每一条原始来源。";

  return (
    <main className={`search-page search-mode-${visibleMode}`}>
      <section className="search-hero">
        <div className="hero-copy">
          <span className="hero-emblem" aria-hidden="true">
            <GitBranch size={27} />
          </span>
          <h1>{heroTitle}</h1>
          <p>{heroDescription}</p>
        </div>

        <div className="query-console-anchor">
          <div
            ref={consoleRef}
            className={`query-console is-mode-${visibleMode} ${
              assistOpen ? "is-expanded" : ""
            }`}
          >
            <form
              className={`hero-search ${visibleMode === "path" ? "is-path-query" : ""}`}
              onSubmit={(event) => {
                event.preventDefault();
                onSubmit();
              }}
            >
              <div className="query-input-row">
                <Search size={21} />
                {pathModeActive && pathMaterialLoaded && !pathRawOpen ? (
                  <button
                    type="button"
                    className="path-loaded-summary"
                    aria-label="查看或编辑原始内容"
                    onClick={openPathRawInput}
                  >
                    <span>
                      {uploadedFileName || "已载入输入材料"}
                    </span>
                    <strong>{pathParts.length} 条输入线索已识别</strong>
                    <small>查看或编辑原始内容</small>
                  </button>
                ) : pathModeActive ? (
                  <textarea
                    ref={(node) => {
                      inputRef.current = node;
                    }}
                    rows={3}
                    aria-label="攻击路径查询输入"
                    aria-controls="search-assist-panel"
                    value={query}
                    onFocus={() => setAssistOpen(true)}
                    onClick={() => setAssistOpen(true)}
                    onChange={(event) => {
                      onQuery(event.target.value);
                      setPathRawOpen(true);
                      setAssistOpen(true);
                    }}
                    placeholder="粘贴一条或多条告警、日志、IOC 或完整情报文本，也可以上传文件"
                  />
                ) : (
                  <input
                    ref={(node) => {
                      inputRef.current = node;
                    }}
                    aria-label="综合查询输入"
                    aria-controls="search-assist-panel"
                    value={query}
                    onFocus={() => setAssistOpen(true)}
                    onClick={() => setAssistOpen(true)}
                    onChange={(event) => {
                      onQuery(event.target.value);
                      setAssistOpen(true);
                    }}
                    placeholder={
                      visibleMode === "gpt"
                        ? "向 ARGUS GPT 询问报告或威胁情报"
                        : "搜索 IP、域名、Hash、URL、CVE、攻击组织或历史报告"
                    }
                  />
                )}
                <button
                  type="submit"
                  aria-label={
                    pathModeActive ? "开始攻击路径研判" : "执行查询"
                  }
                  disabled={!query.trim()}
                >
                  {pathModeActive ? "开始研判" : "查询"}{" "}
                  <ArrowRight size={16} />
                </button>
              </div>
              <input
                ref={fileRef}
                hidden
                type="file"
                accept=".txt,.log,.json,.csv,.md,.xml,.html,application/json,text/plain,text/csv"
                onChange={(event) =>
                  loadAnalysisFile(event.target.files?.[0])
                }
              />
            </form>

            <section
              id="search-assist-panel"
              className="search-assist-panel"
              aria-label="搜索历史和推荐"
              aria-hidden={!assistOpen}
              inert={assistOpen ? undefined : true}
            >
              <div
                className="query-mode-tabs"
                role="tablist"
                aria-label="查询模式"
              >
                {modes.map((item) => {
                  const Icon = item.icon;
                  return (
                    <button
                      type="button"
                      role="tab"
                      aria-selected={visibleMode === item.id}
                      className={visibleMode === item.id ? "active" : ""}
                      key={item.id}
                      onClick={() => {
                        onMode(item.id);
                        setAssistOpen(true);
                      }}
                    >
                      <Icon size={15} />
                      <span>{item.label}</span>
                    </button>
                  );
                })}
              </div>

              {visibleMode === "path" && (
                <div
                  className={`path-query-preview ${
                    pathParts.length ? "has-input" : "is-empty"
                  }`}
                  aria-live="polite"
                >
                  <div className="path-query-summary">
                    <strong>
                      {pathParts.length
                        ? `已识别 ${pathParts.length} 条输入线索`
                        : "提供研判材料"}
                    </strong>
                    <span>
                      {pathParts.length
                        ? uploadedFileName || "来自粘贴内容"
                        : "不要求输入完整攻击链"}
                    </span>
                  </div>
                  <div className="path-input-tools">
                    <button
                      type="button"
                      className="is-upload"
                      onClick={() => fileRef.current?.click()}
                    >
                      <Upload size={14} />
                      上传文件
                    </button>
                  </div>
                  {pathParts.length ? (
                    <ol>
                      {pathParts.map((part, index) => (
                        <li key={`${part}-${index}`}>{part}</li>
                      ))}
                    </ol>
                  ) : (
                    <p>
                      可以只输入已知的一部分。系统会区分输入命中、路径补全和后续预测结果。
                      支持 TXT、LOG、JSON、CSV 与 Markdown。
                    </p>
                  )}
                </div>
              )}

              <div className="search-assist-grid">
                <div className="search-assist-column">
                  <header>
                    <Search size={16} />
                    <h2>
                      {visibleMode === "path" ? "告警输入示例" : "推荐搜索"}
                    </h2>
                  </header>
                  <div className="assist-example-list">
                    {examples.map((example) => (
                      <button
                        type="button"
                        key={example.query}
                        onClick={() => {
                          onQuery(example.query);
                          if (visibleMode === "path") {
                            setUploadedFileName("");
                            setPathRawOpen(true);
                          }
                          inputRef.current?.focus();
                        }}
                      >
                        <Search size={14} />
                        <span>
                          <strong>{example.label}</strong>
                          <small>{example.note}</small>
                        </span>
                        <ArrowRight size={13} />
                      </button>
                    ))}
                  </div>
                </div>

                <div className="search-assist-column">
                  <header>
                    <FileSearch size={16} />
                    <h2>
                      {visibleMode === "path" ? "从情报报告开始" : "近期报告"}
                    </h2>
                  </header>
                  <div className="assist-report-list">
                    {recommendedReports.map((report) => (
                      <button
                        type="button"
                        key={report.id}
                        onClick={() => {
                          onQuery(
                            visibleMode === "path"
                              ? reportPathInput(report.source_ref) || report.title
                              : report.title,
                          );
                          if (visibleMode === "path") {
                            setUploadedFileName(report.title);
                            setPathRawOpen(false);
                          }
                          inputRef.current?.focus();
                        }}
                      >
                        <span>
                          <strong>{report.title}</strong>
                          <small>
                            {report.source} · {formatDate(report.report_date)}
                          </small>
                        </span>
                        <ArrowRight size={13} />
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </section>
          </div>
        </div>
      </section>

      {visibleMode === "intel" && historicalReports.length > 0 && (
        <section
          className="home-report-history"
          aria-labelledby="home-report-history-title"
        >
          <header>
            <div>
              <span className="eyebrow">COMPLETED ANALYSIS</span>
              <h2 id="home-report-history-title">历史研判报告</h2>
              <p>继续查看已完成的分析，保留来源、研判结论与攻击路径上下文。</p>
            </div>
            <span className="home-report-count">
              {historicalReports.length} 份精选记录
            </span>
          </header>

          <div className="home-report-history-list">
            {historicalReports.map((report, index) => (
              <button
                type="button"
                className={`home-report-card${index === 0 ? " is-featured" : ""}`}
                key={report.id}
                onClick={() => onOpenReport(report)}
              >
                <span className="home-report-date">
                  <CalendarDays size={15} />
                  <time dateTime={report.report_date}>
                    {formatDate(report.report_date)}
                  </time>
                </span>
                <span className="home-report-summary">
                  <small>{report.source}</small>
                  <strong>{report.title}</strong>
                  <span>
                    {(reportFlowCounts.get(report.source_ref) ?? 0) > 0
                      ? `${reportFlowCounts.get(report.source_ref)} 条攻击流 · ${reportActionCounts.get(report.source_ref) ?? 0} 个攻击步骤 · ${reportEvidenceIds.get(report.source_ref)?.size ?? 0} 条证据${reportShowcaseNotes.get(report.title) ? ` · ${reportShowcaseNotes.get(report.title)}` : ""}`
                      : report.assessment}
                  </span>
                </span>
                <span className="home-report-action">
                  打开研判 <ArrowRight size={14} />
                </span>
              </button>
            ))}
          </div>
        </section>
      )}

    </main>
  );
}
