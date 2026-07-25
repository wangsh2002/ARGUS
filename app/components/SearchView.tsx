"use client";

import {
  ArrowRight,
  Bot,
  Database,
  FileSearch,
  GitBranch,
  Network,
  Search,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import type { InvestigationCase, SearchMode, Snapshot } from "../types";
import { formatDate } from "../argus-domain";

const modes: Array<{
  id: SearchMode;
  label: string;
  description: string;
  icon: typeof Search;
}> = [
  { id: "intel", label: "情报查询", description: "IOC 与实体", icon: ShieldAlert },
  { id: "chain", label: "攻击链", description: "时序研判", icon: GitBranch },
  { id: "graph", label: "Graph", description: "关系探索", icon: Network },
  { id: "gpt", label: "GPT", description: "安全问答", icon: Bot },
];

export function SearchView({
  data,
  query,
  mode,
  cases,
  onQuery,
  onMode,
  onSubmit,
  onOpenCase,
  onOpenReport,
}: {
  data: Snapshot;
  query: string;
  mode: SearchMode;
  cases: InvestigationCase[];
  onQuery: (value: string) => void;
  onMode: (mode: SearchMode) => void;
  onSubmit: () => void;
  onOpenCase: (investigation: InvestigationCase) => void;
  onOpenReport: (reportId: string) => void;
}) {
  const verifiableReports = [...data.reports].sort(
    (left, right) =>
      Number(Boolean(right.external_url)) - Number(Boolean(left.external_url)) ||
      right.report_date.localeCompare(left.report_date),
  );
  const examples =
    mode === "chain"
      ? ["Outlook 提醒 → 远程 SMB → NTLM 泄露", "H10 Cisco 路由器与 Jaguar Tooth"]
      : mode === "graph"
        ? ["APT28", "Jaguar Tooth", "CVE-2017-6742"]
        : mode === "gpt"
          ? ["总结这批证据中的攻击链", "哪些节点仍缺少来源支持？"]
          : ["cdn-meeting-update.com", "CVE-2017-6742", "APT28"];

  return (
    <main className="search-page">
      <section className="search-hero">
        <div className="hero-copy">
          <span className="hero-emblem" aria-hidden="true">
            <GitBranch size={28} />
          </span>
          <span className="eyebrow">
            <span className="pulse-mark" />
            TRACEABLE THREAT INTELLIGENCE
          </span>
          <h1>
            从零散证据
            <br />
            还原完整攻击链
          </h1>
          <p>
            查询威胁情报、连接历史证据，并把每一步结论追溯到真实来源。
          </p>
        </div>

        <div className="query-console">
          <div className="query-mode-tabs" role="tablist" aria-label="查询模式">
            {modes.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  type="button"
                  role="tab"
                  aria-selected={mode === item.id}
                  className={mode === item.id ? "active" : ""}
                  key={item.id}
                  onClick={() => onMode(item.id)}
                >
                  <Icon size={17} />
                  <span>
                    <strong>{item.label}</strong>
                    <small>{item.description}</small>
                  </span>
                </button>
              );
            })}
          </div>
          <form
            className="hero-search"
            onSubmit={(event) => {
              event.preventDefault();
              onSubmit();
            }}
          >
            <Search size={21} />
            <input
              aria-label="综合查询输入"
              value={query}
              onChange={(event) => onQuery(event.target.value)}
              placeholder={
                mode === "chain"
                  ? "输入攻击步骤、事件名称或粘贴一段安全记录"
                  : mode === "gpt"
                    ? "向 ARGUS GPT 提出安全分析问题"
                    : "输入 IP、域名、Hash、URL、CVE 或自然语言"
              }
            />
            <button type="submit" aria-label="执行查询" disabled={!query.trim()}>
              分析 <ArrowRight size={16} />
            </button>
          </form>
          <div className="query-examples">
            <span>试试：</span>
            {examples.map((example) => (
              <button type="button" key={example} onClick={() => onQuery(example)}>
                {example}
              </button>
            ))}
          </div>
          <div className="truth-note">
            <Database size={15} />
            只返回已入库实体、关系与来源证据；缺失信息不会被补造。
          </div>
        </div>
      </section>

      <section className="home-overview">
        <div className="home-stats">
          {[
            ["情报实体", data.stats.entities, "entities"],
            ["可追溯关系", data.stats.relationships, "relations"],
            ["攻击步骤", data.stats.attack_steps, "chain"],
            ["来源报告", data.stats.reports, "reports"],
          ].map(([label, value, id]) => (
            <article key={id}>
              <span>{label}</span>
              <strong>{Number(value).toLocaleString("zh-CN")}</strong>
              <small>当前真实快照</small>
            </article>
          ))}
        </div>

        <div className="home-grid">
          <section className="home-card recent-cases">
            <header>
              <div>
                <span className="eyebrow">INVESTIGATIONS</span>
                <h2>最近调查案件</h2>
              </div>
              <span className="local-pill">本机 Demo 草稿</span>
            </header>
            {cases.length ? (
              <div className="case-preview-list">
                {cases.slice(0, 3).map((item) => (
                  <button type="button" key={item.id} onClick={() => onOpenCase(item)}>
                    <span className="preview-icon">
                      <GitBranch size={17} />
                    </span>
                    <span>
                      <strong>{item.title}</strong>
                      <small>
                        {item.steps.length} 个步骤 · 更新于 {formatDate(item.updatedAt)}
                      </small>
                    </span>
                    <ArrowRight size={15} />
                  </button>
                ))}
              </div>
            ) : (
              <div className="home-empty">
                <GitBranch size={22} />
                <div>
                  <strong>还没有本机案件</strong>
                  <span>从攻击链示例或历史报告开始一次研判。</span>
                </div>
              </div>
            )}
          </section>

          <section className="home-card recent-intel">
            <header>
              <div>
                <span className="eyebrow">LATEST SOURCES</span>
                <h2>可核验历史报告</h2>
              </div>
              <FileSearch size={18} />
            </header>
            <div className="report-preview-list">
              {verifiableReports.slice(0, 3).map((report) => (
                <button type="button" key={report.id} onClick={() => onOpenReport(report.id)}>
                  <span>
                    <strong>{report.title}</strong>
                    <small>
                      {report.source} · {formatDate(report.report_date)}
                    </small>
                  </span>
                  {report.external_url ? <Sparkles size={15} /> : <ArrowRight size={15} />}
                </button>
              ))}
            </div>
          </section>
        </div>
      </section>
    </main>
  );
}
