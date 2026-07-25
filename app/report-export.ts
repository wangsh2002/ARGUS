"use client";

import type {
  AdviceItem,
  HistoricalFinding,
  InvestigationCase,
  SourceCitation,
} from "./types";
import { formatDate } from "./argus-domain";

export type InvestigationExport = {
  generated_at: string;
  disclaimer: string;
  investigation: InvestigationCase;
  historical_findings: HistoricalFinding[];
  recommendations: AdviceItem[];
  sources: SourceCitation[];
};

export function buildInvestigationExport(
  investigation: InvestigationCase,
  findings: HistoricalFinding[],
  advice: AdviceItem[],
  citations: SourceCitation[],
): InvestigationExport {
  return {
    generated_at: new Date().toISOString(),
    disclaimer:
      "本报告由 ARGUS 基于已入库情报和人工研判状态生成，仅供安全分析参考，不构成自动处置或确定性归因结论。",
    investigation,
    historical_findings: findings,
    recommendations: advice,
    sources: citations,
  };
}

export function exportToMarkdown(bundle: InvestigationExport) {
  const { investigation, historical_findings, recommendations, sources } = bundle;
  const lines = [
    `# ${investigation.title}`,
    "",
    `> ${bundle.disclaimer}`,
    "",
    "## 管理摘要",
    "",
    investigation.summary,
    "",
    `- 案件编号：${investigation.id}`,
    `- 攻击组织候选：${investigation.actor ?? "未确认"}`,
    `- 创建时间：${formatDate(investigation.createdAt)}`,
    `- 更新时间：${formatDate(investigation.updatedAt)}`,
    "",
    "## 攻击链",
    "",
    ...investigation.steps
      .filter((step) => step.reviewStatus !== "excluded")
      .map(
        (step, index) =>
          `${index + 1}. **${step.label}** — ${step.relation}；阶段：${step.phase}；置信度：${Math.round(step.confidence * 100)}%`,
      ),
    "",
    "## 历史报告综合总结",
    "",
    ...historical_findings.flatMap((finding) => [
      `### ${finding.phase} · ${finding.title}`,
      "",
      finding.summary,
      "",
    ]),
    "## 参考处置建议",
    "",
    ...recommendations.flatMap((item) => [
      `### ${item.priority} · ${item.group} · ${item.title}`,
      "",
      item.recommendation,
      "",
      `适用条件：${item.condition}`,
      "",
    ]),
    "## 来源",
    "",
    ...sources.map(
      (source, index) =>
        `${index + 1}. ${source.title} — ${source.publisher}，${formatDate(source.reportDate)}${source.externalUrl ? `，${source.externalUrl}` : ""}`,
    ),
    "",
  ];
  return lines.join("\n");
}

function download(filename: string, body: string, type: string) {
  const blob = new Blob([body], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function safeFilename(value: string) {
  return value.replace(/[\\/:*?"<>|]+/g, "-").slice(0, 70);
}

export function downloadMarkdown(bundle: InvestigationExport) {
  download(
    `${safeFilename(bundle.investigation.title)}.md`,
    exportToMarkdown(bundle),
    "text/markdown;charset=utf-8",
  );
}

export function downloadJson(bundle: InvestigationExport) {
  download(
    `${safeFilename(bundle.investigation.title)}.json`,
    JSON.stringify(bundle, null, 2),
    "application/json;charset=utf-8",
  );
}

export function printInvestigation() {
  window.print();
}
