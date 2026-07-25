"use client";

import {
  ArrowRight,
  Bot,
  Boxes,
  FileJson,
  FileText,
  GitBranch,
  Network,
  Plus,
  ScrollText,
  Upload,
} from "lucide-react";
import { useRef, useState } from "react";
import type { Snapshot } from "../types";
import { formatDate, getChainParts } from "../argus-domain";

const methods = [
  {
    id: "paste",
    title: "粘贴日志或告警",
    description: "支持事件记录、IOC 列表与自然语言",
    icon: ScrollText,
  },
  {
    id: "file",
    title: "上传证据文件",
    description: "TXT、JSON、CSV、STIX",
    icon: FileJson,
  },
  {
    id: "visual",
    title: "可视化组织",
    description: "用节点顺序组织已知线索",
    icon: Network,
  },
  {
    id: "intel",
    title: "从已有情报开始",
    description: "选择 IOC、组织、事件或报告",
    icon: FileText,
  },
  {
    id: "template",
    title: "使用链路模板",
    description: "钓鱼、漏洞利用、身份入侵",
    icon: Boxes,
  },
  {
    id: "gpt",
    title: "通过 GPT 创建",
    description: "生成可供匹配的链路线索",
    icon: Bot,
  },
] as const;

export function ChainIntakeView({
  data,
  initialValue,
  onCreateFromQuery,
  onCreateFromReport,
  onOpenGpt,
}: {
  data: Snapshot;
  initialValue: string;
  onCreateFromQuery: (query: string) => void;
  onCreateFromReport: (reportId: string) => void;
  onOpenGpt: () => void;
}) {
  const [method, setMethod] = useState<(typeof methods)[number]["id"]>("paste");
  const [value, setValue] = useState(initialValue);
  const [filename, setFilename] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);
  const parts = getChainParts(value);
  const verifiableReports = [...data.reports].sort(
    (left, right) =>
      Number(Boolean(right.external_url)) - Number(Boolean(left.external_url)) ||
      right.report_date.localeCompare(left.report_date),
  );

  const selectMethod = (id: (typeof methods)[number]["id"]) => {
    setMethod(id);
    if (id === "file") fileRef.current?.click();
    if (id === "gpt") onOpenGpt();
    if (id === "visual" && !value) {
      setValue("可疑邮件附件 → PowerShell 执行 → 恶意域名回连");
    }
    if (id === "template" && !value) {
      setValue("钓鱼邮件 → 恶意附件 → 脚本执行 → 命令与控制");
    }
  };

  const loadFile = async (file?: File) => {
    if (!file) return;
    setFilename(file.name);
    setValue(await file.text());
    setMethod("file");
  };

  return (
    <main className="page-frame intake-page">
      <section className="page-heading">
        <div>
          <span className="eyebrow">CHAIN EVIDENCE INTAKE</span>
          <h1>匹配攻击链</h1>
          <p>输入已有证据或已知步骤，系统会与情报库匹配并生成只读结果。</p>
        </div>
        <span className="honesty-pill">
          <GitBranch size={15} />
          输入不等于已验证情报
        </span>
      </section>

      <div className="intake-method-grid">
        {methods.map((item) => {
          const Icon = item.icon;
          return (
            <button
              type="button"
              key={item.id}
              className={method === item.id ? "active" : ""}
              onClick={() => selectMethod(item.id)}
            >
              <Icon size={20} />
              <span>
                <strong>{item.title}</strong>
                <small>{item.description}</small>
              </span>
              <ArrowRight size={15} />
            </button>
          );
        })}
      </div>

      <section className="intake-workbench">
        <header>
          <div>
            <span className="eyebrow">INPUT PREVIEW</span>
            <h2>
              {method === "visual"
                ? "可视化编排草稿"
                : method === "file"
                  ? filename || "证据文件"
                  : "证据输入"}
            </h2>
          </div>
          <span>{parts.length || (value.trim() ? 1 : 0)} 个候选片段</span>
        </header>
        <textarea
          aria-label="攻击链证据输入"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder="粘贴告警、日志、IOC 列表，或使用 → 组织已知步骤"
        />
        <input
          ref={fileRef}
          hidden
          type="file"
          accept=".txt,.json,.csv,.md,application/json,text/plain,text/csv"
          onChange={(event) => loadFile(event.target.files?.[0])}
        />
        <div className="candidate-preview">
          {(parts.length ? parts : value.trim() ? [value.trim().slice(0, 90)] : []).map(
            (part, index) => (
              <div key={`${part}-${index}`}>
                <span className="candidate-index">{String(index + 1).padStart(2, "0")}</span>
                <span>
                  <strong>{part}</strong>
                  <small>用户输入 · 待与情报库匹配</small>
                </span>
                <span className="candidate-state">待匹配</span>
              </div>
            ),
          )}
          {!value.trim() && (
            <div className="candidate-placeholder">
              <Plus size={18} /> 输入内容后将在这里预览候选节点
            </div>
          )}
        </div>
        <footer>
          <div>
            <Upload size={15} />
            本阶段提供轻量解析；工作台用于查看匹配路径、图谱和来源证据。
          </div>
          <button
            type="button"
            className="primary-button"
            disabled={!value.trim()}
            onClick={() => onCreateFromQuery(value)}
          >
            匹配攻击链 <ArrowRight size={16} />
          </button>
        </footer>
      </section>

      <section className="source-starts">
        <header>
          <div>
            <span className="eyebrow">START FROM A SOURCE</span>
            <h2>从历史报告开始</h2>
          </div>
          <span>{data.reports.length} 份已入库报告</span>
        </header>
        <div className="source-start-grid">
          {verifiableReports.slice(0, 4).map((report) => (
            <button type="button" key={report.id} onClick={() => onCreateFromReport(report.id)}>
              <FileText size={18} />
              <span>
                <strong>{report.title}</strong>
                <small>
                  {report.source} · {formatDate(report.report_date)}
                </small>
              </span>
              <ArrowRight size={15} />
            </button>
          ))}
        </div>
      </section>
    </main>
  );
}
