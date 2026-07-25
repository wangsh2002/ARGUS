"use client";

import {
  ArrowRight,
  Bot,
  Check,
  FileText,
  GitBranch,
  LoaderCircle,
  Paperclip,
  Plus,
  Send,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type {
  GptResponse,
  InvestigationCase,
  Snapshot,
  SourceCitation,
} from "../types";
import { citationsForCase } from "../argus-domain";

type Message =
  | { id: string; role: "user"; text: string }
  | { id: string; role: "assistant"; text: string; response?: GptResponse };

export function GPTView({
  data,
  initialPrompt,
  investigation,
  onAddSuggestedNode,
  onOpenChain,
}: {
  data: Snapshot;
  initialPrompt: string;
  investigation?: InvestigationCase;
  onAddSuggestedNode: (node: GptResponse["suggested_nodes"][number]) => void;
  onOpenChain: () => void;
}) {
  const [prompt, setPrompt] = useState(initialPrompt);
  const [messages, setMessages] = useState<Message[]>([]);
  const [loading, setLoading] = useState(false);
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [model, setModel] = useState<string>();
  const [filename, setFilename] = useState("");
  const [attachment, setAttachment] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);
  const citations: SourceCitation[] = investigation
    ? citationsForCase(data, investigation)
    : [];

  useEffect(() => {
    fetch("/api/gpt")
      .then((response) => response.json())
      .then((status: { configured?: boolean; model?: string | null }) => {
        setConfigured(Boolean(status.configured));
        setModel(status.model ?? undefined);
      })
      .catch(() => setConfigured(false));
  }, []);

  const send = async () => {
    const message = [prompt.trim(), attachment ? `\n\n附件内容：\n${attachment.slice(0, 6000)}` : ""]
      .join("")
      .trim();
    if (!message || loading) return;
    const userMessage: Message = {
      id: `user-${Date.now().toString(36)}`,
      role: "user",
      text: prompt.trim() || `分析附件 ${filename}`,
    };
    setMessages((current) => [...current, userMessage]);
    setPrompt("");
    setLoading(true);
    try {
      const response = await fetch("/api/gpt", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          message,
          context: investigation
            ? {
                case_id: investigation.id,
                title: investigation.title,
                nodes: investigation.steps.map((step) => ({
                  label: step.label,
                  type: step.type,
                  phase: step.phase,
                  status: step.reviewStatus,
                })),
                sources: citations.map((citation) => ({
                  id: citation.id,
                  title: citation.title,
                  publisher: citation.publisher,
                  excerpt: citation.excerpt,
                  url: citation.externalUrl,
                })),
              }
            : undefined,
        }),
      });
      const payload = (await response.json()) as
        | GptResponse
        | { error?: { message?: string } };
      if (!response.ok) {
        throw new Error(
          "error" in payload
            ? payload.error?.message || "ARGUS GPT 暂时无法回答。"
            : "ARGUS GPT 暂时无法回答。",
        );
      }
      const answer = payload as GptResponse;
      setMessages((current) => [
        ...current,
        {
          id: `assistant-${Date.now().toString(36)}`,
          role: "assistant",
          text: answer.answer,
          response: answer,
        },
      ]);
      setAttachment("");
      setFilename("");
    } catch (error) {
      setMessages((current) => [
        ...current,
        {
          id: `assistant-${Date.now().toString(36)}`,
          role: "assistant",
          text: error instanceof Error ? error.message : "ARGUS GPT 暂时无法回答。",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="gpt-page">
      <aside className="gpt-sidebar">
        <button
          type="button"
          className="new-chat"
          onClick={() => {
            setMessages([]);
            setPrompt("");
          }}
        >
          <Plus size={16} /> 新建对话
        </button>
        <div className="gpt-context-card">
          <span className="eyebrow">CURRENT CONTEXT</span>
          {investigation ? (
            <>
              <GitBranch size={19} />
              <strong>{investigation.title}</strong>
              <small>
                {investigation.steps.length} 个节点 · {citations.length} 条来源
              </small>
              <button type="button" onClick={onOpenChain}>
                返回工作台 <ArrowRight size={13} />
              </button>
            </>
          ) : (
            <>
              <Sparkles size={19} />
              <strong>未携带调查案件</strong>
              <small>仍可进行通用安全问答。</small>
            </>
          )}
        </div>
        <div className={`model-status ${configured ? "is-online" : ""}`}>
          <span />
          <div>
            <strong>
              {configured === null
                ? "正在检查模型"
                : configured
                  ? "模型服务已连接"
                  : "模型服务未配置"}
            </strong>
            <small>{model ?? "OpenAI-compatible endpoint"}</small>
          </div>
        </div>
        <div className="gpt-boundary">
          <ShieldCheck size={15} />
          GPT 建议不会自动写入正式情报库，加入攻击链前必须人工确认。
        </div>
      </aside>

      <section className="gpt-stage">
        <header>
          <span className="gpt-logo"><Bot size={24} /></span>
          <div>
            <span className="eyebrow">SECURITY ANALYSIS ASSISTANT</span>
            <h1>ARGUS GPT</h1>
            <p>结合当前案件和真实来源，辅助解释证据、总结链路与发现缺口。</p>
          </div>
        </header>

        <div className="conversation" aria-live="polite">
          {!messages.length && (
            <div className="gpt-welcome">
              <Sparkles size={27} />
              <h2>今天需要分析什么？</h2>
              <p>选择一个问题开始，或上传文本类情报与日志。</p>
              <div>
                {[
                  "总结当前攻击链中已有证据和缺口",
                  "哪些节点仍需要人工确认？",
                  "基于历史报告整理参考处置建议",
                ].map((example) => (
                  <button type="button" key={example} onClick={() => setPrompt(example)}>
                    {example} <ArrowRight size={14} />
                  </button>
                ))}
              </div>
            </div>
          )}
          {messages.map((message) => (
            <article key={message.id} className={`message message-${message.role}`}>
              <span className="message-avatar">
                {message.role === "assistant" ? <Bot size={16} /> : "AN"}
              </span>
              <div>
                <strong>{message.role === "assistant" ? "ARGUS GPT" : "你"}</strong>
                <p>{message.text}</p>
                {message.role === "assistant" && message.response && (
                  <>
                    {message.response.citations.length > 0 && (
                      <div className="gpt-citations">
                        {message.response.citations.map((citation) => (
                          citation.url ? (
                            <a key={citation.id} href={citation.url} target="_blank" rel="noreferrer">
                              <FileText size={13} /> {citation.label}
                            </a>
                          ) : (
                            <span key={citation.id}>
                              <FileText size={13} /> {citation.label}
                            </span>
                          )
                        ))}
                      </div>
                    )}
                    {message.response.suggested_nodes.length > 0 && (
                      <div className="gpt-suggestions">
                        <span>建议加入研判草稿</span>
                        {message.response.suggested_nodes.map((node) => (
                          <div key={node.id}>
                            <span>
                              <strong>{node.label}</strong>
                              <small>{node.type} · {node.relation}</small>
                            </span>
                            <button type="button" onClick={() => onAddSuggestedNode(node)}>
                              <Check size={13} /> 确认加入
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
            </article>
          ))}
          {loading && (
            <article className="message message-assistant">
              <span className="message-avatar"><Bot size={16} /></span>
              <div>
                <strong>ARGUS GPT</strong>
                <p className="thinking"><LoaderCircle size={15} /> 正在结合案件证据分析……</p>
              </div>
            </article>
          )}
        </div>

        <div className="gpt-composer">
          {filename && (
            <div className="attachment-chip">
              <FileText size={14} />
              {filename}
              <button
                type="button"
                aria-label="移除附件"
                onClick={() => {
                  setFilename("");
                  setAttachment("");
                }}
              >
                ×
              </button>
            </div>
          )}
          <textarea
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                send();
              }
            }}
            placeholder="输入安全分析问题，Enter 发送，Shift + Enter 换行"
          />
          <input
            ref={fileRef}
            hidden
            type="file"
            accept=".txt,.json,.csv,.md,text/plain,application/json,text/csv,text/markdown"
            onChange={async (event) => {
              const file = event.target.files?.[0];
              if (!file) return;
              setFilename(file.name);
              setAttachment(await file.text());
            }}
          />
          <footer>
            <button type="button" aria-label="上传文本附件" onClick={() => fileRef.current?.click()}>
              <Paperclip size={17} />
            </button>
            <span>
              {configured
                ? `回答由 ${model} 生成，仍需人工复核`
                : "配置模型环境变量后即可发送真实请求"}
            </span>
            <button
              type="button"
              className="send-button"
              aria-label="发送"
              disabled={(!prompt.trim() && !attachment) || loading}
              onClick={send}
            >
              <Send size={16} />
            </button>
          </footer>
        </div>
        {configured === false && (
          <div className="gpt-offline-note">
            <TriangleAlert size={15} />
            GPT 页面和工作台联动已就绪；模型未配置时不会返回模拟回答。
          </div>
        )}
      </section>
    </main>
  );
}
