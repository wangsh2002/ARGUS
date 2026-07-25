import { NextResponse } from "next/server";

type GptRequest = {
  message?: string;
  context?: {
    case_id?: string;
    title?: string;
    nodes?: Array<{ label?: string; type?: string; phase?: string; status?: string }>;
    sources?: Array<{
      id?: string;
      title?: string;
      publisher?: string;
      excerpt?: string;
      url?: string;
    }>;
  };
};

function config() {
  return {
    baseUrl: process.env.ARGUS_LLM_BASE_URL?.trim() ?? "",
    apiKey: process.env.ARGUS_LLM_API_KEY?.trim() ?? "",
    model: process.env.ARGUS_LLM_MODEL?.trim() ?? "",
  };
}

export async function GET() {
  const current = config();
  return NextResponse.json({
    configured: Boolean(current.baseUrl && current.apiKey && current.model),
    model: current.model || null,
  });
}

function cleanSuggestedNodes(value: unknown) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item) => item && typeof item === "object")
    .slice(0, 6)
    .map((item, index) => {
      const node = item as Record<string, unknown>;
      return {
        id:
          typeof node.id === "string"
            ? node.id
            : `gpt-suggestion-${Date.now().toString(36)}-${index}`,
        label: typeof node.label === "string" ? node.label.slice(0, 100) : "待确认节点",
        type: typeof node.type === "string" ? node.type.slice(0, 40) : "输入步骤",
        relation:
          typeof node.relation === "string" ? node.relation.slice(0, 60) : "待确认关系",
        confidence:
          typeof node.confidence === "number"
            ? Math.max(0, Math.min(1, node.confidence))
            : 0.4,
      };
    });
}

function cleanCitations(value: unknown, sources: NonNullable<GptRequest["context"]>["sources"]) {
  if (!Array.isArray(value)) return [];
  const sourceMap = new Map(
    (sources ?? [])
      .filter((source) => typeof source.id === "string")
      .map((source) => [source.id as string, source]),
  );
  return value
    .filter((item) => item && typeof item === "object")
    .map((item) => {
      const citation = item as Record<string, unknown>;
      const id = typeof citation.id === "string" ? citation.id : "";
      const source = sourceMap.get(id);
      if (!source) return null;
      return {
        id,
        label: source.title || source.publisher || id,
        url: source.url || undefined,
      };
    })
    .filter((citation): citation is NonNullable<typeof citation> => Boolean(citation))
    .slice(0, 8);
}

export async function POST(request: Request) {
  const current = config();
  if (!current.baseUrl || !current.apiKey || !current.model) {
    return NextResponse.json(
      {
        error: {
          code: "MODEL_NOT_CONFIGURED",
          message:
            "ARGUS GPT 尚未配置。请设置 ARGUS_LLM_BASE_URL、ARGUS_LLM_API_KEY 和 ARGUS_LLM_MODEL。",
        },
      },
      { status: 503 },
    );
  }

  let body: GptRequest;
  try {
    body = (await request.json()) as GptRequest;
  } catch {
    return NextResponse.json(
      { error: { code: "INVALID_JSON", message: "请求正文不是有效 JSON。" } },
      { status: 400 },
    );
  }
  const message = body.message?.trim();
  if (!message) {
    return NextResponse.json(
      { error: { code: "MESSAGE_REQUIRED", message: "请输入安全分析问题。" } },
      { status: 400 },
    );
  }

  const nodes = (body.context?.nodes ?? []).slice(0, 20);
  const sources = (body.context?.sources ?? []).slice(0, 8);
  const system = [
    "你是 ARGUS 威胁情报分析助手。",
    "只根据用户提供的案件上下文和来源证据回答；无法确认时必须明确说不确定。",
    "不要给出绝对归因或自动处置指令。",
    "返回严格 JSON：answer 字符串、citations 数组、suggested_nodes 数组。",
    "citations 中只能引用上下文给出的来源 id、label、url。",
    "suggested_nodes 只用于攻击链草稿，每项包含 label、type、relation、confidence，且需要人工确认。",
  ].join("\n");
  const context = JSON.stringify(
    {
      case_id: body.context?.case_id,
      title: body.context?.title,
      nodes,
      sources: sources.map((source) => ({
        ...source,
        excerpt: source.excerpt?.slice(0, 900),
      })),
    },
    null,
    2,
  );

  try {
    const response = await fetch(
      `${current.baseUrl.replace(/\/$/, "")}/chat/completions`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${current.apiKey}`,
        },
        body: JSON.stringify({
          model: current.model,
          temperature: 0.2,
          messages: [
            { role: "system", content: system },
            {
              role: "user",
              content: `案件上下文：\n${context}\n\n用户问题：${message}`,
            },
          ],
        }),
      },
    );
    const payload = (await response.json()) as Record<string, unknown>;
    if (!response.ok) {
      const remoteError = payload.error as Record<string, unknown> | undefined;
      return NextResponse.json(
        {
          error: {
            code: "MODEL_REQUEST_FAILED",
            message:
              (typeof remoteError?.message === "string" && remoteError.message) ||
              `模型接口返回 ${response.status}。`,
          },
        },
        { status: 502 },
      );
    }

    const choices = payload.choices as
      | Array<{ message?: { content?: string } }>
      | undefined;
    const content = choices?.[0]?.message?.content?.trim() ?? "";
    let parsed: Record<string, unknown> = {};
    try {
      const normalized = content
        .replace(/^```(?:json)?\s*/i, "")
        .replace(/\s*```$/, "");
      parsed = JSON.parse(normalized) as Record<string, unknown>;
    } catch {
      parsed = { answer: content };
    }

    return NextResponse.json({
      answer:
        typeof parsed.answer === "string"
          ? parsed.answer
          : content || "模型没有返回可展示的回答。",
      citations: cleanCitations(parsed.citations, sources),
      suggested_nodes: cleanSuggestedNodes(parsed.suggested_nodes),
      model: current.model,
    });
  } catch {
    return NextResponse.json(
      {
        error: {
          code: "MODEL_UNREACHABLE",
          message: "无法连接已配置的模型服务，请检查接口地址和网络状态。",
        },
      },
      { status: 502 },
    );
  }
}
