import { NextResponse } from "next/server";


type IngestionRequest =
  | {
      action: "stage";
      source: {
        title?: string;
        publisher?: string;
        canonical_url?: string;
        published_at?: string;
        content?: string;
      };
      projection_goal?: "incident-response" | "soc-triage";
      attack_flow_candidate?: unknown;
      attack_flow_candidates?: unknown[];
      extract_attack_flows?: boolean;
      merge_review?: unknown;
    }
  | { action: "publish"; ingestion_id?: string }
  | {
      action: "revise-flow";
      ingestion_id?: string;
      attack_flow_candidate?: unknown;
      merge_review?: unknown;
    }
  | { action: "reject-flow"; ingestion_id?: string }
  | { action: "rollback"; version_id?: string };


function backendUrl() {
  return (
    process.env.ARGUS_BACKEND_URL?.trim() || "http://127.0.0.1:8000"
  ).replace(/\/$/, "");
}


async function backendRequest(
  path: string,
  method: "GET" | "POST" | "PUT" = "POST",
  body?: unknown,
) {
  const response = await fetch(`${backendUrl()}${path}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(90_000),
  });
  const payload = (await response.json()) as Record<string, unknown>;
  if (!response.ok) {
    throw new Error(
      typeof payload.detail === "string"
        ? payload.detail
        : `入库后端返回 ${response.status}。`,
    );
  }
  return payload;
}


export async function GET() {
  try {
    return NextResponse.json(
      await backendRequest("/v1/knowledge-ingestions?status=staged", "GET"),
    );
  } catch (error) {
    return NextResponse.json(
      {
        error: {
          code: "INGESTION_QUEUE_UNAVAILABLE",
          message:
            error instanceof Error ? error.message : "无法读取 AttackFlow 待审队列。",
        },
      },
      { status: 503 },
    );
  }
}


export async function POST(request: Request) {
  let body: IngestionRequest;
  try {
    body = (await request.json()) as IngestionRequest;
  } catch {
    return NextResponse.json(
      { error: { code: "INVALID_JSON", message: "请求正文不是有效 JSON。" } },
      { status: 400 },
    );
  }
  try {
    if (body.action === "stage") {
      const content = body.source.content?.trim();
      const canonicalUrl = body.source.canonical_url?.trim();
      if (!content || !canonicalUrl) {
        return NextResponse.json(
          {
            error: {
              code: "SOURCE_REQUIRED",
              message: "来源链接和情报正文不能为空。",
            },
          },
          { status: 400 },
        );
      }
      const source = await backendRequest("/v1/sources", "POST", {
        title: body.source.title?.trim() || "待编目情报",
        publisher: body.source.publisher?.trim() || "待核验来源",
        canonical_url: canonicalUrl,
        published_at:
          body.source.published_at?.trim() ||
          new Date().toISOString().slice(0, 10),
        mime_type: "text/plain",
        content,
      });
      const sourceDocument = source.source_document as
        | { id?: unknown }
        | undefined;
      if (typeof sourceDocument?.id !== "string") {
        throw new Error("后端未返回来源文档 ID。");
      }
      return NextResponse.json(
        await backendRequest("/v1/knowledge-ingestions", "POST", {
          source_document_id: sourceDocument.id,
          projection_goal: body.projection_goal || "incident-response",
          attack_flow_candidate: body.attack_flow_candidate,
          attack_flow_candidates: body.attack_flow_candidates,
          extract_attack_flows: body.extract_attack_flows,
          merge_review: body.merge_review,
        }),
      );
    }
    if (body.action === "publish") {
      if (!body.ingestion_id) throw new Error("缺少入库任务 ID。");
      return NextResponse.json(
        await backendRequest(
          `/v1/knowledge-ingestions/${encodeURIComponent(body.ingestion_id)}/publish`,
        ),
      );
    }
    if (body.action === "revise-flow") {
      if (!body.ingestion_id || !body.attack_flow_candidate) {
        throw new Error("缺少入库任务 ID 或 AttackFlow 候选。")
      }
      return NextResponse.json(
        await backendRequest(
          `/v1/knowledge-ingestions/${encodeURIComponent(body.ingestion_id)}`,
          "PUT",
          {
            attack_flow_candidate: body.attack_flow_candidate,
            merge_review: body.merge_review,
          },
        ),
      );
    }
    if (body.action === "reject-flow") {
      if (!body.ingestion_id) throw new Error("缺少入库任务 ID。")
      return NextResponse.json(
        await backendRequest(
          `/v1/knowledge-ingestions/${encodeURIComponent(body.ingestion_id)}/reject`,
        ),
      );
    }
    if (body.action === "rollback") {
      if (!body.version_id) throw new Error("缺少知识版本 ID。");
      return NextResponse.json(
        await backendRequest(
          `/v1/knowledge-versions/${encodeURIComponent(body.version_id)}/rollback`,
        ),
      );
    }
    throw new Error("不支持的入库动作。");
  } catch (error) {
    return NextResponse.json(
      {
        error: {
          code: "INGESTION_BACKEND_ERROR",
          message:
            error instanceof Error ? error.message : "无法连接情报入库后端。",
        },
      },
      { status: 503 },
    );
  }
}
