import { NextResponse } from "next/server";


function backendUrl() {
  return (
    process.env.ARGUS_BACKEND_URL?.trim() || "http://127.0.0.1:8000"
  ).replace(/\/$/, "");
}


export async function GET() {
  try {
    const response = await fetch(`${backendUrl()}/v1/actor-knowledge`, {
      headers: { accept: "application/json" },
      cache: "no-store",
      signal: AbortSignal.timeout(15_000),
    });
    const payload = (await response.json()) as Record<string, unknown>;
    if (!response.ok) {
      throw new Error(
        typeof payload.detail === "string"
          ? payload.detail
          : `组织知识后端返回 ${response.status}。`,
      );
    }
    return NextResponse.json(payload, {
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    return NextResponse.json(
      {
        error: {
          code: "ACTOR_KNOWLEDGE_UNAVAILABLE",
          message:
            error instanceof Error
              ? error.message
              : "无法连接组织知识后端。",
        },
      },
      { status: 503 },
    );
  }
}
