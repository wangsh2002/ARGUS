import { NextResponse } from "next/server";


function backendUrl() {
  return (
    process.env.ARGUS_BACKEND_URL?.trim() || "http://127.0.0.1:8000"
  ).replace(/\/$/, "");
}


export async function GET(
  _request: Request,
  context: { params: Promise<{ entityId: string }> },
) {
  const { entityId } = await context.params;
  try {
    const response = await fetch(
      `${backendUrl()}/v1/runtime/entities/${encodeURIComponent(entityId)}`,
      {
        headers: { accept: "application/json" },
        cache: "no-store",
        signal: AbortSignal.timeout(15_000),
      },
    );
    const payload = (await response.json()) as Record<string, unknown>;
    if (!response.ok) {
      return NextResponse.json(
        {
          error: {
            code: "ENTITY_INTELLIGENCE_FAILED",
            message:
              typeof payload.detail === "string"
                ? payload.detail
                : `实体详情后端返回 ${response.status}。`,
          },
        },
        { status: response.status },
      );
    }
    return NextResponse.json(payload, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return NextResponse.json(
      {
        error: {
          code: "ENTITY_INTELLIGENCE_UNAVAILABLE",
          message: error instanceof Error ? error.message : "无法连接实体详情后端。",
        },
      },
      { status: 503 },
    );
  }
}
