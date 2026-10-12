import { NextResponse } from "next/server";


function backendUrl() {
  return (
    process.env.ARGUS_BACKEND_URL?.trim() || "http://127.0.0.1:8000"
  ).replace(/\/$/, "");
}


export async function GET(
  _request: Request,
  context: { params: Promise<{ flowId: string }> },
) {
  const { flowId } = await context.params;
  try {
    const response = await fetch(
      `${backendUrl()}/v1/attack-flows/${encodeURIComponent(flowId)}/source-documents`,
      {
        headers: { accept: "application/json" },
        cache: "no-store",
        signal: AbortSignal.timeout(15_000),
      },
    );
    const payload = (await response.json()) as unknown;
    if (!response.ok) {
      const detail =
        typeof payload === "object" &&
        payload &&
        "detail" in payload &&
        typeof payload.detail === "string"
          ? payload.detail
          : `原文标注后端返回 ${response.status}。`;
      return NextResponse.json(
        { error: { code: "SOURCE_ANNOTATIONS_READ_FAILED", message: detail } },
        { status: response.status },
      );
    }
    return NextResponse.json(payload, {
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    return NextResponse.json(
      {
        error: {
          code: "SOURCE_ANNOTATIONS_BACKEND_UNAVAILABLE",
          message:
            error instanceof Error ? error.message : "无法读取原文标注。",
        },
      },
      { status: 503 },
    );
  }
}
