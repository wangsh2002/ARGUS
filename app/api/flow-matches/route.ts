import { NextResponse } from "next/server";


function backendUrl() {
  return (
    process.env.ARGUS_BACKEND_URL?.trim() || "http://127.0.0.1:8000"
  ).replace(/\/$/, "");
}


export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { error: { code: "INVALID_JSON", message: "请求正文不是有效 JSON。" } },
      { status: 400 },
    );
  }
  try {
    const response = await fetch(`${backendUrl()}/v1/flow-matches`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      cache: "no-store",
      signal: AbortSignal.timeout(15_000),
    });
    const payload = (await response.json()) as Record<string, unknown>;
    if (!response.ok) {
      const detail =
        typeof payload.detail === "string"
          ? payload.detail
          : `攻击流匹配后端返回 ${response.status}。`;
      return NextResponse.json(
        { error: { code: "FLOW_MATCH_FAILED", message: detail } },
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
          code: "FLOW_MATCH_BACKEND_UNAVAILABLE",
          message:
            error instanceof Error ? error.message : "无法连接攻击流匹配后端。",
        },
      },
      { status: 503 },
    );
  }
}
