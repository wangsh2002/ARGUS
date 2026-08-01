import assert from "node:assert/strict";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the ARGUS runtime bootstrap", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /ARGUS 威胁情报分析平台/);
  assert.match(html, /综合查询/);
  assert.match(html, /正在加载运行时知识/);
  assert.doesNotMatch(html, /威胁情报查询与分析平台/);
  assert.doesNotMatch(html, /aria-controls="search-assist-panel"/);
  assert.doesNotMatch(html, /最近收录的攻击链报告/);
  assert.match(html, /ARGUS GPT/);
  assert.doesNotMatch(html, /Your site is taking shape|Codex is working|react-loading-skeleton/);
});
