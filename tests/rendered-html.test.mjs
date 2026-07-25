import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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

test("server-renders the ARGUS intelligence workspace", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /ARGUS 可追溯攻击链研判平台/);
  assert.match(html, /综合查询/);
  assert.match(html, /从零散证据/);
  assert.match(html, /攻击组织/);
  assert.match(html, /ARGUS GPT/);
  assert.match(html, />160</);
  assert.match(html, />182</);
  assert.doesNotMatch(html, /Your site is taking shape|Codex is working|react-loading-skeleton/);
});

test("uses the synchronized SQLite snapshot instead of demo constants", async () => {
  const snapshot = JSON.parse(
    await readFile(new URL("../lib/argus-data.json", import.meta.url), "utf8"),
  );
  assert.equal(snapshot.meta.source, "data/argus_cti.db");
  assert.equal(snapshot.meta.is_demo, false);
  assert.equal(snapshot.entities.length, 160);
  assert.equal(snapshot.relationships.length, 182);
  assert.equal(snapshot.evidence.length, 182);
  assert.equal(snapshot.reports.length, 13);
  assert.equal(snapshot.actors.length, 5);
  assert.ok(snapshot.entities.some((entity) => entity.label === "APT28"));
  assert.ok(snapshot.entities.some((entity) => entity.label === "CVE-2023-23397"));
});
