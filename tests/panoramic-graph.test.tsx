import { describe, expect, it } from "vitest";
import { adaptPanoramicNeighborhood } from "../app/panoramic-graph";
import type { PanoramicGraphNeighborhood } from "../app/types";

describe("panoramic graph adapter", () => {
  it("keeps report metadata without rendering title nodes", () => {
    const neighborhood: PanoramicGraphNeighborhood = {
      root_id: "ACTION-1",
      depth: 3,
      nodes: [
        {
          id: "FLOW-1",
          kind: "attack-flow",
          label: "A very long report-derived attack-flow title",
          type: "攻击流",
          description: "",
          confidence: 1,
          properties: {},
        },
        {
          id: "SOURCE-1",
          kind: "source",
          label: "Threat research report title",
          type: "来源报告",
          description: "Example CERT",
          confidence: 1,
          properties: {},
        },
        {
          id: "ACTION-1",
          kind: "action",
          label: "执行加载器",
          type: "攻击步骤",
          description: "",
          confidence: 0.95,
          properties: { flow_id: "FLOW-1" },
        },
        {
          id: "EVIDENCE-1",
          kind: "evidence",
          label: "证据 · line:12",
          type: "来源片段",
          description: "The loader was executed.",
          confidence: 0.95,
          properties: {
            source_id: "SOURCE-1",
            source_title: "Threat research report title",
            publisher: "Example CERT",
            canonical_url: "https://example.test/report",
            published_at: "2026-08-01",
          },
        },
        {
          id: "TOOL-1",
          kind: "entity",
          label: "Example Loader",
          type: "恶意软件/工具",
          description: "",
          confidence: 0.95,
          properties: {},
        },
      ],
      edges: [
        {
          id: "flow-action",
          source_id: "FLOW-1",
          target_id: "ACTION-1",
          type: "contains-action",
          label: "包含步骤",
          confidence: 1,
          aggregate: false,
          evidence_ids: [],
          explanation: null,
        },
        {
          id: "action-evidence",
          source_id: "ACTION-1",
          target_id: "EVIDENCE-1",
          type: "supported-by-evidence",
          label: "证据支持",
          confidence: 0.95,
          aggregate: false,
          evidence_ids: ["EVIDENCE-1"],
          explanation: null,
        },
        {
          id: "action-tool",
          source_id: "ACTION-1",
          target_id: "TOOL-1",
          type: "action-context",
          label: "uses",
          confidence: 0.95,
          aggregate: false,
          evidence_ids: ["EVIDENCE-1"],
          evidence: [
            {
              id: "CONTEXT-EVIDENCE-1",
              source_span_id: "EVIDENCE-1",
              source_id: "SOURCE-1",
              title: "Threat research report title",
              publisher: "Example CERT",
              canonical_url: "https://example.test/report",
              locator: "line:12",
              quote: "The loader used Example Loader.",
              confidence: 0.95,
            },
          ],
          explanation: null,
        },
        {
          id: "evidence-source",
          source_id: "EVIDENCE-1",
          target_id: "SOURCE-1",
          type: "excerpt-of",
          label: "摘录自",
          confidence: 0.95,
          aggregate: false,
          evidence_ids: ["EVIDENCE-1"],
          explanation: null,
        },
      ],
      available_expansions: {},
      knowledge_version: "test",
    };

    const graph = adaptPanoramicNeighborhood(neighborhood);

    expect(graph.nodes.map((node) => node.id)).toEqual([
      "ACTION-1",
      "TOOL-1",
    ]);
    expect(graph.edges).toHaveLength(1);
    expect(graph.edges[0].label).toBe("使用");
    expect(graph.edges[0].evidence?.[0]).toMatchObject({
      report_title: "Threat research report title",
      publisher: "Example CERT",
      canonical_url: "https://example.test/report",
      report_date: "2026-08-01",
      excerpt: "The loader used Example Loader.",
    });
  });
});
