import { describe, expect, it } from "vitest";
import {
  compactHighCardinalityIocs,
  iocCollectionMembers,
} from "../app/ioc-graph-projection";
import type { GraphEdge, GraphNode } from "../app/types";

function highCardinalityGraph(count: number) {
  const action: GraphNode = {
    id: "action-1",
    label: "发送钓鱼邮件",
    type: "攻击步骤",
  };
  const iocs: GraphNode[] = Array.from({ length: count }, (_, index) => ({
    id: `ioc-${index + 1}`,
    label: `c2-${index + 1}.example.test`,
    type: "IOC/基础设施",
    confidence: 0.95,
    entity: {
      id: `ioc-${index + 1}`,
      entity_type: "IOC/基础设施",
      canonical_key: `ioc:${index + 1}`,
      label: `c2-${index + 1}.example.test`,
      normalized_value: `c2-${index + 1}.example.test`,
      description: "",
      first_seen: null,
      last_seen: null,
      source_count: 1,
      properties: { context_type: "infrastructure" },
    },
  }));
  const edges: GraphEdge[] = iocs.map((node, index) => ({
    id: `context-${index + 1}`,
    source: action.id,
    target: node.id,
    label: "通信",
    category: "行为上下文",
    confidence: 0.95,
  }));
  return {
    nodes: [action, ...iocs],
    edges,
    rootIds: [action.id, ...iocs.map((node) => node.id)],
  };
}

describe("high-cardinality IOC graph projection", () => {
  it("collapses a large same-role IOC group without dropping member records", () => {
    const graph = highCardinalityGraph(8);
    const projected = compactHighCardinalityIocs(
      graph.nodes,
      graph.edges,
      graph.rootIds,
    );
    const collection = projected.nodes.find((node) => node.type === "IOC 集合");

    expect(projected.nodes).toHaveLength(2);
    expect(projected.edges).toHaveLength(1);
    expect(collection?.label).toBe("报告关联 IOC 集合");
    expect(iocCollectionMembers(collection)).toHaveLength(8);
    expect(iocCollectionMembers(collection).map((member) => member.id)).toEqual(
      expect.arrayContaining(graph.nodes.slice(1).map((node) => node.id)),
    );
    expect(projected.rootIds).toEqual(["action-1", collection?.id]);
    expect(projected.edges[0]).toMatchObject({
      source: "action-1",
      target: collection?.id,
      aggregate: true,
      label: "报告关联 · 8 个 IOC",
    });
  });

  it("keeps ordinary IOC groups as individual nodes", () => {
    const graph = highCardinalityGraph(6);
    const projected = compactHighCardinalityIocs(
      graph.nodes,
      graph.edges,
      graph.rootIds,
    );

    expect(projected.nodes).toBe(graph.nodes);
    expect(projected.edges).toBe(graph.edges);
    expect(projected.nodes.some((node) => node.type === "IOC 集合")).toBe(false);
  });

  it("classifies URLs containing an at-sign as URLs instead of email addresses", () => {
    const graph = highCardinalityGraph(7);
    graph.nodes[1].label =
      "https://storage.example.test/index.html#user@organization.test";
    const projected = compactHighCardinalityIocs(
      graph.nodes,
      graph.edges,
      graph.rootIds,
    );
    const collection = projected.nodes.find((node) => node.type === "IOC 集合");

    expect(
      iocCollectionMembers(collection).find((member) =>
        member.label.startsWith("https://"),
      )?.observableKind,
    ).toBe("URL");
  });
});
