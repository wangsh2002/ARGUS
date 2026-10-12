import { describe, expect, it } from "vitest";
import {
  analysisInputForReport,
  buildIntelExamples,
  buildPathExamples,
} from "../app/search-recommendations";
import type { AttackFlow, Entity, Report, RuntimeCatalog } from "../app/types";

function flow(id: string, actor: string, prefix: string): AttackFlow {
  const actions = Array.from({ length: 6 }, (_, index) => ({
    id: `${id}-A${index}`,
    name: `${prefix} behavior ${index}`,
    description: "",
    phase: "execution",
    confidence: "high" as const,
    technique_ids: [],
    contexts: [],
    evidence: [],
  }));
  return {
    schema_version: "1.0",
    id,
    title: `${actor} campaign`,
    description: "",
    sources: [],
    reported_actors: [
      {
        id: `${id}-actor`,
        reported_name: actor,
        actor_id: null,
        confidence: "high",
        evidence: [],
      },
    ],
    actions,
    relations: [],
    mainline: actions.map((action) => action.id),
  };
}

function entity(id: string, type: string, label: string, sourceCount: number): Entity {
  return {
    id,
    entity_type: type,
    canonical_key: `${type}:${label}`,
    label,
    normalized_value: label.toLocaleLowerCase(),
    description: "",
    first_seen: null,
    last_seen: null,
    source_count: sourceCount,
    properties: {},
  };
}

describe("data-driven search recommendations", () => {
  it("derives completion, prediction and multi-flow inputs from current flows", () => {
    const examples = buildPathExamples([
      flow("FLOW-A", "Actor Alpha", "alpha"),
      flow("FLOW-B", "Actor Beta", "beta"),
    ]);

    expect(examples).toHaveLength(3);
    expect(examples[0].query).toContain("alpha behavior 1");
    expect(examples[1].query).toContain("beta behavior 0");
    expect(examples[2].query).toContain("alpha behavior 5");
    expect(examples[2].query).toContain("beta behavior 5");
  });

  it("selects representative entities by type and source support", () => {
    const catalog = {
      entities: [
        entity("IOC-LOW", "IOC/基础设施", "low.example", 1),
        entity("IOC-HIGH", "IOC/基础设施", "high.example", 4),
        entity("ACTOR", "攻击组织", "Actor Gamma", 3),
      ],
    } as RuntimeCatalog;

    expect(buildIntelExamples(catalog).map((example) => example.query)).toEqual([
      "high.example",
      "Actor Gamma",
    ]);
  });

  it("derives report analysis input from flows sharing its source", () => {
    const related = flow("FLOW-REPORT", "Actor Delta", "delta");
    related.sources = [
      {
        id: "ART-1234",
        title: "Report",
        publisher: "Publisher",
        canonical_url: "https://example.test/report",
        published_at: "2026-08-03",
      },
    ];
    const report = { source_ref: "SRC-DOC-1234" } as Report;

    expect(analysisInputForReport(report, [related])).toBe(
      "delta behavior 0\ndelta behavior 2",
    );
  });
});
