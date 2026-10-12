import { describe, expect, it } from "vitest";
import { adviceForCase } from "../app/argus-domain";
import type {
  InvestigationCase,
  ResponseRule,
  Snapshot,
} from "../app/types";

const investigation: InvestigationCase = {
  id: "CASE-TEST",
  title: "Test case",
  summary: "",
  sourceKind: "query",
  sourceLabel: "test",
  createdAt: "2026-08-03T00:00:00+08:00",
  updatedAt: "2026-08-03T00:00:00+08:00",
  steps: [
    {
      id: "STEP-1",
      label: "Observed indicator",
      type: "IOC/基础设施",
      relation: "observed",
      phase: "discovery",
      confidence: 0.9,
      evidenceCount: 1,
      status: "confirmed",
      origin: "database",
      reviewStatus: "matched",
    },
  ],
  links: [],
  notes: "",
  completedAdviceIds: [],
  version: 1,
};

function snapshotWithRules(responseRules: ResponseRule[]) {
  return { responseRules } as Snapshot;
}

describe("response rule projection", () => {
  it("does not fabricate advice when the backend supplies no rules", () => {
    expect(adviceForCase(snapshotWithRules([]), investigation)).toEqual([]);
  });

  it("applies configurable wildcard rules to any investigation type", () => {
    const advice = adviceForCase(
      snapshotWithRules([
        {
          id: "RULE-GENERIC",
          match_entity_type: "*",
          priority: "P1",
          action_template: "Validate the observed evidence.",
          rationale: "Evidence must precede containment.",
          source_url: "",
          title: "Validate evidence",
          group_label: "立即遏制",
          match_event: "",
        },
      ]),
      investigation,
    );

    expect(advice).toHaveLength(1);
    expect(advice[0]).toMatchObject({
      id: "RULE-GENERIC",
      group: "立即遏制",
      stepIds: ["STEP-1"],
    });
  });
});
