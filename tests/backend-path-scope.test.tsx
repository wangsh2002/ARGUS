import { describe, expect, it } from "vitest";
import { scopeFlowMatchAnalysisBySource } from "../app/backend-path";
import type { AttackFlow, BackendFlowMatchAnalysis } from "../app/types";

function flow(id: string, sourceId: string): AttackFlow {
  return {
    schema_version: "1.0",
    id,
    title: id,
    description: "",
    sources: [
      {
        id: sourceId,
        title: "Report",
        publisher: "Publisher",
        canonical_url: "https://example.test/report",
        published_at: "2026-08-03",
      },
    ],
    actions: [],
    relations: [],
    mainline: [],
  };
}

describe("report-scoped flow matching", () => {
  it("keeps only candidates extracted from the selected report source", () => {
    const analysis = {
      candidates: [{ flow_id: "FLOW-A" }, { flow_id: "FLOW-B" }],
      flows: [flow("FLOW-A", "ART-1234"), flow("FLOW-B", "ART-9999")],
    } as BackendFlowMatchAnalysis;

    const scoped = scopeFlowMatchAnalysisBySource(
      analysis,
      "SRC-DOC-1234",
    );

    expect(scoped.candidates.map((candidate) => candidate.flow_id)).toEqual([
      "FLOW-A",
    ]);
    expect(scoped.flows.map((candidate) => candidate.id)).toEqual(["FLOW-A"]);
  });
});
