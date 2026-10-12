import { describe, expect, it } from "vitest";
import {
  annotationMatchesSelection,
  buildAnnotatedSourceSegments,
} from "../app/source-annotations";
import type { AttackFlowSourceAnnotation } from "../app/types";

function annotation(
  values: Partial<AttackFlowSourceAnnotation>,
): AttackFlowSourceAnnotation {
  return {
    id: "annotation-1",
    kind: "attack-process",
    label: "下载载荷",
    start_offset: 0,
    end_offset: 4,
    quote: "download",
    confidence: 0.95,
    action_ids: ["action-1"],
    entity_id: null,
    evidence_ids: ["evidence-1"],
    ...values,
  };
}

describe("source annotation projection", () => {
  it("splits overlapping annotations without dropping source text", () => {
    const content = "0123456789";
    const segments = buildAnnotatedSourceSegments(content, [
      annotation({ start_offset: 1, end_offset: 6 }),
      annotation({
        id: "annotation-2",
        kind: "ioc",
        label: "example.test",
        start_offset: 4,
        end_offset: 9,
      }),
    ]);

    expect(segments.map((segment) => segment.text).join("")).toBe(content);
    expect(
      segments.find((segment) => segment.start === 4 && segment.end === 6)
        ?.annotations,
    ).toHaveLength(2);
    expect(
      segments.find((segment) => segment.start === 4 && segment.end === 6)
        ?.primaryKind,
    ).toBe("attack-process");
  });

  it("matches graph actions and context entities independently", () => {
    const contextAnnotation = annotation({
      kind: "ioc",
      action_ids: ["action-2"],
      entity_id: "entity-1",
    });

    expect(annotationMatchesSelection(contextAnnotation, "action-2")).toBe(true);
    expect(
      annotationMatchesSelection(contextAnnotation, undefined, "entity-1"),
    ).toBe(true);
    expect(annotationMatchesSelection(contextAnnotation, "action-3")).toBe(false);
  });
});
