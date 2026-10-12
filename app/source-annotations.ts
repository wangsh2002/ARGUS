import type {
  AttackFlowSourceAnnotation,
  AttackFlowSourceAnnotationKind,
} from "./types";

export type AnnotatedSourceSegment = {
  start: number;
  end: number;
  text: string;
  annotations: AttackFlowSourceAnnotation[];
  primaryKind?: AttackFlowSourceAnnotationKind;
};

const annotationPriority: AttackFlowSourceAnnotationKind[] = [
  "attack-process",
  "ioc",
  "software",
  "vulnerability",
  "asset",
  "actor",
];

export function buildAnnotatedSourceSegments(
  content: string,
  annotations: AttackFlowSourceAnnotation[],
): AnnotatedSourceSegment[] {
  const validAnnotations = annotations.filter(
    (annotation) =>
      Number.isFinite(annotation.start_offset) &&
      Number.isFinite(annotation.end_offset) &&
      annotation.start_offset >= 0 &&
      annotation.end_offset > annotation.start_offset &&
      annotation.start_offset < content.length,
  );
  const boundaries = new Set([0, content.length]);
  validAnnotations.forEach((annotation) => {
    boundaries.add(Math.min(content.length, annotation.start_offset));
    boundaries.add(Math.min(content.length, annotation.end_offset));
  });
  const orderedBoundaries = [...boundaries].sort((left, right) => left - right);

  return orderedBoundaries.slice(0, -1).flatMap((start, index) => {
    const end = orderedBoundaries[index + 1];
    if (end <= start) return [];
    const active = validAnnotations.filter(
      (annotation) =>
        annotation.start_offset < end && annotation.end_offset > start,
    );
    return [
      {
        start,
        end,
        text: content.slice(start, end),
        annotations: active,
        primaryKind: annotationPriority.find((kind) =>
          active.some((annotation) => annotation.kind === kind),
        ),
      },
    ];
  });
}

export function annotationMatchesSelection(
  annotation: AttackFlowSourceAnnotation,
  selectedActionId?: string,
  selectedEntityId?: string,
) {
  if (selectedEntityId && annotation.entity_id === selectedEntityId) return true;
  return Boolean(
    selectedActionId && annotation.action_ids.includes(selectedActionId),
  );
}
