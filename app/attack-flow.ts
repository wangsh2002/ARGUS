import { historicalPathCandidate } from "./argus-domain";
import type {
  AttackFlow,
  AttackFlowConfidence,
  PathCandidate,
  Snapshot,
} from "./types";


function confidenceScore(confidence: AttackFlowConfidence) {
  if (confidence === "high") return 0.95;
  if (confidence === "medium") return 0.65;
  return 0.35;
}


function relationLabel(type: AttackFlow["relations"][number]["type"]) {
  return {
    precedes: "有证据先于",
    leads_to: "推进至",
    enables: "使后续行为成为可能",
    causes: "直接触发",
    on_success: "成功后进入",
    on_failure: "失败后进入",
  }[type];
}


function evidenceRecord(
  evidence: AttackFlow["actions"][number]["evidence"][number],
  target: { node_id?: string; edge_id?: string },
) {
  return {
    id: evidence.id,
    path_id: "",
    node_id: target.node_id ?? null,
    edge_id: target.edge_id ?? null,
    source_span_id: evidence.source_span_id,
    support_type: "supports",
    evidence_role: "direct",
    quote: evidence.quote,
    confidence: evidence.confidence,
    review_state: "agent-assisted-reviewed",
    locator: evidence.locator,
    artifact_id: evidence.source_id,
    report_title: evidence.title,
    publisher: evidence.publisher,
    canonical_url: evidence.canonical_url,
  };
}


export function adaptAttackFlowToHistoricalPath(
  flow: AttackFlow,
  previous?: Snapshot["historicalPaths"][number],
): Snapshot["historicalPaths"][number] {
  const actionById = new Map(flow.actions.map((action) => [action.id, action]));
  const mainlineSet = new Set(flow.mainline);
  const orderedActions = [
    ...flow.mainline.flatMap((actionId) => {
      const action = actionById.get(actionId);
      return action ? [action] : [];
    }),
    ...flow.actions.filter((action) => !mainlineSet.has(action.id)),
  ];
  const mainlineRelationIds = flow.mainline.slice(1).flatMap((targetId, index) => {
    const sourceId = flow.mainline[index];
    const relation = flow.relations.find(
      (item) =>
        item.source_action_id === sourceId && item.target_action_id === targetId,
    );
    return relation ? [relation.id] : [];
  });
  const contextLinks = flow.actions.flatMap((action) =>
    action.contexts.map((context) => ({
      id: context.id,
      path_id: flow.id,
      action_node_id: action.id,
      entity_id: context.entity_id,
      role: context.role,
      direction: context.direction,
      first_seen: null,
      last_seen: null,
      assertion_origin: "source-observed",
      review_state: "agent-assisted-reviewed",
      confidence: confidenceScore(context.confidence),
      properties: { context_type: context.type, context_name: context.name },
    })),
  );
  const keyContextByAction = Object.fromEntries(
    flow.actions
      .filter((action) => action.contexts.length > 0)
      .map((action) => [
        action.id,
        action.contexts.map((context) => context.entity_id),
      ]),
  );
  const pathEvidence = [
    ...flow.actions.flatMap((action) =>
      action.evidence.map((evidence) => ({
        ...evidenceRecord(evidence, { node_id: action.id }),
        path_id: flow.id,
      })),
    ),
    ...flow.relations.flatMap((relation) =>
      relation.evidence.map((evidence) => ({
        ...evidenceRecord(evidence, { edge_id: relation.id }),
        path_id: flow.id,
      })),
    ),
  ];
  const contextEvidence = flow.actions.flatMap((action) =>
    action.contexts.flatMap((context) =>
      context.evidence.map((evidence) => ({
        id: evidence.id,
        path_id: flow.id,
        context_link_id: context.id,
        action_node_id: action.id,
        entity_id: context.entity_id,
        source_span_id: evidence.source_span_id,
        support_type: "supports",
        evidence_role: "direct",
        quote: evidence.quote,
        confidence: evidence.confidence,
        review_state: "agent-assisted-reviewed",
        locator: evidence.locator,
        artifact_id: evidence.source_id,
        report_title: evidence.title,
        publisher: evidence.publisher,
        canonical_url: evidence.canonical_url,
      })),
    ),
  );
  return {
    id: flow.id,
    name: flow.title,
    description: flow.description,
    activity_key: previous?.activity_key ?? `attack-flow:${flow.id}`,
    path_kind: previous?.path_kind ?? "historical",
    review_state: previous?.review_state ?? "agent-assisted-reviewed",
    reviewer_type: previous?.reviewer_type ?? "agent-assisted",
    reviewer_id: previous?.reviewer_id ?? null,
    reviewed_at: previous?.reviewed_at ?? null,
    primary_artifact_id: flow.sources[0]?.id ?? null,
    started_at: previous?.started_at ?? null,
    ended_at: previous?.ended_at ?? null,
    victim_scope: previous?.victim_scope ?? "",
    confidence: Math.max(
      ...flow.actions.map((action) => confidenceScore(action.confidence)),
      0.5,
    ),
    metadata: {
      ...(previous?.metadata ?? {}),
      contract: `AttackFlow/${flow.schema_version}`,
      runtime_source: true,
    },
    nodes: orderedActions.map((action, index) => ({
      id: action.id,
      path_id: flow.id,
      entity_id: null,
      occurrence_key: action.id,
      label: action.name,
      node_type: "behavior-action",
      phase: action.phase,
      sequence_hint: index + 1,
      assertion_origin: "source-observed",
      review_state: "agent-assisted-reviewed",
      confidence: confidenceScore(action.confidence),
      properties: {
        description: action.description,
        technique_ids: action.technique_ids,
        mainline_role: mainlineSet.has(action.id) ? "backbone" : "supporting",
      },
    })),
    edges: flow.relations.map((relation) => ({
      id: relation.id,
      path_id: flow.id,
      source_node_id: relation.source_action_id,
      target_node_id: relation.target_action_id,
      edge_type: relation.type,
      branch_group: null,
      condition_label: relation.condition ?? relationLabel(relation.type),
      assertion_origin: "source-observed",
      review_state: "agent-assisted-reviewed",
      confidence: confidenceScore(relation.confidence),
      properties: { attack_flow_relation_type: relation.type },
    })),
    evidence: pathEvidence,
    contextLinks,
    contextEvidence,
    projection: {
      id: `attack-flow-projection:${flow.id}`,
      path_id: flow.id,
      projection_kind: "attack-flow-mainline",
      root_action_refs: flow.mainline.slice(0, 1),
      mainline_action_refs: flow.mainline,
      mainline_dependency_refs: mainlineRelationIds,
      branch_groups: [],
      key_context_by_action: keyContextByAction,
      lane_assignment: Object.fromEntries(
        flow.actions.map((action, index) => [
          action.id,
          { phase: action.phase, lane_order: index + 1 },
        ]),
      ),
      node_state: Object.fromEntries(
        flow.actions.map((action) => [action.id, "observed"]),
      ),
      selection_reason: "AttackFlow V1 显式 mainline",
      algorithm_version: `attack-flow-contract/${flow.schema_version}`,
      generated_at: new Date().toISOString(),
    },
  };
}


export function adaptAttackFlowToPathCandidate(
  flow: AttackFlow,
  previous?: Snapshot["historicalPaths"][number],
): PathCandidate {
  return historicalPathCandidate(adaptAttackFlowToHistoricalPath(flow, previous));
}


export async function requestAttackFlow(flowId: string): Promise<AttackFlow> {
  const response = await fetch(`/api/attack-flows/${encodeURIComponent(flowId)}`, {
    headers: { accept: "application/json" },
    cache: "no-store",
  });
  const payload = (await response.json()) as AttackFlow | { error?: { message?: string } };
  if (
    !response.ok ||
    !("schema_version" in payload) ||
    payload.schema_version !== "1.0" ||
    !Array.isArray(payload.actions) ||
    !Array.isArray(payload.mainline)
  ) {
    const message =
      "error" in payload && payload.error?.message
        ? payload.error.message
        : "AttackFlow 后端没有返回有效数据。";
    throw new Error(message);
  }
  return payload;
}


export async function requestAttackFlows(): Promise<AttackFlow[]> {
  const response = await fetch("/api/attack-flows", {
    headers: { accept: "application/json" },
    cache: "no-store",
  });
  const payload = (await response.json()) as
    | AttackFlow[]
    | { error?: { message?: string } };
  if (!response.ok || !Array.isArray(payload)) {
    throw new Error(
      !Array.isArray(payload) && payload.error?.message
        ? payload.error.message
        : "AttackFlow 后端没有返回有效列表。",
    );
  }
  return payload;
}
