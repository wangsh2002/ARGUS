import type {
  AttackFlow,
  AttackActivityCluster,
  BackendFlowMatchAnalysis,
  BackendFlowMatchRun,
  PathCandidate,
  PathCandidateLink,
  PathCandidateStep,
} from "./types";


function flowConfidence(value: AttackFlow["actions"][number]["confidence"]) {
  if (value === "high") return 0.95;
  if (value === "medium") return 0.65;
  return 0.35;
}


function flowRelationLabel(type: AttackFlow["relations"][number]["type"]) {
  return {
    precedes: "有证据先于",
    leads_to: "推进至",
    enables: "使后续行为成为可能",
    causes: "直接触发",
    on_success: "成功后进入",
    on_failure: "失败后进入",
  }[type];
}


export async function requestFlowMatchAnalysis(
  content: string,
): Promise<BackendFlowMatchAnalysis> {
  const response = await fetch("/api/flow-matches", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query_text: content }),
  });
  const payload = (await response.json()) as
    | BackendFlowMatchRun
    | { error?: { message?: string } };
  if (!response.ok || !("id" in payload) || !Array.isArray(payload.candidates)) {
    throw new Error(
      "error" in payload
        ? payload.error?.message || "攻击流后端没有返回有效匹配结果。"
        : "攻击流后端没有返回有效匹配结果。",
    );
  }
  const flowsResponse = await fetch("/api/attack-flows", {
    headers: { accept: "application/json" },
    cache: "no-store",
  });
  const flowsPayload = (await flowsResponse.json()) as
    | AttackFlow[]
    | { error?: { message?: string } };
  if (!flowsResponse.ok || !Array.isArray(flowsPayload)) {
    throw new Error(
      !Array.isArray(flowsPayload) && flowsPayload.error?.message
        ? flowsPayload.error.message
        : "无法读取匹配候选对应的 AttackFlow。",
    );
  }
  return { ...payload, flows: flowsPayload };
}


export function adaptBackendFlowMatches(
  analysis: BackendFlowMatchAnalysis,
): AttackActivityCluster[] {
  const flowById = new Map(analysis.flows.map((flow) => [flow.id, flow]));
  return analysis.candidates.flatMap((result, rank) => {
    const flow = flowById.get(result.flow_id);
    if (!flow) return [];
    const actionById = new Map(flow.actions.map((action) => [action.id, action]));
    const mainlineSet = new Set(flow.mainline);
    const orderedActions = [
      ...flow.mainline.flatMap((actionId) => {
        const action = actionById.get(actionId);
        return action ? [action] : [];
      }),
      ...flow.actions.filter((action) => !mainlineSet.has(action.id)),
    ];
    const stateByAction = new Map(
      result.action_states.map((item) => [item.action_id, item.state]),
    );
    const matchesByAction = new Map<string, (typeof result.matches)[number][]>();
    result.matches.forEach((item) => {
      matchesByAction.set(item.action_id, [
        ...(matchesByAction.get(item.action_id) ?? []),
        item,
      ]);
    });
    const stepIdByAction = new Map(
      orderedActions.map((action) => [action.id, `flow-match-step-${action.id}`]),
    );
    const steps: PathCandidateStep[] = orderedActions.map((action) => {
      const actionMatches = matchesByAction.get(action.id) ?? [];
      const backendState = stateByAction.get(action.id) ?? "reference";
      return {
        id: stepIdByAction.get(action.id) as string,
        pathNodeId: action.id,
        contextEntityIds: action.contexts.map((context) => context.entity_id),
        label: action.name,
        description: action.description,
        phase: action.phase,
        analysisState: backendState === "input_hit" ? "observed" : backendState,
        confidence:
          actionMatches.length > 0
            ? Math.max(...actionMatches.map((item) => item.confidence))
            : flowConfidence(action.confidence),
        evidenceCount: action.evidence.length,
        matchKind: actionMatches[0]?.match_kind,
        matchReason: actionMatches.map((item) => item.explanation).join("；"),
      };
    });
    const links: PathCandidateLink[] = flow.relations.flatMap((relation) => {
      const sourceStepId = stepIdByAction.get(relation.source_action_id);
      const targetStepId = stepIdByAction.get(relation.target_action_id);
      if (!sourceStepId || !targetStepId) return [];
      const sourceState = stateByAction.get(relation.source_action_id);
      const targetState = stateByAction.get(relation.target_action_id);
      return [{
        id: `flow-match-link-${relation.id}`,
        sourceStepId,
        targetStepId,
        label: relation.condition || flowRelationLabel(relation.type),
        reviewStatus:
          targetState === "predicted"
            ? "predicted"
            : sourceState === "reconstructed" || targetState === "reconstructed"
              ? "suggested"
              : "observed",
        confidence: flowConfidence(relation.confidence),
      }];
    });
    const hitCount = result.matches.filter((item) => item.match_kind !== "attack").length;
    const reconstructedCount = result.action_states.filter((item) => item.state === "reconstructed").length;
    const predictedCount = result.action_states.filter((item) => item.state === "predicted").length;
    const unmatchedLabels = result.unmatched_inputs.map((item) => item.value);
    const candidate: PathCandidate = {
      id: `flow-match-candidate-${analysis.id}-${flow.id}`,
      activityId: `flow-match-activity-${flow.id}`,
      historicalPathId: flow.id,
      title: flow.title,
      summary: `命中 ${hitCount} 条具体线索，路径补全 ${reconstructedCount} 步，后续预测 ${predictedCount} 步。`,
      reason: result.matches.map((item) => item.explanation).join(" "),
      gap: unmatchedLabels.length
        ? `未解释线索：${unmatchedLabels.join("、")}。`
        : "本次输入线索均已获得候选内解释，仍需结合本地证据复核。",
      confidence: result.score,
      sourceCount: flow.sources.length,
      disposition: rank === 0 ? "primary" : "candidate",
      steps,
      links,
      analysisQuery: analysis.query_text,
      backendAnalysisId: analysis.id,
      knowledgeSnapshot: analysis.knowledge_snapshot,
    };
    return [{
      id: candidate.activityId as string,
      title: flow.title,
      summary: candidate.summary,
      scope: flow.sources.map((source) => source.publisher).join("、") || "已归档来源",
      timeRange: `匹配运行 ${analysis.id}`,
      confidence: result.score,
      sourceCount: flow.sources.length,
      disposition: result.score >= 0.75 ? "confirmed" : "review",
      sharedSteps: [],
      candidates: [candidate],
    }];
  });
}
