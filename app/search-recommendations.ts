import type {
  AttackFlow,
  Entity,
  RuntimeCatalog,
  Report,
  SearchMode,
} from "./types";
import {
  curatedGptExamples,
  curatedIntelLabels,
  curatedPathExamples,
} from "./showcase-config";

export type SearchExample = {
  label: string;
  query: string;
  note: string;
};

function entityScore(entity: Entity) {
  const readableLength = entity.label.length <= 72 ? 40 : 0;
  return entity.source_count * 100 + readableLength - entity.label.length;
}

function bestEntity(entities: Entity[], type: string) {
  return entities
    .filter(
      (entity) =>
        entity.entity_type === type &&
        entity.source_count > 0 &&
        entity.label.trim().length >= 2,
    )
    .sort(
      (left, right) =>
        entityScore(right) - entityScore(left) ||
        left.label.localeCompare(right.label),
    )[0];
}

function mainlineActions(flow: AttackFlow) {
  const actionById = new Map(flow.actions.map((action) => [action.id, action]));
  return flow.mainline
    .map((id) => actionById.get(id))
    .filter((action): action is AttackFlow["actions"][number] => Boolean(action));
}

function flowScore(flow: AttackFlow) {
  const contextCount = flow.actions.reduce(
    (total, action) => total + action.contexts.length,
    0,
  );
  const evidenceCount = flow.actions.reduce(
    (total, action) => total + action.evidence.length,
    0,
  );
  return (
    mainlineActions(flow).length * 12 +
    Math.min(contextCount, 24) * 2 +
    Math.min(evidenceCount, 16) +
    (flow.reported_actors?.length ?? 0) * 8
  );
}

function flowLabel(flow: AttackFlow) {
  return flow.reported_actors?.[0]?.reported_name || flow.title;
}

function entityFlowMetrics(entity: Entity, flows: AttackFlow[]) {
  const flowIds = new Set<string>();
  const evidenceIds = new Set<string>();
  const relatedEntityIds = new Set<string>();
  const normalizedLabel = entity.label.trim().toLocaleLowerCase();
  flows.forEach((flow) => {
    let matched = false;
    flow.actions.forEach((action) => {
      action.contexts.forEach((context) => {
        const contextMatches = context.entity_id
          ? context.entity_id === entity.id
          : context.name.trim().toLocaleLowerCase() === normalizedLabel;
        if (!contextMatches) return;
        matched = true;
        context.evidence.forEach((evidence) => evidenceIds.add(evidence.id));
      });
    });
    flow.reported_actors?.forEach((actor) => {
      if (
        actor.actor_id !== entity.id &&
        actor.reported_name.trim().toLocaleLowerCase() !== normalizedLabel
      ) {
        return;
      }
      matched = true;
      actor.evidence.forEach((evidence) => evidenceIds.add(evidence.id));
    });
    if (matched) {
      flowIds.add(flow.id);
      flow.actions.forEach((action) =>
        action.contexts.forEach((context) => {
          if (context.entity_id && context.entity_id !== entity.id) {
            relatedEntityIds.add(context.entity_id);
          }
        }),
      );
    }
  });
  return {
    flowCount: flowIds.size,
    evidenceCount: evidenceIds.size,
    relatedEntityCount: relatedEntityIds.size,
  };
}

export function normalizedFlowSourceRef(sourceId: string) {
  return sourceId.startsWith("ART-")
    ? `SRC-DOC-${sourceId.slice("ART-".length)}`
    : sourceId;
}

export function analysisInputForReport(report: Report, flows: AttackFlow[]) {
  const relatedFlows = flowsForReport(report, flows)
    .sort(
      (left, right) =>
        right.actions.length - left.actions.length ||
        left.title.localeCompare(right.title),
    );
  const selectedFlows =
    relatedFlows.length > 1 ? relatedFlows.slice(0, 2) : relatedFlows;
  return selectedFlows
    .flatMap((flow) => {
      const actions = mainlineActions(flow);
      const first = actions[0];
      const frontier = actions[Math.min(2, actions.length - 1)];
      return [first?.name, frontier?.name].filter(
        (name, index, values) => Boolean(name) && values.indexOf(name) === index,
      );
    })
    .join("\n");
}

export function flowsForReport(report: Report, flows: AttackFlow[]) {
  return flows
    .filter((flow) =>
      flow.sources.some(
        (source) => normalizedFlowSourceRef(source.id) === report.source_ref,
      ),
    );
}

function uniqueActionByFlow(flows: AttackFlow[]) {
  const owners = new Map<string, Set<string>>();
  flows.forEach((flow) => {
    flow.actions.forEach((action) => {
      const key = action.name.trim().toLocaleLowerCase();
      if (!key) return;
      const flowIds = owners.get(key) ?? new Set<string>();
      flowIds.add(flow.id);
      owners.set(key, flowIds);
    });
  });
  return owners;
}

export function buildIntelExamples(
  catalog: RuntimeCatalog,
  flows: AttackFlow[] = [],
): SearchExample[] {
  const curated = curatedIntelLabels.flatMap((label) => {
    const entity = catalog.entities.find(
      (candidate) =>
        candidate.label.toLocaleLowerCase() === label.toLocaleLowerCase() ||
        candidate.normalized_value.toLocaleLowerCase() === label.toLocaleLowerCase(),
    );
    if (!entity) return [];
    const metrics = entityFlowMetrics(entity, flows);
    const metricLabel =
      entity.entity_type === "攻击组织" ? "历史活动" : "攻击流";
    return [{
      label: entity.label,
      query: entity.label,
      note: metrics.flowCount
        ? entity.entity_type === "攻击组织"
          ? `${metrics.flowCount} 条${metricLabel}·${metrics.relatedEntityCount} 个关联实体`
          : `${metrics.flowCount} 条${metricLabel}·${metrics.evidenceCount} 条原文证据`
        : `${entity.entity_type}·${entity.source_count} 个来源支撑`,
    }];
  });
  if (curated.length === curatedIntelLabels.length) return curated;

  const representativeTypes = [
    "IOC/基础设施",
    "攻击组织",
    "恶意软件/工具",
    "CVE",
    "ATT&CK 技术",
  ];
  return representativeTypes
    .map((type) => bestEntity(catalog.entities, type))
    .filter((entity): entity is Entity => Boolean(entity))
    .map((entity) => ({
      label: entity.label,
      query: entity.label,
      note: `${entity.entity_type}·${entity.source_count} 个来源支撑`,
    }));
}

export function buildPathExamples(flows: AttackFlow[]): SearchExample[] {
  const availableActions = new Set(
    flows.flatMap((flow) =>
      flow.actions.map((action) => action.name.trim().toLocaleLowerCase()),
    ),
  );
  const curated = curatedPathExamples
    .filter((example) =>
      example.requiredActions.every((action) =>
        availableActions.has(action.toLocaleLowerCase()),
      ),
    )
    .map(({ label, query, note }) => ({ label, query, note }));
  if (curated.length === curatedPathExamples.length) return curated;

  const ranked = [...flows]
    .filter((flow) => mainlineActions(flow).length >= 4)
    .sort(
      (left, right) =>
        flowScore(right) - flowScore(left) || left.title.localeCompare(right.title),
    );
  const examples: SearchExample[] = [];
  const partialFlow = ranked.find((flow) => mainlineActions(flow).length >= 5);
  if (partialFlow) {
    const actions = mainlineActions(partialFlow);
    examples.push({
      label: `${flowLabel(partialFlow)} · 部分链路补全`,
      query: `${actions[1].name} → ${actions[3].name}`,
      note: "输入间隔行为，展示缺失步骤补全与后续预测",
    });
  }

  const predictionFlow = ranked.find((flow) => flow.id !== partialFlow?.id);
  if (predictionFlow) {
    const actions = mainlineActions(predictionFlow);
    examples.push({
      label: `${flowLabel(predictionFlow)} · 后续行为预测`,
      query: `${actions[0].name} → ${actions[1].name}`,
      note: "仅输入攻击初段，展示历史攻击流的后续步骤",
    });
  }

  const actionOwners = uniqueActionByFlow(ranked);
  const multiFlowInputs = ranked.flatMap((flow) => {
    const action = [...mainlineActions(flow)]
      .reverse()
      .find(
        (candidate) =>
          actionOwners.get(candidate.name.trim().toLocaleLowerCase())?.size === 1,
      );
    return action ? [{ flow, action }] : [];
  });
  const first = multiFlowInputs[0];
  const second = multiFlowInputs.find((item) => item.flow.id !== first?.flow.id);
  if (first && second) {
    examples.push({
      label: "跨报告告警 · 多链匹配",
      query: `EDR alert A: ${first.action.name}; EDR alert B: ${second.action.name}`,
      note: `一次输入同时检验 ${flowLabel(first.flow)} 与 ${flowLabel(second.flow)} 两条攻击链`,
    });
  }
  return examples;
}

export function buildGptExamples(catalog: RuntimeCatalog): SearchExample[] {
  const availableLabels = new Set(
    catalog.entities.map((entity) => entity.label.toLocaleLowerCase()),
  );
  const curated = curatedGptExamples
    .filter((example) =>
      example.requiredLabels.every((label) =>
        availableLabels.has(label.toLocaleLowerCase()),
      ),
    )
    .map(({ label, query, note }) => ({ label, query, note }));
  if (curated.length === curatedGptExamples.length) return curated;

  const actor = bestEntity(catalog.entities, "攻击组织");
  const tool = bestEntity(catalog.entities, "恶意软件/工具");
  return [
    actor
      ? {
          label: `总结 ${actor.label} 攻击路径`,
          query: `根据公开报告总结 ${actor.label} 的攻击路径、关键 IOC 与证据来源`,
          note: "组织、攻击步骤、IOC 与历史报告联合分析",
        }
      : undefined,
    tool
      ? {
          label: `梳理 ${tool.label} 攻击过程`,
          query: `梳理 ${tool.label} 在已入库报告中的攻击过程和处置重点`,
          note: "恶意软件、工具与关联攻击链联合分析",
        }
      : undefined,
  ].filter((example): example is SearchExample => Boolean(example));
}

export function buildSearchExamples(
  mode: SearchMode,
  catalog: RuntimeCatalog,
  flows: AttackFlow[],
) {
  if (mode === "path") return buildPathExamples(flows);
  if (mode === "gpt") return buildGptExamples(catalog);
  return buildIntelExamples(catalog, flows);
}
