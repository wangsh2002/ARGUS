import {
  adaptAttackFlowToHistoricalPath,
} from "./attack-flow";
import type {
  ActorKnowledgeSlice,
  AttackFlow,
  Entity,
  IntelligenceWorkspace,
  PathWorkspace,
  RuntimeCatalog,
  RuntimeEntityIntelligence,
  Snapshot,
  SourceArtifact,
} from "./types";


async function requestJson<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    cache: "no-store",
    headers: { accept: "application/json" },
  });
  const payload = (await response.json()) as T & {
    error?: { message?: string };
  };
  if (!response.ok) {
    throw new Error(payload.error?.message || `运行时知识接口返回 ${response.status}。`);
  }
  return payload;
}


export async function requestRuntimeCatalog() {
  const payload = await requestJson<
    Omit<RuntimeCatalog, "responseRules"> & {
      response_rules: RuntimeCatalog["responseRules"];
    }
  >("/api/runtime/catalog");
  return {
    ...payload,
    responseRules: payload.response_rules,
  };
}


export function requestEntityIntelligence(entityId: string) {
  return requestJson<RuntimeEntityIntelligence>(
    `/api/runtime/entities/${encodeURIComponent(entityId)}`,
  );
}


function confidenceScore(value: AttackFlow["actions"][number]["confidence"]) {
  if (value === "high") return 0.95;
  if (value === "medium") return 0.65;
  return 0.35;
}


function contextEntity(
  context: AttackFlow["actions"][number]["contexts"][number],
  previous?: Entity,
): Entity {
  const entityType =
    context.type === "vulnerability"
      ? "CVE"
      : ["malware", "tool"].includes(context.type)
        ? "恶意软件/工具"
        : ["asset", "account"].includes(context.type)
          ? "资产"
          : "IOC/基础设施";
  return {
    id: context.entity_id,
    entity_type: previous?.entity_type ?? entityType,
    canonical_key: previous?.canonical_key ?? `attack-flow-context:${context.entity_id}`,
    label: context.name,
    normalized_value: previous?.normalized_value ?? context.name.toLocaleLowerCase(),
    description: previous?.description ?? "",
    first_seen: previous?.first_seen ?? null,
    last_seen: previous?.last_seen ?? null,
    source_count: Math.max(previous?.source_count ?? 0, context.evidence.length),
    properties: {
      ...(previous?.properties ?? {}),
      confidence: confidenceScore(context.confidence),
      context_type: context.type,
      runtime_source: true,
    },
  };
}


function sourceArtifact(flow: AttackFlow): SourceArtifact[] {
  return flow.sources.map((source) => ({
    id: source.id,
    collection_id: "runtime",
    collection_record_id: source.id,
    title: source.title,
    publisher: source.publisher,
    canonical_url: source.canonical_url,
    acquisition_source: "runtime-api",
    acquisition_url: source.canonical_url,
    published_at: source.published_at,
    collected_at: "",
    mime_type: "",
    size_bytes: 0,
    sha256: "",
    storage_path: "",
    dataset_license: "",
    source_license: "",
    tlp: "TLP:CLEAR",
    archive_status: "text-only",
    canonical_verification_state: "unverified",
    canonical_verified_at: null,
    review_state: "agent-assisted-reviewed",
    metadata: { runtime_source: true, flow_id: flow.id },
  }));
}


function uniqueById<T extends { id: string }>(items: T[]) {
  return [...new Map(items.map((item) => [item.id, item])).values()];
}


export function buildPathWorkspace(
  catalog: RuntimeCatalog,
  flows: AttackFlow[],
  actorKnowledge?: ActorKnowledgeSlice,
): PathWorkspace {
  const knownEntities = new Map(catalog.entities.map((entity) => [entity.id, entity]));
  const contextEntities = flows.flatMap((flow) =>
    flow.actions.flatMap((action) =>
      action.contexts.map((context) =>
        contextEntity(context, knownEntities.get(context.entity_id)),
      ),
    ),
  );
  return {
    meta: {
      source: catalog.meta.source,
      generated_at: catalog.meta.generated_at,
      is_demo: false,
    },
    stats: catalog.stats,
    entities: uniqueById([
      ...catalog.entities,
      ...(actorKnowledge?.entities ?? []),
      ...contextEntities,
    ]),
    relationships: actorKnowledge?.relationships ?? [],
    evidence: actorKnowledge?.evidence ?? [],
    reports: uniqueById([...catalog.reports, ...(actorKnowledge?.reports ?? [])]),
    aliases: uniqueById([...catalog.aliases, ...(actorKnowledge?.aliases ?? [])]),
    historicalPaths: flows.map((flow) => adaptAttackFlowToHistoricalPath(flow)),
    sourceArtifacts: uniqueById(flows.flatMap(sourceArtifact)),
    actors: actorKnowledge?.actors ?? [],
    responseRules: catalog.responseRules,
    algorithms: catalog.algorithms,
  };
}


export function adaptEntityIntelligence(
  catalog: RuntimeCatalog,
  readModel: RuntimeEntityIntelligence,
): IntelligenceWorkspace {
  const knownEntities = new Map(
    [...catalog.entities, ...readModel.entities].map((entity) => [entity.id, entity]),
  );
  const contextEntities = readModel.attack_flows.flatMap((flow) =>
    flow.actions.flatMap((action) =>
      action.contexts.map((context) =>
        contextEntity(context, knownEntities.get(context.entity_id)),
      ),
    ),
  );
  return {
    entities: uniqueById([...readModel.entities, ...contextEntities]),
    relationships: readModel.relationships,
    evidence: readModel.evidence,
    reports: readModel.reports,
    aliases: catalog.aliases.filter((alias) =>
      readModel.entities.some((entity) => entity.id === alias.entity_id),
    ),
    historicalPaths: readModel.attack_flows.map((flow) =>
      adaptAttackFlowToHistoricalPath(flow),
    ),
    sourceArtifacts: uniqueById([
      ...readModel.source_artifacts,
      ...readModel.attack_flows.flatMap(sourceArtifact),
    ]),
  };
}


export function catalogFromFixture(fixture: Snapshot): RuntimeCatalog {
  return {
    meta: {
      source: fixture.meta.source,
      generated_at: fixture.meta.generated_at,
      version: "explicit-test-fixture",
    },
    stats: fixture.stats,
    entities: fixture.entities,
    reports: fixture.reports,
    aliases: fixture.aliases,
    responseRules: fixture.responseRules,
    algorithms: fixture.algorithms,
  };
}


export function actorKnowledgeFromFixture(
  fixture: Snapshot,
): ActorKnowledgeSlice {
  return {
    meta: {
      source: fixture.meta.source,
      generated_at: fixture.meta.generated_at,
      version: "explicit-test-fixture",
    },
    scope: {
      actor_ids: fixture.actors.map((actor) => actor.id),
      entity_ids: fixture.entities.map((entity) => entity.id),
      relationship_ids: fixture.relationships.map((relationship) => relationship.id),
    },
    actors: fixture.actors,
    entities: fixture.entities,
    relationships: fixture.relationships,
    evidence: fixture.evidence,
    reports: fixture.reports,
    aliases: fixture.aliases,
  };
}


export function pathWorkspaceFromFixture(
  fixture: Snapshot,
  flows: AttackFlow[],
): PathWorkspace {
  if (!flows.length) return fixture;
  const runtime = buildPathWorkspace(
    catalogFromFixture(fixture),
    flows,
    actorKnowledgeFromFixture(fixture),
  );
  const runtimePathIds = new Set(runtime.historicalPaths.map((path) => path.id));
  return {
    ...fixture,
    entities: uniqueById([...fixture.entities, ...runtime.entities]),
    reports: uniqueById([...fixture.reports, ...runtime.reports]),
    sourceArtifacts: uniqueById([
      ...fixture.sourceArtifacts,
      ...runtime.sourceArtifacts,
    ]),
    historicalPaths: [
      ...fixture.historicalPaths.filter((path) => !runtimePathIds.has(path.id)),
      ...runtime.historicalPaths,
    ],
  };
}
