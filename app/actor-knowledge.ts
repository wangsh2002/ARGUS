import type {
  ActorKnowledgeSlice,
  Entity,
  Relationship,
} from "./types";


function isActorKnowledgeSlice(value: unknown): value is ActorKnowledgeSlice {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<ActorKnowledgeSlice>;
  return Boolean(
    candidate.meta &&
      typeof candidate.meta.version === "string" &&
      typeof candidate.meta.generated_at === "string" &&
      candidate.scope &&
      Array.isArray(candidate.scope.actor_ids) &&
      Array.isArray(candidate.scope.entity_ids) &&
      Array.isArray(candidate.scope.relationship_ids) &&
      Array.isArray(candidate.actors) &&
      Array.isArray(candidate.entities) &&
      Array.isArray(candidate.relationships) &&
      Array.isArray(candidate.evidence) &&
      Array.isArray(candidate.reports) &&
      Array.isArray(candidate.aliases),
  );
}


export async function requestActorKnowledge(): Promise<ActorKnowledgeSlice> {
  const response = await fetch("/api/actor-knowledge", {
    cache: "no-store",
    headers: { accept: "application/json" },
  });
  const payload = (await response.json()) as
    | ActorKnowledgeSlice
    | { error?: { message?: string } };
  if (!response.ok || !isActorKnowledgeSlice(payload)) {
    throw new Error(
      "error" in payload
        ? payload.error?.message || "组织知识暂时不可用。"
        : "组织知识接口返回了无效数据。",
    );
  }
  return payload;
}


function otherEntityId(relationship: Relationship, entityId: string) {
  return relationship.source_entity_id === entityId
    ? relationship.target_entity_id
    : relationship.source_entity_id;
}


export function actorContextEntities(
  data: ActorKnowledgeSlice,
  actorId: string,
): {
  entities: Entity[];
  relationships: Relationship[];
} {
  const entityMap = new Map(data.entities.map((entity) => [entity.id, entity]));
  const adjacency = new Map<string, Relationship[]>();
  data.relationships.forEach((relationship) => {
    [relationship.source_entity_id, relationship.target_entity_id].forEach(
      (entityId) => {
        const current = adjacency.get(entityId) ?? [];
        current.push(relationship);
        adjacency.set(entityId, current);
      },
    );
  });
  const direct = adjacency.get(actorId) ?? [];
  const activities = direct
    .map((relationship) =>
      entityMap.get(otherEntityId(relationship, actorId)),
    )
    .filter(
      (entity): entity is Entity => entity?.entity_type === "历史事件",
    );
  const activityIds = new Set(activities.map((activity) => activity.id));
  const relationshipIds = new Set(direct.map((relationship) => relationship.id));
  const entityIds = new Set(
    direct.flatMap((relationship) => [
      relationship.source_entity_id,
      relationship.target_entity_id,
    ]),
  );
  const queue = [...activityIds];
  const traversed = new Set(activityIds);
  while (queue.length) {
    const currentId = queue.shift() as string;
    (adjacency.get(currentId) ?? []).forEach((relationship) => {
      const neighbor = entityMap.get(otherEntityId(relationship, currentId));
      if (!neighbor || neighbor.entity_type === "攻击组织") return;
      if (
        neighbor.entity_type === "历史事件" &&
        !activityIds.has(neighbor.id)
      ) {
        return;
      }
      relationshipIds.add(relationship.id);
      entityIds.add(neighbor.id);
      if (
        neighbor.entity_type === "攻击步骤" &&
        !traversed.has(neighbor.id)
      ) {
        traversed.add(neighbor.id);
        queue.push(neighbor.id);
      }
    });
  }
  return {
    entities: [...entityIds]
      .map((id) => entityMap.get(id))
      .filter((entity): entity is Entity => Boolean(entity)),
    relationships: data.relationships.filter((relationship) =>
      relationshipIds.has(relationship.id),
    ),
  };
}
