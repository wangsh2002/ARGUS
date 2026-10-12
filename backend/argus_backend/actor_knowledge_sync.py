from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
import unicodedata
from typing import Any


ACTOR_BASELINE_PREFIX = "actor-baseline:"

ACTOR_KNOWLEDGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS actor_external_mappings (
  actor_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  canonical_name TEXT NOT NULL,
  mapping_status TEXT NOT NULL,
  confidence REAL NOT NULL,
  source_url TEXT NOT NULL DEFAULT '',
  source_version TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (source, external_id),
  UNIQUE (actor_id, source)
);

CREATE INDEX IF NOT EXISTS idx_actor_external_mappings_actor
  ON actor_external_mappings(actor_id, source);
CREATE INDEX IF NOT EXISTS idx_relationships_seed_origin
  ON relationships(seed_origin);
CREATE INDEX IF NOT EXISTS idx_aliases_source
  ON aliases(source);
"""


@dataclass(frozen=True)
class ExternalActorIdentity:
    identity_key: str
    attack_group: dict[str, Any] | None
    misp_actor: dict[str, Any] | None


def actor_name_key(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in normalized if character.isalnum())


def actor_name_variants(value: str) -> list[str]:
    key = actor_name_key(value)
    if not key:
        return []
    suffixes = ("group", "team", "gang")
    variants = [key]
    matched_suffix = next(
        (suffix for suffix in suffixes if key.endswith(suffix)), None
    )
    if matched_suffix and len(key) > len(matched_suffix):
        variants.append(key[: -len(matched_suffix)])
    else:
        variants.extend(f"{key}{suffix}" for suffix in suffixes)
    return variants


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _unique_labels(values: list[str]) -> list[str]:
    unique: dict[str, str] = {}
    for value in values:
        key = unicodedata.normalize("NFKC", value).casefold().strip()
        if key and key not in unique:
            unique[key] = value
    return sorted(unique.values(), key=str.casefold)


def _clean_description(value: str) -> str:
    cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", value or "")
    cleaned = re.sub(r"\s*\(Citation:[^)]+\)", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _attack_active_from(group: dict[str, Any] | None) -> str | None:
    if group is None:
        return None
    description = _clean_description(str(group.get("description", "")))
    patterns = (
        r"\bactive since (?:at least |as early as )?(\d{4})\b",
        r"\bactive (?:from|as early as) (\d{4})\b",
    )
    for pattern in patterns:
        match = re.search(pattern, description, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def _external_reference(item: dict[str, Any]) -> tuple[str, str]:
    references = item.get("external_references", [])
    for reference in references:
        if reference.get("source_name") == "mitre-attack":
            return str(reference.get("external_id", "")), str(
                reference.get("url", "")
            )
    return "", ""


def _active_attack_objects(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item
        for item in bundle.get("objects", [])
        if isinstance(item, dict)
        and not item.get("revoked")
        and not item.get("x_mitre_deprecated")
    ]


def _attack_version(bundle: dict[str, Any]) -> str:
    for item in bundle.get("objects", []):
        if item.get("type") == "x-mitre-collection":
            return str(item.get("x_mitre_version", ""))
    return ""


def _index_attack_groups(
    bundle: dict[str, Any],
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, list[dict[str, Any]]],
    dict[str, dict[str, Any]],
    list[dict[str, Any]],
]:
    objects = _active_attack_objects(bundle)
    object_by_id = {str(item.get("id")): item for item in objects}
    groups = {
        str(item["id"]): item
        for item in objects
        if item.get("type") == "intrusion-set"
    }
    groups_by_name: dict[str, list[dict[str, Any]]] = {}
    for group in groups.values():
        for name in [str(group.get("name", "")), *_strings(group.get("aliases"))]:
            key = actor_name_key(name)
            if key:
                groups_by_name.setdefault(key, []).append(group)
    relationships = [
        item
        for item in objects
        if item.get("type") == "relationship"
        and item.get("relationship_type") == "uses"
        and str(item.get("source_ref", "")) in groups
    ]
    return groups, groups_by_name, object_by_id, relationships


def _index_misp_actors(
    bundle: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    actors = {
        str(item["uuid"]): item
        for item in bundle.get("values", [])
        if isinstance(item, dict) and item.get("uuid") and item.get("value")
    }
    actors_by_name: dict[str, list[dict[str, Any]]] = {}
    for actor in actors.values():
        meta = actor.get("meta", {})
        for name in [str(actor.get("value", "")), *_strings(meta.get("synonyms"))]:
            key = actor_name_key(name)
            if key:
                actors_by_name.setdefault(key, []).append(actor)
    return actors, actors_by_name


def _misp_attack_links(
    misp_actors: dict[str, dict[str, Any]],
    attack_groups_by_name: dict[str, list[dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    links: dict[str, dict[str, Any]] = {}
    for misp_id, actor in misp_actors.items():
        meta = actor.get("meta", {})
        candidates: dict[str, dict[str, Any]] = {}
        for name in [str(actor.get("value", "")), *_strings(meta.get("synonyms"))]:
            for group in attack_groups_by_name.get(actor_name_key(name), []):
                candidates[str(group["id"])] = group
        if len(candidates) == 1:
            links[misp_id] = next(iter(candidates.values()))
    return links


def _unique_match(
    index: dict[str, list[dict[str, Any]]], value: str
) -> dict[str, Any] | None:
    exact = {
        str(item.get("id") or item.get("uuid")): item
        for item in index.get(actor_name_key(value), [])
    }
    if len(exact) == 1:
        return next(iter(exact.values()))
    if exact:
        return None
    matches = {
        str(item.get("id") or item.get("uuid")): item
        for variant in actor_name_variants(value)[1:]
        for item in index.get(variant, [])
    }
    return next(iter(matches.values())) if len(matches) == 1 else None


def _actor_identity(
    label: str,
    attack_groups_by_name: dict[str, list[dict[str, Any]]],
    misp_actors_by_name: dict[str, list[dict[str, Any]]],
    misp_attack_links: dict[str, dict[str, Any]],
) -> ExternalActorIdentity:
    attack_group = _unique_match(attack_groups_by_name, label)
    misp_actor = _unique_match(misp_actors_by_name, label)
    if attack_group is None and misp_actor is not None:
        attack_group = misp_attack_links.get(str(misp_actor["uuid"]))
    elif attack_group is not None and misp_actor is not None:
        linked_group = misp_attack_links.get(str(misp_actor["uuid"]))
        if linked_group is None or linked_group.get("id") != attack_group.get("id"):
            misp_actor = None
    if attack_group is not None:
        external_id, _ = _external_reference(attack_group)
        return ExternalActorIdentity(
            identity_key=f"mitre-attack:{external_id or attack_group['id']}",
            attack_group=attack_group,
            misp_actor=misp_actor,
        )
    if misp_actor is not None:
        return ExternalActorIdentity(
            identity_key=f"misp-galaxy:{misp_actor['uuid']}",
            attack_group=None,
            misp_actor=misp_actor,
        )
    return ExternalActorIdentity(
        identity_key=f"local:{actor_name_key(label)}",
        attack_group=None,
        misp_actor=None,
    )


def _preferred_actor_row(
    rows: list[sqlite3.Row], identity: ExternalActorIdentity
) -> sqlite3.Row:
    preferred_names: list[str] = []
    if identity.misp_actor is not None:
        preferred_names.append(str(identity.misp_actor.get("value", "")))
    if identity.attack_group is not None:
        preferred_names.append(str(identity.attack_group.get("name", "")))
    preferred_keys = [actor_name_key(name) for name in preferred_names]
    return sorted(
        rows,
        key=lambda row: (
            preferred_keys.index(actor_name_key(str(row["label"])))
            if actor_name_key(str(row["label"])) in preferred_keys
            else len(preferred_keys),
            -int(row["source_count"]),
            len(str(row["label"])),
            str(row["label"]).casefold(),
        ),
    )[0]


def _misp_profile_values(actor: dict[str, Any] | None) -> dict[str, Any]:
    if actor is None:
        return {
            "motivations": [],
            "target_sectors": [],
            "source_urls": [],
            "active_from": None,
            "origin": "",
            "actor_kind": "",
        }
    meta = actor.get("meta", {})
    motivations = _strings(meta.get("motive")) or _strings(
        meta.get("cfr-type-of-incident")
    )
    target_sectors = []
    for key in ("targeted-sector", "sector", "cfr-target-category"):
        target_sectors.extend(_strings(meta.get(key)))
    classifications = _strings(meta.get("threat-actor-classification"))
    origin = str(
        meta.get("cfr-suspected-state-sponsor") or meta.get("country") or ""
    ).strip()
    return {
        "motivations": _unique_labels(motivations),
        "target_sectors": _unique_labels(target_sectors),
        "source_urls": _strings(meta.get("refs"))[:16],
        "active_from": str(meta.get("since", "")).strip() or None,
        "origin": origin,
        "actor_kind": classifications[0] if classifications else "threat-actor",
    }


def _merge_properties(raw: str, values: dict[str, Any]) -> str:
    try:
        properties = json.loads(raw or "{}")
    except json.JSONDecodeError:
        properties = {}
    properties.update(values)
    return json.dumps(properties, ensure_ascii=False, sort_keys=True)


def _without_actor_identity(raw: str) -> str:
    try:
        properties = json.loads(raw or "{}")
    except json.JSONDecodeError:
        properties = {}
    for key in (
        "actor_identity_status",
        "canonical_actor_id",
        "external_identity_key",
        "external_ids",
        "knowledge_sources",
        "actor_kind",
    ):
        properties.pop(key, None)
    return json.dumps(properties, ensure_ascii=False, sort_keys=True)


def _stable_id(prefix: str, value: str) -> str:
    return f"{prefix}-{sha256(value.encode()).hexdigest()[:20]}"


def _upsert_alias(
    connection: sqlite3.Connection,
    actor_id: str,
    alias: str,
    alias_type: str,
    source: str,
    confidence: float,
    now: str,
) -> bool:
    key = actor_name_key(alias)
    if not key:
        return False
    alias_key = key
    existing = connection.execute(
        "SELECT source FROM aliases WHERE alias_key = ?", (alias_key,)
    ).fetchone()
    if existing and not str(existing["source"]).startswith(ACTOR_BASELINE_PREFIX):
        return False
    connection.execute(
        """
        INSERT INTO aliases (
          id, entity_id, alias, alias_key, alias_type, source, confidence, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(alias_key) DO UPDATE SET
          entity_id = excluded.entity_id,
          alias = excluded.alias,
          alias_type = excluded.alias_type,
          source = excluded.source,
          confidence = excluded.confidence
        """,
        (
            _stable_id("ALIAS-ACTOR", alias_key),
            actor_id,
            alias,
            alias_key,
            alias_type,
            source,
            confidence,
            now,
        ),
    )
    return True


def _upsert_external_entity(
    connection: sqlite3.Connection,
    item: dict[str, Any],
    now: str,
    attack_version: str,
) -> tuple[str, str] | None:
    item_type = str(item.get("type", ""))
    external_id, source_url = _external_reference(item)
    name = str(item.get("name", "")).strip()
    if not name or not external_id:
        return None
    if item_type == "attack-pattern":
        entity_type = "ATT&CK 技术"
        canonical_key = f"attack-technique:{external_id.casefold()}"
        label = external_id
    elif item_type in {"malware", "tool"}:
        entity_type = "恶意软件/工具"
        canonical_key = f"attack-software:{external_id.casefold()}"
        label = name
    else:
        return None
    row = connection.execute(
        "SELECT id, properties_json FROM entities WHERE canonical_key = ?",
        (canonical_key,),
    ).fetchone()
    if row is None and item_type in {"malware", "tool"}:
        row = connection.execute(
            """
            SELECT id, properties_json FROM entities
            WHERE entity_type = ? AND normalized_value = ?
            ORDER BY source_count DESC, id LIMIT 1
            """,
            (entity_type, actor_name_key(name)),
        ).fetchone()
    entity_id = str(row["id"]) if row else _stable_id("ENT-ATTACK", external_id)
    existing_key = canonical_key
    existing_label = label
    if row:
        existing = connection.execute(
            "SELECT canonical_key, label FROM entities WHERE id = ?", (entity_id,)
        ).fetchone()
        existing_key = str(existing["canonical_key"])
        existing_label = str(existing["label"])
    properties = _merge_properties(
        str(row["properties_json"]) if row else "{}",
        {
            "sub": name,
            "attack_id": external_id,
            "source_scope": "public-baseline",
            "source_name": "MITRE ATT&CK",
            "source_url": source_url,
            "source_version": attack_version,
        },
    )
    description = _clean_description(str(item.get("description", "")))
    connection.execute(
        """
        INSERT INTO entities (
          id, entity_type, canonical_key, label, normalized_value, description,
          first_seen, last_seen, source_count, created_at, updated_at,
          properties_json, seed_origin
        ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, 1, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          description = CASE WHEN excluded.description <> '' THEN excluded.description ELSE entities.description END,
          properties_json = excluded.properties_json,
          updated_at = excluded.updated_at
        """,
        (
            entity_id,
            entity_type,
            existing_key,
            existing_label,
            external_id.casefold() if entity_type == "ATT&CK 技术" else actor_name_key(name),
            description,
            now,
            now,
            properties,
            f"{ACTOR_BASELINE_PREFIX}mitre-attack:{attack_version}",
        ),
    )
    return entity_id, source_url


def sync_actor_knowledge(
    database_path: Path,
    attack_bundle: dict[str, Any],
    misp_bundle: dict[str, Any],
    *,
    synced_at: str | None = None,
) -> dict[str, Any]:
    now = synced_at or datetime.now(timezone.utc).isoformat()
    attack_version = _attack_version(attack_bundle)
    misp_version = str(misp_bundle.get("version", ""))
    attack_groups, attack_groups_by_name, attack_objects, attack_relationships = (
        _index_attack_groups(attack_bundle)
    )
    misp_actors, misp_actors_by_name = _index_misp_actors(misp_bundle)
    misp_attack_links = _misp_attack_links(misp_actors, attack_groups_by_name)

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(ACTOR_KNOWLEDGE_SCHEMA)
        actor_rows = connection.execute(
            """
            SELECT id, label, normalized_value, description, first_seen,
                   last_seen, source_count, properties_json
            FROM entities
            WHERE entity_type = '攻击组织'
            ORDER BY label, id
            """
        ).fetchall()
        for row in actor_rows:
            connection.execute(
                "UPDATE entities SET properties_json = ? WHERE id = ?",
                (_without_actor_identity(str(row["properties_json"])), str(row["id"])),
            )
        grouped: dict[str, list[tuple[sqlite3.Row, ExternalActorIdentity]]] = {}
        for row in actor_rows:
            identity = _actor_identity(
                str(row["label"]),
                attack_groups_by_name,
                misp_actors_by_name,
                misp_attack_links,
            )
            grouped.setdefault(identity.identity_key, []).append((row, identity))

        connection.execute(
            "DELETE FROM aliases WHERE source LIKE ?", (f"{ACTOR_BASELINE_PREFIX}%",)
        )
        connection.execute("DELETE FROM actor_external_mappings")
        connection.execute(
            "DELETE FROM relationships WHERE seed_origin LIKE ?",
            (f"{ACTOR_BASELINE_PREFIX}%",),
        )

        canonical_by_attack_id: dict[str, str] = {}
        actor_count = 0
        alias_count = 0
        mapped_actor_count = 0
        merged_name_count = 0

        for members in grouped.values():
            identity = members[0][1]
            rows = [row for row, _ in members]
            canonical_row = _preferred_actor_row(rows, identity)
            canonical_id = str(canonical_row["id"])
            canonical_label = str(canonical_row["label"])
            attack_group = identity.attack_group
            candidate_misp = [
                member_identity.misp_actor
                for _, member_identity in members
                if member_identity.misp_actor is not None
            ]
            misp_actor = candidate_misp[0] if candidate_misp else identity.misp_actor
            if attack_group is not None and misp_actor is None:
                linked = [
                    actor
                    for misp_id, actor in misp_actors.items()
                    if misp_attack_links.get(misp_id, {}).get("id")
                    == attack_group.get("id")
                ]
                misp_actor = linked[0] if linked else None
            misp_values = _misp_profile_values(misp_actor)
            attack_external_id = ""
            attack_url = ""
            source_refs: list[str] = []
            source_urls = list(misp_values["source_urls"])
            description = str(canonical_row["description"])
            if attack_group is not None:
                attack_external_id, attack_url = _external_reference(attack_group)
                if attack_external_id:
                    source_refs.append(attack_external_id)
                    canonical_by_attack_id[str(attack_group["id"])] = canonical_id
                if attack_url:
                    source_urls.insert(0, attack_url)
                attack_description = _clean_description(
                    str(attack_group.get("description", ""))
                )
                if attack_description:
                    description = attack_description
            if misp_actor is not None:
                source_refs.append(f"MISP:{misp_actor['uuid']}")
            source_refs = list(dict.fromkeys(source_refs))
            source_urls = list(dict.fromkeys(url for url in source_urls if url))[:16]
            source_names = []
            if attack_group is not None:
                source_names.append(f"MITRE ATT&CK {attack_external_id}".strip())
            if misp_actor is not None:
                source_names.append("MISP Galaxy")
            origin = str(misp_values["origin"])
            origin_label = " · ".join(
                [item for item in [origin, " / ".join(source_names)] if item]
            ) or "当前仅有本库报告观测"
            profile_status = (
                "verified"
                if attack_group is not None
                else "agent-assisted-reviewed"
                if misp_actor is not None
                else "partial"
            )
            source_grade = 1.0 if attack_group and misp_actor else 0.95 if attack_group else 0.82 if misp_actor else 0.6
            public_attribution = (
                description
                if attack_group is not None or misp_actor is not None
                else f"{canonical_label} 当前只有本库报告中的活动观测，尚未匹配权威外部组织画像。"
            )
            properties = _merge_properties(
                str(canonical_row["properties_json"]),
                {
                    "actor_identity_status": "canonical",
                    "actor_kind": misp_values["actor_kind"] or "unclassified",
                    "external_identity_key": identity.identity_key,
                    "external_ids": source_refs,
                    "knowledge_sources": source_names,
                },
            )
            connection.execute(
                """
                UPDATE entities
                SET description = ?, properties_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (description, properties, now, canonical_id),
            )
            connection.execute(
                """
                INSERT INTO actor_profiles (
                  actor_id, profile_status, origin_label, active_from, active_to,
                  public_attribution, motivations_json, target_sectors_json,
                  source_refs_json, source_urls_json, source_grade, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(actor_id) DO UPDATE SET
                  profile_status = excluded.profile_status,
                  origin_label = excluded.origin_label,
                  active_from = excluded.active_from,
                  active_to = excluded.active_to,
                  public_attribution = excluded.public_attribution,
                  motivations_json = excluded.motivations_json,
                  target_sectors_json = excluded.target_sectors_json,
                  source_refs_json = excluded.source_refs_json,
                  source_urls_json = excluded.source_urls_json,
                  source_grade = excluded.source_grade,
                  updated_at = excluded.updated_at
                """,
                (
                    canonical_id,
                    profile_status,
                    origin_label,
                    misp_values["active_from"] or _attack_active_from(attack_group),
                    None,
                    public_attribution,
                    json.dumps(misp_values["motivations"], ensure_ascii=False),
                    json.dumps(misp_values["target_sectors"], ensure_ascii=False),
                    json.dumps(source_refs, ensure_ascii=False),
                    json.dumps(source_urls, ensure_ascii=False),
                    source_grade,
                    now,
                ),
            )
            actor_count += 1
            if attack_group is not None or misp_actor is not None:
                mapped_actor_count += 1

            external_aliases: list[tuple[str, str, str, float]] = []
            if attack_group is not None:
                external_aliases.extend(
                    (
                        name,
                        "exact-alias",
                        f"{ACTOR_BASELINE_PREFIX}mitre-attack:{attack_version}",
                        0.95,
                    )
                    for name in [
                        str(attack_group.get("name", "")),
                        *_strings(attack_group.get("aliases")),
                    ]
                )
            if misp_actor is not None:
                external_aliases.extend(
                    (
                        name,
                        "associated-name",
                        f"{ACTOR_BASELINE_PREFIX}misp-galaxy:{misp_version}",
                        0.82,
                    )
                    for name in [
                        str(misp_actor.get("value", "")),
                        *_strings(misp_actor.get("meta", {}).get("synonyms")),
                    ]
                )
            external_aliases.extend(
                (
                    str(row["label"]),
                    "exact-alias" if attack_group is not None else "associated-name",
                    f"{ACTOR_BASELINE_PREFIX}identity-resolution",
                    0.95 if attack_group is not None else 0.82,
                )
                for row in rows
            )
            for alias, alias_type, source, confidence in external_aliases:
                if actor_name_key(alias) == actor_name_key(canonical_label):
                    continue
                alias_identity = _actor_identity(
                    alias,
                    attack_groups_by_name,
                    misp_actors_by_name,
                    misp_attack_links,
                )
                if alias_identity.identity_key != identity.identity_key:
                    continue
                if _upsert_alias(
                    connection,
                    canonical_id,
                    alias,
                    alias_type,
                    source,
                    confidence,
                    now,
                ):
                    alias_count += 1

            for row in rows:
                row_id = str(row["id"])
                if row_id == canonical_id:
                    continue
                merged_name_count += 1
                alias_properties = _merge_properties(
                    str(row["properties_json"]),
                    {
                        "actor_identity_status": "alias",
                        "canonical_actor_id": canonical_id,
                        "external_identity_key": identity.identity_key,
                    },
                )
                connection.execute(
                    "UPDATE entities SET properties_json = ?, updated_at = ? WHERE id = ?",
                    (alias_properties, now, row_id),
                )
                connection.execute(
                    "DELETE FROM actor_profiles WHERE actor_id = ?", (row_id,)
                )

            if attack_group is not None:
                connection.execute(
                    """
                    INSERT INTO actor_external_mappings (
                      actor_id, source, external_id, canonical_name, mapping_status,
                      confidence, source_url, source_version, metadata_json, updated_at
                    ) VALUES (?, 'mitre-attack', ?, ?, 'exact-alias', 0.95, ?, ?, ?, ?)
                    """,
                    (
                        canonical_id,
                        attack_external_id or str(attack_group["id"]),
                        str(attack_group.get("name", canonical_label)),
                        attack_url,
                        attack_version,
                        json.dumps(
                            {"stix_id": attack_group["id"]}, ensure_ascii=False
                        ),
                        now,
                    ),
                )
            if misp_actor is not None:
                misp_urls = _strings(misp_actor.get("meta", {}).get("refs"))
                connection.execute(
                    """
                    INSERT INTO actor_external_mappings (
                      actor_id, source, external_id, canonical_name, mapping_status,
                      confidence, source_url, source_version, metadata_json, updated_at
                    ) VALUES (?, 'misp-galaxy', ?, ?, 'associated-name', 0.82, ?, ?, ?, ?)
                    """,
                    (
                        canonical_id,
                        str(misp_actor["uuid"]),
                        str(misp_actor.get("value", canonical_label)),
                        misp_urls[0] if misp_urls else "",
                        misp_version,
                        json.dumps(
                            {"actor_kind": misp_values["actor_kind"]},
                            ensure_ascii=False,
                        ),
                        now,
                    ),
                )

        baseline_relationship_count = 0
        for relationship in attack_relationships:
            actor_id = canonical_by_attack_id.get(str(relationship.get("source_ref")))
            target = attack_objects.get(str(relationship.get("target_ref")))
            if actor_id is None or target is None:
                continue
            target_result = _upsert_external_entity(
                connection, target, now, attack_version
            )
            if target_result is None:
                continue
            target_id, target_url = target_result
            relation_type = (
                "uses-technique"
                if target.get("type") == "attack-pattern"
                else "uses"
            )
            source_group = attack_groups.get(str(relationship.get("source_ref")))
            _, group_url = _external_reference(source_group or {})
            source_urls = [url for url in [group_url, target_url] if url]
            relationship_id = _stable_id(
                "REL-ACTOR-BASELINE", f"{actor_id}|{relation_type}|{target_id}"
            )
            connection.execute(
                """
                INSERT INTO relationships (
                  id, source_entity_id, target_entity_id, relation_type,
                  canonical_key, confidence, evidence_count, first_seen,
                  last_seen, created_at, updated_at, category, status,
                  properties_json, seed_origin
                ) VALUES (?, ?, ?, ?, ?, 0.95, ?, NULL, NULL, ?, ?, ?, 'positive', ?, ?)
                """,
                (
                    relationship_id,
                    actor_id,
                    target_id,
                    relation_type,
                    f"actor-baseline:{actor_id}:{relation_type}:{target_id}",
                    len(source_urls),
                    now,
                    now,
                    "technique" if relation_type == "uses-technique" else "software",
                    json.dumps(
                        {
                            "source_scope": "public-baseline",
                            "source_name": "MITRE ATT&CK",
                            "source_version": attack_version,
                            "source_urls": source_urls,
                            "relationship_description": _clean_description(
                                str(relationship.get("description", ""))
                            ),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    f"{ACTOR_BASELINE_PREFIX}mitre-attack:{attack_version}",
                ),
            )
            baseline_relationship_count += 1

        alias_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM aliases WHERE source LIKE ?",
                (f"{ACTOR_BASELINE_PREFIX}%",),
            ).fetchone()[0]
        )
        connection.commit()

    return {
        "actor_entities": len(actor_rows),
        "canonical_actors": actor_count,
        "mapped_actors": mapped_actor_count,
        "merged_names": merged_name_count,
        "aliases": alias_count,
        "baseline_relationships": baseline_relationship_count,
        "attack_version": attack_version,
        "misp_version": misp_version,
        "synced_at": now,
    }
