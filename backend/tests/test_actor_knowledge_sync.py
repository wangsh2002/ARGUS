from pathlib import Path
import shutil
import sqlite3

from argus_backend.actor_knowledge_sync import actor_name_variants, sync_actor_knowledge
from argus_backend.attack_flow_publication import AttackFlowPublicationService
from argus_backend.repository import SqliteRepository


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_actor_name_variants_only_add_structural_suffixes() -> None:
    assert actor_name_variants("Lazarus") == [
        "lazarus",
        "lazarusgroup",
        "lazarusteam",
        "lazarusgang",
    ]
    assert actor_name_variants("Lazarus Group") == ["lazarusgroup", "lazarus"]


def attack_bundle() -> dict:
    return {
        "objects": [
            {
                "type": "x-mitre-collection",
                "id": "x-mitre-collection--test",
                "x_mitre_version": "test-1",
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--apt28",
                "name": "APT28",
                "aliases": ["Fancy Bear", "Sofacy"],
                "description": "A versioned public actor profile active since at least 2004.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "G0007",
                        "url": "https://attack.mitre.org/groups/G0007/",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--test",
                "name": "Test Technique",
                "description": "A public technique description.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T9999",
                        "url": "https://attack.mitre.org/techniques/T9999/",
                    }
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--test",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt28",
                "target_ref": "attack-pattern--test",
            },
        ]
    }


def misp_bundle() -> dict:
    return {
        "version": 1,
        "values": [
            {
                "uuid": "misp-apt28",
                "value": "APT28",
                "meta": {
                    "synonyms": ["Fancy Bear", "Sofacy"],
                    "cfr-suspected-state-sponsor": "Russian Federation",
                    "cfr-target-category": ["Government"],
                    "cfr-type-of-incident": "Espionage",
                    "refs": ["https://example.test/apt28"],
                },
            }
        ],
    }


def test_sync_canonicalizes_aliases_and_is_idempotent(tmp_path: Path) -> None:
    database_path = tmp_path / "argus_cti.db"
    shutil.copy2(REPOSITORY_ROOT / "data" / "argus_cti.db", database_path)

    first = sync_actor_knowledge(
        database_path,
        attack_bundle(),
        misp_bundle(),
        synced_at="2026-08-03T00:00:00+00:00",
    )
    second = sync_actor_knowledge(
        database_path,
        attack_bundle(),
        misp_bundle(),
        synced_at="2026-08-03T00:01:00+00:00",
    )

    assert first["baseline_relationships"] == 1
    assert second["baseline_relationships"] == 1

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        apt28 = connection.execute(
            "SELECT id FROM entities WHERE entity_type = '攻击组织' AND label = 'APT28'"
        ).fetchone()
        fancy_bear = connection.execute(
            "SELECT properties_json FROM entities "
            "WHERE entity_type = '攻击组织' AND label = 'Fancy Bear'"
        ).fetchone()
        alias = connection.execute(
            "SELECT entity_id FROM aliases WHERE alias_key = 'fancybear'"
        ).fetchone()
        relationships = connection.execute(
            "SELECT COUNT(*) FROM relationships "
            "WHERE seed_origin LIKE 'actor-baseline:%'"
        ).fetchone()[0]

    assert apt28 is not None
    assert fancy_bear is not None
    assert f'"canonical_actor_id": "{apt28["id"]}"' in fancy_bear["properties_json"]
    assert alias["entity_id"] == apt28["id"]
    assert relationships == 1

    projection = SqliteRepository(database_path).load_actor_knowledge_slice()
    actor_labels = {actor["label"] for actor in projection["actors"]}
    assert "APT28" in actor_labels
    assert "Fancy Bear" not in actor_labels
    apt28_projection = next(
        actor for actor in projection["actors"] if actor["label"] == "APT28"
    )
    assert apt28_projection["target_sectors"] == ["Government"]
    assert apt28_projection["motivations"] == ["Espionage"]
    assert apt28_projection["active_from"] == "2004"
    assert apt28_projection["active_to"] is None
    assert any(
        relationship["source_entity_id"] == apt28_projection["id"]
        and relationship["relation_type"] == "uses-technique"
        and relationship["properties"]["source_scope"] == "public-baseline"
        for relationship in projection["relationships"]
    )


def test_publication_resolves_duplicate_actor_node_to_canonical_identity() -> None:
    entities = [
        {
            "id": "ACTOR-APT28",
            "entity_type": "攻击组织",
            "label": "APT28",
            "properties_json": '{"actor_identity_status":"canonical"}',
        },
        {
            "id": "ACTOR-FANCY-BEAR",
            "entity_type": "攻击组织",
            "label": "Fancy Bear",
            "properties_json": (
                '{"actor_identity_status":"alias",'
                '"canonical_actor_id":"ACTOR-APT28"}'
            ),
        },
    ]
    aliases = [
        {
            "entity_id": "ACTOR-APT28",
            "alias_key": "fancybear",
        }
    ]

    assert (
        AttackFlowPublicationService._resolve_actor(
            "Fancy Bear", entities, aliases
        )
        == "ACTOR-APT28"
    )
