#!/usr/bin/env python3
"""Index AnnoCTR actor mentions without treating them as attribution.

The script canonicalizes dataset GROUP labels against the official MITRE
ATT&CK STIX bundle, creates partial profiles for unmatched activity clusters,
and stores actor-to-report mention edges with exact line evidence.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
import unicodedata


VARIANT_SUFFIXES = ("_w_con", "_w_neg", "_w_con_w_neg")
EXCLUDED_GROUP_LINKS = {
    # AnnoCTR marks Orz as GROUP, but S0229 is ATT&CK Software.
    "https://attack.mitre.org/software/S0229",
    # “Magecart-type” is a generic ecosystem label in this report, not a
    # uniquely attributable actor.
    "http://www.bosch.com#node1frhbstcrx1",
}
FANCY_BEAR_DATASET_LINK = "http://www.bosch.com#node1fvup9pj1x36"
FANCY_LAZARUS_DATASET_LINK = "http://www.bosch.com#node1g7env4v1x9"
TA453_DATASET_LINK = "http://www.bosch.com#node1g7env4v1x8"
BERSERK_BEAR_DATASET_LINK = "http://www.bosch.com#node1fsmh11c3x16"
EXISTING_LABEL_OVERRIDES = {
    "G0007": "APT28",
    "G0010": "Turla",
    "G0016": "APT29",
    "G0032": "Lazarus",
}


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=root / "data" / "corpus" / "annoctr_actor_coverage_manifest.json",
    )
    parser.add_argument(
        "--supplemental-manifest",
        type=Path,
        default=root
        / "data"
        / "corpus"
        / "annoctr_actor_supplement_manifest.json",
    )
    parser.add_argument(
        "--reviewed-links",
        type=Path,
        default=root / "data" / "corpus" / "annoctr_ext_actor_review.json",
    )
    parser.add_argument(
        "--dataset-root",
        type=Path,
        default=(root / "data" / "corpus" / "upstream" / "anno-ctr-lrec-coling-2024"),
    )
    parser.add_argument(
        "--attack-bundle",
        type=Path,
        default=(
            root
            / "data"
            / "corpus"
            / "upstream"
            / "mitre-attack-v19.1"
            / "enterprise-attack.json"
        ),
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=root / "data" / "argus_cti.db",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def normalized(value: str) -> str:
    value = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", " ", value).strip()


def short_hash(value: str, length: int = 12) -> str:
    return sha256(value.encode()).hexdigest()[:length]


def mitre_groups(bundle_path: Path) -> tuple[dict[str, dict], dict[str, str]]:
    bundle = json.loads(bundle_path.read_text())
    groups: dict[str, dict] = {}
    alias_index: dict[str, str] = {}
    for item in bundle["objects"]:
        if item.get("type") != "intrusion-set":
            continue
        if item.get("revoked", False) or item.get("x_mitre_deprecated", False):
            continue
        reference = next(
            (
                ref
                for ref in item.get("external_references", [])
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id")
            ),
            None,
        )
        if reference is None:
            continue
        attack_id = str(reference["external_id"])
        aliases = list(dict.fromkeys([item["name"], *item.get("aliases", [])]))
        groups[attack_id] = {
            "attack_id": attack_id,
            "name": str(item["name"]),
            "description": str(item.get("description", "")).replace("\n", " "),
            "aliases": aliases,
            "url": str(reference.get("url", "")),
            "modified": str(item.get("modified", "")),
        }
        for alias in aliases:
            alias_index.setdefault(normalized(alias), attack_id)
    return groups, alias_index


def base_linking_files(linking_root: Path) -> list[Path]:
    return [
        path
        for path in sorted(linking_root.glob("*.json"))
        if not any(path.stem.endswith(suffix) for suffix in VARIANT_SUFFIXES)
    ]


def dataset_mentions(linking_root: Path) -> list[dict]:
    rows: list[dict] = []
    for path in base_linking_files(linking_root):
        for raw_line in path.read_text().splitlines():
            if not raw_line.strip():
                continue
            item = json.loads(raw_line)
            if item.get("entity_type") != "GROUP":
                continue
            if item.get("label_link") in EXCLUDED_GROUP_LINKS:
                continue
            link = str(item["label_link"])
            label = str(item["label_title"])
            allow_alias_match = True
            use_mention_as_alias = True
            if link == FANCY_BEAR_DATASET_LINK:
                # This annotation belongs to the Fancy Lazarus report and
                # captures names that the extortion actor impersonated. It is
                # report evidence for Fancy Lazarus, not an APT28 alias.
                link = FANCY_LAZARUS_DATASET_LINK
                label = "Fancy Lazarus"
                allow_alias_match = False
                use_mention_as_alias = False
            elif link == TA453_DATASET_LINK:
                # The report body consistently identifies TA543/JSSLoader.
                label = "TA543"
                allow_alias_match = False
            elif link == BERSERK_BEAR_DATASET_LINK:
                # ATT&CK currently lists this alias for two overlapping
                # Dragonfly records, so a blind alias merge is not auditable.
                allow_alias_match = False
            rows.append(
                {
                    "document": str(item["document"]),
                    "mention": str(item["mention"]),
                    "label": label,
                    "link": link,
                    "allow_alias_match": allow_alias_match,
                    "use_mention_as_alias": use_mention_as_alias,
                }
            )
    return rows


def actor_key(
    row: dict,
    alias_index: dict[str, str],
) -> tuple[str, str | None]:
    match = re.search(r"/groups/(G\d+)", row["link"])
    if match:
        return f"mitre:{match.group(1)}", match.group(1)
    attack_id = (
        alias_index.get(normalized(row["label"]))
        if row.get("allow_alias_match", True)
        else None
    )
    if attack_id:
        return f"mitre:{attack_id}", attack_id
    return f"annoctr:{row['link']}", None


def report_rows(manifest_paths: list[Path]) -> dict[str, dict]:
    reports: dict[str, dict] = {}
    for manifest_path in manifest_paths:
        manifest = json.loads(manifest_path.read_text())
        reports.update(
            {
                Path(report["source_path"]).stem: report
                for report in manifest["reports"]
            }
        )
    return reports


def source_span(
    connection: sqlite3.Connection,
    document_id: str,
    mentions: set[str],
    preferred_line: int | None = None,
) -> sqlite3.Row | None:
    rows = connection.execute(
        """
        SELECT id, locator, line_start, text
        FROM source_spans
        WHERE source_document_id = ?
        ORDER BY line_start, id
        """,
        (document_id,),
    ).fetchall()
    candidates = sorted(
        {mention for mention in mentions if mention.strip()},
        key=lambda value: (-len(value), value.casefold()),
    )
    if preferred_line is not None:
        for row in rows:
            if row["line_start"] != preferred_line:
                continue
            if any(
                normalized(mention) in normalized(str(row["text"]))
                for mention in candidates
            ):
                return row
    for mention in candidates:
        needle = normalized(mention)
        for row in rows:
            if needle and needle in normalized(str(row["text"])):
                return row
    return None


def main() -> int:
    args = parse_args()
    now = datetime.now(timezone.utc).isoformat()
    groups, alias_index = mitre_groups(args.attack_bundle.resolve())
    reports = report_rows(
        [args.manifest.resolve(), args.supplemental_manifest.resolve()]
    )
    mentions = dataset_mentions(
        args.dataset_root.resolve() / "AnnoCTR" / "all" / "linking"
    )
    actors: dict[str, dict] = {}
    actor_reports: dict[tuple[str, str], set[str]] = defaultdict(set)
    actor_report_review_lines: dict[tuple[str, str], int] = {}
    for row in mentions:
        if row["document"] not in reports:
            continue
        key, attack_id = actor_key(row, alias_index)
        if key not in actors:
            if attack_id:
                mitre = groups[attack_id]
                actors[key] = {
                    "key": key,
                    "attack_id": attack_id,
                    "label": EXISTING_LABEL_OVERRIDES.get(attack_id, mitre["name"]),
                    "aliases": set(mitre["aliases"]),
                    "description": mitre["description"],
                    "source_url": mitre["url"],
                    "profile_status": "verified",
                    "origin_label": f"MITRE ATT&CK {attack_id}",
                    "source_grade": 0.82,
                }
            else:
                actors[key] = {
                    "key": key,
                    "attack_id": None,
                    "label": row["label"],
                    "aliases": set(),
                    "description": (
                        "AnnoCTR 原始报告中以该名称跟踪的攻击活动簇；"
                        "当前尚未与 MITRE ATT&CK 组织完成可靠归并。"
                    ),
                    "source_url": row["link"],
                    "profile_status": "internal_cluster",
                    "origin_label": "AnnoCTR 报告索引活动簇 · 待归并",
                    "source_grade": 0.56,
                }
        actors[key]["aliases"].add(row["label"])
        if row.get("use_mention_as_alias", True):
            actors[key]["aliases"].add(row["mention"])
        actor_reports[(key, row["document"])].add(row["mention"])

    reviewed_links = json.loads(args.reviewed_links.resolve().read_text())
    for item in reviewed_links["accepted"]:
        key = str(item["actor_key"])
        document = str(item["document"])
        if key not in actors:
            raise ValueError(f"Reviewed actor key is not canonicalized: {key}")
        if document not in reports:
            raise ValueError(f"Reviewed report is missing from manifests: {document}")
        actor_reports[(key, document)].add(str(item["mention"]))
        actor_report_review_lines[(key, document)] = int(item["evidence_line"])

    coverage: dict[str, set[str]] = defaultdict(set)
    for actor_key_value, document in actor_reports:
        coverage[actor_key_value].add(document)
    summary = {
        "actors": len(actors),
        "mitre_actors": sum(
            actor["attack_id"] is not None for actor in actors.values()
        ),
        "internal_clusters": sum(
            actor["attack_id"] is None for actor in actors.values()
        ),
        "actor_report_links": len(actor_reports),
        "actors_with_three_reports": sum(
            len(documents) >= 3 for documents in coverage.values()
        ),
        "actors_with_two_reports": sum(
            len(documents) == 2 for documents in coverage.values()
        ),
        "actors_with_one_report": sum(
            len(documents) == 1 for documents in coverage.values()
        ),
        "actor_report_gap_to_three": sum(
            max(0, 3 - len(documents)) for documents in coverage.values()
        ),
        "excluded_annotation_anomalies": len(EXCLUDED_GROUP_LINKS),
    }
    if args.dry_run:
        print(json.dumps(summary, ensure_ascii=False))
        return 0

    with sqlite3.connect(args.database.resolve()) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        indexed_report_ids = {
            f"RPT-CORPUS-{str(report['sha256'])[:16]}"
            for report in reports.values()
        }
        indexed_source_urls = {
            str(report["canonical_url"]) for report in reports.values()
        }
        importer_actor_ids = {
            str(row["id"])
            for row in connection.execute(
                """
                SELECT id
                FROM entities
                WHERE entity_type = '攻击组织'
                  AND seed_origin = 'annoctr-actor-report-index'
                """
            )
        }
        for profile in connection.execute(
            """
            SELECT actor_id, source_refs_json, source_urls_json
            FROM actor_profiles
            """
        ).fetchall():
            source_refs = [
                value
                for value in json.loads(profile["source_refs_json"])
                if value not in indexed_report_ids
            ]
            source_urls = [
                value
                for value in json.loads(profile["source_urls_json"])
                if value not in indexed_source_urls
            ]
            connection.execute(
                """
                UPDATE actor_profiles
                SET source_refs_json = ?, source_urls_json = ?, updated_at = ?
                WHERE actor_id = ?
                """,
                (
                    json.dumps(source_refs, ensure_ascii=False),
                    json.dumps(source_urls, ensure_ascii=False),
                    now,
                    profile["actor_id"],
                ),
            )
        connection.execute(
            """
            DELETE FROM evidence
            WHERE relationship_id IN (
              SELECT id FROM relationships
              WHERE seed_origin = 'annoctr-actor-report-index'
            )
            """
        )
        connection.execute(
            """
            DELETE FROM relationships
            WHERE seed_origin = 'annoctr-actor-report-index'
            """
        )
        connection.execute(
            """
            DELETE FROM aliases
            WHERE source IN ('MITRE ATT&CK v19.1', 'AnnoCTR GROUP index')
            """
        )
        if importer_actor_ids:
            placeholders = ",".join("?" for _ in importer_actor_ids)
            connection.execute(
                f"DELETE FROM actor_profiles WHERE actor_id IN ({placeholders})",
                tuple(importer_actor_ids),
            )
            connection.execute(
                f"DELETE FROM entities WHERE id IN ({placeholders})",
                tuple(importer_actor_ids),
            )
        connection.execute(
            """
            DELETE FROM entities
            WHERE entity_type = '情报报告'
              AND seed_origin = 'annoctr-actor-report-index'
            """
        )
        connection.execute(
            """
            DELETE FROM import_jobs
            WHERE stage = 'actor-index'
            """
        )
        existing_actor_by_alias: dict[str, str] = {}
        for row in connection.execute(
            """
            SELECT e.id, e.label, a.alias
            FROM entities e
            LEFT JOIN aliases a ON a.entity_id = e.id
            WHERE e.entity_type = '攻击组织'
            """
        ):
            existing_actor_by_alias[normalized(str(row["label"]))] = row["id"]
            if row["alias"]:
                existing_actor_by_alias[normalized(str(row["alias"]))] = row["id"]

        entity_ids: dict[str, str] = {}
        report_ids: dict[str, str] = {}
        for document, report in reports.items():
            digest = str(report["sha256"])
            report_id = f"RPT-CORPUS-{digest[:16]}"
            report_ids[document] = report_id
            report_entity_id = f"ENT-REPORT-{digest[:12]}"
            connection.execute(
                """
                INSERT INTO entities (
                  id, entity_type, canonical_key, label, normalized_value,
                  description, first_seen, last_seen, source_count,
                  created_at, updated_at, properties_json, seed_origin
                ) VALUES (?, '情报报告', ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  label = excluded.label,
                  description = excluded.description,
                  updated_at = excluded.updated_at,
                  properties_json = excluded.properties_json
                """,
                (
                    report_entity_id,
                    f"情报报告:{digest}",
                    report["title"],
                    digest,
                    f"{report['publisher']} 发布的公开威胁情报原文。",
                    report["published_at"],
                    report["published_at"],
                    now,
                    now,
                    json.dumps(
                        {
                            "ui_type": "report",
                            "report_id": report_id,
                            "source_ref": f"SRC-DOC-{digest[:16]}",
                            "confidence": 1.0,
                        },
                        ensure_ascii=False,
                    ),
                    "annoctr-actor-report-index",
                ),
            )
            job_id = f"JOB-ACTORIDX-{digest[:12]}"
            connection.execute(
                """
                INSERT INTO import_jobs (
                  id, report_id, title, status, stage, entity_count,
                  relation_count, published_entity_count,
                  published_relation_count, created_at, updated_at, published_at
                ) VALUES (?, ?, ?, '已发布', 'actor-index', 1, 0, 1, 0, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at
                """,
                (job_id, report_id, report["title"], now, now, now),
            )

        for key, actor in sorted(actors.items()):
            aliases = sorted(actor["aliases"], key=str.casefold)
            existing_id = next(
                (
                    existing_actor_by_alias[normalized(alias)]
                    for alias in [actor["label"], *aliases]
                    if normalized(alias) in existing_actor_by_alias
                ),
                None,
            )
            entity_id = existing_id or f"ENT-ACTOR-{short_hash(key)}"
            entity_ids[key] = entity_id
            documents = sorted(coverage[key])
            dates = sorted(reports[document]["published_at"] for document in documents)
            source_refs = [report_ids[document] for document in documents]
            source_urls = [reports[document]["canonical_url"] for document in documents]
            connection.execute(
                """
                INSERT INTO entities (
                  id, entity_type, canonical_key, label, normalized_value,
                  description, first_seen, last_seen, source_count,
                  created_at, updated_at, properties_json, seed_origin
                ) VALUES (?, '攻击组织', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  source_count = MAX(entities.source_count, excluded.source_count),
                  updated_at = excluded.updated_at
                """,
                (
                    entity_id,
                    f"攻击组织:{normalized(actor['label'])}",
                    actor["label"],
                    normalized(actor["label"]),
                    actor["description"],
                    dates[0],
                    dates[-1],
                    len(documents),
                    now,
                    now,
                    json.dumps(
                        {
                            "ui_type": "actor",
                            "actor": actor["label"],
                            "sub": actor["origin_label"],
                            "confidence": actor["source_grade"],
                            "attack_id": actor["attack_id"],
                            "report_coverage": len(documents),
                        },
                        ensure_ascii=False,
                    ),
                    "annoctr-actor-report-index",
                ),
            )
            existing_profile = connection.execute(
                """
                SELECT profile_status, source_refs_json, source_urls_json
                FROM actor_profiles
                WHERE actor_id = ?
                """,
                (entity_id,),
            ).fetchone()
            if existing_profile is None:
                connection.execute(
                    """
                    INSERT INTO actor_profiles (
                      actor_id, profile_status, origin_label, active_from,
                      active_to, public_attribution, motivations_json,
                      target_sectors_json, source_refs_json, source_urls_json,
                      source_grade, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, '[]', '[]', ?, ?, ?, ?)
                    """,
                    (
                        entity_id,
                        actor["profile_status"],
                        actor["origin_label"],
                        dates[0],
                        dates[-1],
                        actor["description"],
                        json.dumps(source_refs, ensure_ascii=False),
                        json.dumps(source_urls, ensure_ascii=False),
                        actor["source_grade"],
                        now,
                    ),
                )
            else:
                merged_source_refs = list(
                    dict.fromkeys(
                        [
                            *json.loads(existing_profile["source_refs_json"]),
                            *source_refs,
                        ]
                    )
                )
                merged_source_urls = list(
                    dict.fromkeys(
                        [
                            *json.loads(existing_profile["source_urls_json"]),
                            *source_urls,
                        ]
                    )
                )
                connection.execute(
                    """
                    UPDATE actor_profiles
                    SET source_refs_json = ?,
                        source_urls_json = ?,
                        updated_at = ?
                    WHERE actor_id = ?
                    """,
                    (
                        json.dumps(merged_source_refs, ensure_ascii=False),
                        json.dumps(merged_source_urls, ensure_ascii=False),
                        now,
                        entity_id,
                    ),
                )
            for alias in aliases:
                alias_value = alias.strip()
                alias_key = normalized(alias_value)
                if not alias_key or alias_key == normalized(actor["label"]):
                    continue
                connection.execute(
                    """
                    INSERT OR IGNORE INTO aliases (
                      id, entity_id, alias, alias_key, alias_type, source,
                      confidence, created_at
                    ) VALUES (?, ?, ?, ?, '组织命名映射', ?, ?, ?)
                    """,
                    (
                        f"ALS-ACTOR-{short_hash(f'{entity_id}:{alias_key}', 16)}",
                        entity_id,
                        alias_value,
                        alias_key,
                        (
                            "MITRE ATT&CK v19.1"
                            if actor["attack_id"]
                            else "AnnoCTR GROUP index"
                        ),
                        0.96 if actor["attack_id"] else 0.76,
                        now,
                    ),
                )

        for (key, document), mention_values in sorted(actor_reports.items()):
            actor_id = entity_ids[key]
            report = reports[document]
            digest = str(report["sha256"])
            report_id = report_ids[document]
            report_entity_id = f"ENT-REPORT-{digest[:12]}"
            relation_key = f"{actor_id}:报告提及:{report_entity_id}"
            relationship_id = f"REL-ACTORIDX-{short_hash(relation_key, 16)}"
            source_document_id = f"SRC-DOC-{digest[:16]}"
            span = source_span(
                connection,
                source_document_id,
                mention_values,
                actor_report_review_lines.get((key, document)),
            )
            if span is None:
                raise RuntimeError(
                    f"No exact source line for {actors[key]['label']} in {document}"
                )
            connection.execute(
                """
                INSERT INTO relationships (
                  id, source_entity_id, target_entity_id, relation_type,
                  canonical_key, confidence, evidence_count, first_seen,
                  last_seen, created_at, updated_at, category, status,
                  properties_json, seed_origin
                ) VALUES (
                  ?, ?, ?, '报告提及', ?, 0.82, 1, ?, ?, ?, ?, 'identity',
                  'partial', ?, ?
                )
                ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at
                """,
                (
                    relationship_id,
                    actor_id,
                    report_entity_id,
                    relation_key,
                    report["published_at"],
                    report["published_at"],
                    now,
                    now,
                    json.dumps(
                        {
                            "claim_scope": "name-mention-only",
                            "attribution": False,
                            "selection_basis": (
                                "manual-review-of-annoctr-ext-report"
                                if (key, document) in actor_report_review_lines
                                else "annoctr-group-annotation-index-only"
                            ),
                            "review_note": (
                                (
                                    "A reviewer confirmed this actor is a report "
                                    "subject or has a substantive behavior section."
                                )
                                if (key, document) in actor_report_review_lines
                                else (
                                    "The source report mentions this actor name. "
                                    "This edge is not an attribution judgment."
                                )
                            ),
                        },
                        ensure_ascii=False,
                    ),
                    "annoctr-actor-report-index",
                ),
            )
            evidence_id = f"EVD-ACTORIDX-{short_hash(relation_key, 16)}"
            connection.execute(
                """
                INSERT INTO evidence (
                  id, relationship_id, report_id, job_id, excerpt, confidence,
                  created_at, source_ref, location
                ) VALUES (?, ?, ?, ?, ?, 0.82, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  excerpt = excluded.excerpt,
                  source_ref = excluded.source_ref,
                  location = excluded.location
                """,
                (
                    evidence_id,
                    relationship_id,
                    report_id,
                    f"JOB-ACTORIDX-{digest[:12]}",
                    span["text"],
                    now,
                    source_document_id,
                    span["locator"],
                ),
            )
            connection.execute(
                """
                UPDATE import_jobs
                SET relation_count = relation_count + 1,
                    published_relation_count = published_relation_count + 1,
                    updated_at = ?
                WHERE id = ?
                  AND NOT EXISTS (
                    SELECT 1 FROM evidence
                    WHERE id = ? AND created_at <> ?
                  )
                """,
                (
                    now,
                    f"JOB-ACTORIDX-{digest[:12]}",
                    evidence_id,
                    now,
                ),
            )

    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
