#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from argus_backend.entity_evidence import (  # noqa: E402
    EntityEvidenceIngestionService,
    NON_INDICATOR_FILE_SUFFIXES,
    STRONG_IOC_PATTERN,
)
from argus_backend.entity_resolution import (  # noqa: E402
    alias_key,
    canonicalize_observation,
)


METHOD = "report-entity-backfill/1.1"
MAX_CONTEXT_DISTANCE = 600
ANNOTATION_TYPES = {"GROUP", "MALWARE", "TOOL"}
GENERIC_SOFTWARE_NAMES = {
    "adware",
    "backdoor",
    "botnet",
    "dropper",
    "exploit kit",
    "infostealer",
    "loader",
    "malware",
    "ransomware",
    "rat",
    "rootkit",
    "spyware",
    "trojan",
    "virus",
    "worm",
}
NON_DOMAIN_SUFFIXES = {
    "each",
    "exploitation",
    "finally",
    "first",
    "mediterranean",
    "once",
    "rules",
    "second",
    "the",
    "threat",
    "ttp",
    *NON_INDICATOR_FILE_SUFFIXES,
    "jsp",
    "tff",
    "wll",
}
DOMAIN_CONTEXT = re.compile(
    r"\b(?:c2|c&c|command[- ]and[- ]control|domain|dns|url|indicator|ioc|"
    r"connect|communicat|download|server|host|beacon|callback|payload)\b",
    re.IGNORECASE,
)
NETWORK_ACTION = re.compile(
    r"\b(?:connect|communicat|download|callback|beacon|c2|command and control|"
    r"exfiltrat|redirect|send|receive)\b",
    re.IGNORECASE,
)
SOFTWARE_ACTION = re.compile(
    r"\b(?:execute|run|load|download|drop|install|inject|launch|deploy|deliver)\b",
    re.IGNORECASE,
)
EXPLOIT_ACTION = re.compile(r"\b(?:exploit|vulnerab|cve)\b", re.IGNORECASE)


def digest_id(prefix: str, *parts: str) -> str:
    digest = sha256("\0".join(parts).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}-{digest}"


def clean_indicator(raw_value: str) -> str:
    value = raw_value.rstrip(".,;:)]}")
    return value.replace("\\_", "_")


def extract_ioc_candidates(source: sqlite3.Row, spans: list[sqlite3.Row]) -> list[dict]:
    candidates: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for span in spans:
        for match in STRONG_IOC_PATTERN.finditer(str(span["text"])):
            raw_value = match.group(0)
            if not EntityEvidenceIngestionService._is_indicator(
                match.lastgroup or "", raw_value
            ):
                continue
            value = clean_indicator(raw_value)
            kind = "vulnerability" if match.lastgroup == "cve" else "ioc"
            canonical = canonicalize_observation(value, kind)
            if canonical is None:
                continue
            if canonical.value_type == "domain":
                defanged = "[.]" in raw_value or "(.)" in raw_value
                domain_parts = canonical.canonical_value.rsplit(".", 1)
                if (
                    len(domain_parts) != 2
                    or domain_parts[0].split(".", 1)[0].isdigit()
                    or domain_parts[1] in NON_DOMAIN_SUFFIXES
                ):
                    continue
                if not defanged and not DOMAIN_CONTEXT.search(str(span["text"])):
                    continue
            if canonical.value_type == "ipv4":
                try:
                    ipaddress.ip_address(canonical.canonical_value)
                except ValueError:
                    continue
            key = (canonical.canonical_key, str(span["id"]))
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    "entity_id": canonical.entity_id,
                    "entity_type": canonical.entity_type,
                    "canonical_key": canonical.canonical_key,
                    "label": canonical.label,
                    "normalized_value": canonical.canonical_value,
                    "value_type": canonical.value_type,
                    "original_value": value,
                    "source_span_id": str(span["id"]),
                    "start_offset": int(span["start_offset"]) + match.start(),
                    "end_offset": int(span["start_offset"]) + match.end(),
                    "confidence": 0.95,
                    "origin": "deterministic-ioc",
                    "source_document_id": str(source["id"]),
                }
            )
    return candidates


def bio_mentions(tokens: list[str], tags: list[str]) -> list[tuple[str, str]]:
    mentions: list[tuple[str, str]] = []
    label: str | None = None
    parts: list[str] = []
    for token, tag in zip(tokens, tags):
        if tag.startswith("B-"):
            if label is not None:
                mentions.append((label, " ".join(parts)))
            label = tag[2:]
            parts = [token]
        elif tag.startswith("I-") and label == tag[2:]:
            parts.append(token)
        else:
            if label is not None:
                mentions.append((label, " ".join(parts)))
            label = None
            parts = []
    if label is not None:
        mentions.append((label, " ".join(parts)))
    return mentions


def annotation_identity(label_type: str, value: str) -> dict | None:
    cleaned = value.strip(" \t\r\n\"'`“”‘’.,;:()[]{}")
    if not cleaned:
        return None
    if label_type == "GROUP":
        normalized = alias_key(cleaned)
        if not normalized:
            return None
        canonical_key = f"actor-name:{normalized}"
        return {
            "entity_id": digest_id("ENT-ACTOR", canonical_key),
            "entity_type": "攻击组织",
            "canonical_key": canonical_key,
            "label": cleaned,
            "normalized_value": normalized,
            "value_type": "actor-name",
        }
    if cleaned.casefold() in GENERIC_SOFTWARE_NAMES:
        return None
    canonical = canonicalize_observation(
        cleaned,
        "malware" if label_type == "MALWARE" else "tool",
    )
    if canonical is None:
        return None
    return {
        "entity_id": canonical.entity_id,
        "entity_type": canonical.entity_type,
        "canonical_key": canonical.canonical_key,
        "label": canonical.label,
        "normalized_value": canonical.canonical_value,
        "value_type": canonical.value_type,
    }


def extract_annotation_candidates(
    source: sqlite3.Row,
    spans: list[sqlite3.Row],
    annotation_path: Path,
) -> list[dict]:
    if not annotation_path.is_file():
        return []
    candidates: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for line in annotation_path.read_text(encoding="utf-8").splitlines():
        sentence = json.loads(line)
        sentence_text = str(sentence.get("text") or "")
        matching_spans = [
            span
            for span in spans
            if sentence_text and sentence_text in str(span["text"])
        ]
        for label_type, value in bio_mentions(
            sentence.get("tokens", []), sentence.get("ce_tags", [])
        ):
            if label_type not in ANNOTATION_TYPES:
                continue
            identity = annotation_identity(label_type, value)
            if identity is None:
                continue
            span = next(
                (
                    item
                    for item in matching_spans
                    if value.casefold() in str(item["text"]).casefold()
                ),
                None,
            )
            if span is None:
                span = next(
                    (
                        item
                        for item in spans
                        if value.casefold() in str(item["text"]).casefold()
                    ),
                    None,
                )
            if span is None:
                continue
            mention_match = re.search(
                re.escape(value),
                str(span["text"]),
                flags=re.IGNORECASE,
            )
            mention_start = (
                int(span["start_offset"]) + mention_match.start()
                if mention_match
                else int(span["start_offset"])
            )
            mention_end = (
                int(span["start_offset"]) + mention_match.end()
                if mention_match
                else int(span["end_offset"])
            )
            key = (identity["canonical_key"], str(span["id"]))
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    **identity,
                    "original_value": value,
                    "source_span_id": str(span["id"]),
                    "start_offset": mention_start,
                    "end_offset": mention_end,
                    "confidence": 1.0,
                    "origin": f"annoctr-{label_type.casefold()}",
                    "source_document_id": str(source["id"]),
                }
            )
    return candidates


def context_role(candidate: dict) -> str:
    if candidate["value_type"] == "cve":
        return "exploits"
    if candidate["value_type"] in {
        "url",
        "domain",
        "ipv4",
        "ipv6",
        "network-endpoint",
        "email",
    }:
        return "communicates-with"
    return "uses"


def semantic_penalty(candidate: dict, action_label: str) -> int:
    if candidate["value_type"] == "cve":
        return -2000 if EXPLOIT_ACTION.search(action_label) else 0
    if context_role(candidate) == "communicates-with":
        return -1000 if NETWORK_ACTION.search(action_label) else 0
    return -500 if SOFTWARE_ACTION.search(action_label) else 0


def nearest_action(
    candidate: dict,
    action_evidence: dict[str, list[sqlite3.Row]],
) -> sqlite3.Row | None:
    rows = action_evidence.get(candidate["source_document_id"], [])
    if not rows:
        return None
    if candidate["entity_type"] == "恶意软件/工具":
        normalized_value = str(candidate["original_value"]).replace("\\_", "_")
        rows = [
            row
            for row in rows
            if normalized_value.casefold()
            in str(row.get("evidence_quote", ""))
            .replace("\\_", "_")
            .casefold()
        ]
        if not rows:
            return None
    start = int(candidate["start_offset"])
    end = int(candidate["end_offset"])

    def distance(row: sqlite3.Row) -> int:
        evidence_start = int(row["start_offset"])
        evidence_end = int(row["end_offset"])
        if evidence_start <= end and start <= evidence_end:
            return 0
        return min(abs(start - evidence_end), abs(evidence_start - end))

    nearby_rows = [row for row in rows if distance(row) <= MAX_CONTEXT_DISTANCE]
    if not nearby_rows:
        return None

    def score(row: sqlite3.Row) -> tuple[int, int, str]:
        raw_distance = distance(row)
        return (
            raw_distance + semantic_penalty(candidate, str(row["action_label"])),
            raw_distance,
            str(row["action_node_id"]),
        )

    return min(nearby_rows, key=score)


def evidence_offsets(row: sqlite3.Row) -> tuple[int, int]:
    span_start = int(row["span_start_offset"])
    span_end = int(row["span_end_offset"])
    span_text = str(row["span_text"])
    quote = str(row["evidence_quote"]).strip()
    variants = [quote, quote.replace("\\_", "_").replace("\\*", "*")]
    for variant in variants:
        if not variant:
            continue
        match = re.search(re.escape(variant), span_text, flags=re.IGNORECASE)
        if match:
            return span_start + match.start(), span_start + match.end()
    return span_start, span_end


def load_action_evidence(connection: sqlite3.Connection) -> dict[str, list[sqlite3.Row]]:
    rows = connection.execute(
        """
        SELECT fss.source_document_id, pel.path_id, pel.node_id AS action_node_id,
               n.label AS action_label, pel.quote AS evidence_quote,
               ss.text AS span_text, ss.start_offset AS span_start_offset,
               ss.end_offset AS span_end_offset
        FROM flow_source_supports fss
        JOIN path_evidence_links pel ON pel.path_id = fss.path_id
        JOIN activity_path_nodes n ON n.id = pel.node_id
        JOIN source_spans ss ON ss.id = pel.source_span_id
        WHERE pel.node_id IS NOT NULL
          AND ss.source_document_id = fss.source_document_id
        ORDER BY fss.source_document_id, pel.path_id, n.sequence_hint, n.id
        """
    ).fetchall()
    by_source: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        start_offset, end_offset = evidence_offsets(row)
        by_source[str(row["source_document_id"])].append(
            {
                **dict(row),
                "start_offset": start_offset,
                "end_offset": end_offset,
            }
        )
    return by_source


def clear_previous_context_backfill(
    connection: sqlite3.Connection,
    source_document_ids: set[str],
) -> tuple[int, int]:
    if not source_document_ids:
        return 0, 0
    placeholders = ",".join("?" for _ in source_document_ids)
    path_filter = f"""
        SELECT path_id FROM flow_source_supports
        WHERE source_document_id IN ({placeholders})
    """
    evidence_cursor = connection.execute(
        f"""
        DELETE FROM action_context_evidence_links
        WHERE id LIKE 'ACE-BACKFILL-%'
          AND context_link_id IN (
            SELECT id FROM action_context_links
            WHERE path_id IN ({path_filter})
          )
        """,
        sorted(source_document_ids),
    )
    context_cursor = connection.execute(
        f"""
        DELETE FROM action_context_links
        WHERE json_extract(properties_json, '$.backfill_method')
              LIKE 'report-entity-backfill/%'
          AND path_id IN ({path_filter})
        """,
        sorted(source_document_ids),
    )
    return evidence_cursor.rowcount, context_cursor.rowcount


def persist_candidates(
    connection: sqlite3.Connection,
    sources: list[sqlite3.Row],
    candidates: list[dict],
) -> dict[str, int]:
    now = datetime.now(timezone.utc).isoformat()
    source_by_id = {str(source["id"]): source for source in sources}
    action_evidence = load_action_evidence(connection)
    stats = defaultdict(int)
    removed_evidence, removed_contexts = clear_previous_context_backfill(
        connection,
        {candidate["source_document_id"] for candidate in candidates},
    )
    stats["previous_context_evidence_removed"] = removed_evidence
    stats["previous_context_links_removed"] = removed_contexts
    stored_id_by_key: dict[str, str] = {}
    candidates.sort(
        key=lambda item: (
            item["source_document_id"],
            item["canonical_key"],
            item["source_span_id"],
        )
    )
    for source_id in sorted({item["source_document_id"] for item in candidates}):
        source = source_by_id[source_id]
        ingestion_id = f"KING-BACKFILL-{str(source['sha256'])[:16]}"
        connection.execute(
            """
            INSERT OR IGNORE INTO knowledge_ingestion_runs (
                id, source_document_id, status, result_json, created_at, updated_at
            ) VALUES (?, ?, 'published', ?, ?, ?)
            """,
            (
                ingestion_id,
                source_id,
                json.dumps(
                    {
                        "id": ingestion_id,
                        "ingestion_kind": "entity-backfill",
                        "status": "published",
                        "extraction_audit": {"method": METHOD},
                    },
                    ensure_ascii=False,
                ),
                now,
                now,
            ),
        )
        version_id = f"KVER-BACKFILL-{str(source['sha256'])[:16]}"
        connection.execute(
            """
            INSERT OR IGNORE INTO knowledge_versions (
                id, ingestion_id, status, changes_json, published_at
            ) VALUES (?, ?, 'published', '{}', ?)
            """,
            (version_id, ingestion_id, now),
        )

    for candidate in candidates:
        properties = {
            "ui_type": (
                "actor"
                if candidate["entity_type"] == "攻击组织"
                else "ioc"
                if candidate["entity_type"] in {"IOC/基础设施", "CVE"}
                else "software"
            ),
            "value_type": candidate["value_type"],
            "confidence": candidate["confidence"],
            "backfill_method": METHOD,
        }
        source = source_by_id[candidate["source_document_id"]]
        connection.execute(
            """
            INSERT OR IGNORE INTO entities (
                id, entity_type, canonical_key, label, normalized_value,
                description, first_seen, last_seen, source_count,
                created_at, updated_at, properties_json, seed_origin
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
            """,
            (
                candidate["entity_id"],
                candidate["entity_type"],
                candidate["canonical_key"],
                candidate["label"],
                candidate["normalized_value"],
                f"由报告原文证据抽取的 {candidate['value_type']} 实体。",
                source["published_at"],
                source["published_at"],
                now,
                now,
                json.dumps(properties, ensure_ascii=False),
                METHOD,
            ),
        )
        stored_id = stored_id_by_key.get(candidate["canonical_key"])
        if stored_id is None:
            row = connection.execute(
                "SELECT id FROM entities WHERE canonical_key = ?",
                (candidate["canonical_key"],),
            ).fetchone()
            if row is None:
                raise RuntimeError(candidate["canonical_key"])
            stored_id = str(row["id"])
            stored_id_by_key[candidate["canonical_key"]] = stored_id
        mention_id = digest_id(
            "EMN-BACKFILL",
            stored_id,
            candidate["source_span_id"],
            candidate["original_value"],
        )
        ingestion_id = f"KING-BACKFILL-{str(source['sha256'])[:16]}"
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO entity_mentions (
                id, entity_id, source_document_id, source_span_id,
                ingestion_id, original_value, canonical_value,
                value_type, confidence, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mention_id,
                stored_id,
                candidate["source_document_id"],
                candidate["source_span_id"],
                ingestion_id,
                candidate["original_value"],
                candidate["normalized_value"],
                candidate["value_type"],
                candidate["confidence"],
                now,
            ),
        )
        stats["mentions_created"] += cursor.rowcount
        if candidate["entity_type"] == "攻击组织":
            continue
        action = nearest_action(candidate, action_evidence)
        if action is None:
            stats["standalone_mentions"] += 1
            continue
        role = context_role(candidate)
        link_id = digest_id(
            "CTX-BACKFILL",
            str(action["path_id"]),
            str(action["action_node_id"]),
            stored_id,
            role,
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO action_context_links (
                id, path_id, action_node_id, entity_id, role, direction,
                assertion_origin, review_state, confidence, properties_json
            ) VALUES (?, ?, ?, ?, ?, 'action-to-entity', 'source-observed',
                      'machine-proposed', ?, ?)
            """,
            (
                link_id,
                action["path_id"],
                action["action_node_id"],
                stored_id,
                role,
                candidate["confidence"],
                json.dumps(
                    {
                        "backfill_method": METHOD,
                        "value_type": candidate["value_type"],
                    },
                    ensure_ascii=False,
                ),
            ),
        )
        stored_link = connection.execute(
            """
            SELECT id FROM action_context_links
            WHERE path_id = ? AND action_node_id = ? AND entity_id = ? AND role = ?
            """,
            (
                action["path_id"],
                action["action_node_id"],
                stored_id,
                role,
            ),
        ).fetchone()
        if stored_link is None:
            raise RuntimeError(link_id)
        evidence_id = digest_id(
            "ACE-BACKFILL",
            str(stored_link["id"]),
            candidate["source_span_id"],
        )
        evidence_cursor = connection.execute(
            """
            INSERT OR IGNORE INTO action_context_evidence_links (
                id, context_link_id, source_span_id, support_type,
                evidence_role, quote, confidence, review_state
            ) VALUES (?, ?, ?, 'supports', 'direct', ?, ?, 'machine-proposed')
            """,
            (
                evidence_id,
                stored_link["id"],
                candidate["source_span_id"],
                candidate["original_value"],
                candidate["confidence"],
            ),
        )
        stats["context_evidence_created"] += evidence_cursor.rowcount

    connection.execute(
        """
        UPDATE entities
        SET source_count = MAX(
                1,
                (SELECT COUNT(DISTINCT em.source_document_id)
                 FROM entity_mentions em WHERE em.entity_id = entities.id)
            ),
            updated_at = ?
        WHERE id IN (SELECT DISTINCT entity_id FROM entity_mentions)
        """,
        (now,),
    )
    stats["unique_candidates"] = len(
        {candidate["canonical_key"] for candidate in candidates}
    )
    stats["candidate_mentions"] = len(candidates)
    stats["context_links"] = connection.execute(
        "SELECT COUNT(*) FROM action_context_links WHERE properties_json LIKE ?",
        (f'%"backfill_method": "{METHOD}"%',),
    ).fetchone()[0]
    return dict(stats)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, default=ROOT / "data/argus_cti.db")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "data/corpus/annoctr_rebuild_50_manifest.json",
    )
    parser.add_argument(
        "--annoctr-root",
        type=Path,
        default=(
            ROOT
            / "data/corpus/upstream/anno-ctr-lrec-coling-2024/AnnoCTR/all"
        ),
    )
    parser.add_argument("--backup", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.backup and not args.dry_run:
        backup = args.database.with_name(
            f"{args.database.name}.before-report-entity-backfill"
        )
        with sqlite3.connect(args.database) as source_connection:
            with sqlite3.connect(backup) as backup_connection:
                source_connection.backup(backup_connection)
        print(f"backup={backup}")

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    report_by_sha = {str(item["sha256"]): item for item in manifest["reports"]}
    connection = sqlite3.connect(args.database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    sources = connection.execute(
        "SELECT * FROM source_documents ORDER BY id"
    ).fetchall()
    all_candidates: list[dict[str, Any]] = []
    for source in sources:
        spans = connection.execute(
            """
            SELECT * FROM source_spans
            WHERE source_document_id = ?
            ORDER BY start_offset, end_offset, id
            """,
            (source["id"],),
        ).fetchall()
        all_candidates.extend(extract_ioc_candidates(source, spans))
        report = report_by_sha.get(str(source["sha256"]))
        if report is None:
            continue
        annotation_path = (
            args.annoctr_root
            / "ner_json"
            / f"{Path(report['source_path']).stem}.json"
        )
        all_candidates.extend(
            extract_annotation_candidates(source, spans, annotation_path)
        )

    print(
        json.dumps(
            {
                "sources": len(sources),
                "candidate_mentions": len(all_candidates),
                "unique_candidates": len(
                    {item["canonical_key"] for item in all_candidates}
                ),
                "by_origin": dict(
                    sorted(
                        (
                            origin,
                            sum(item["origin"] == origin for item in all_candidates),
                        )
                        for origin in {item["origin"] for item in all_candidates}
                    )
                ),
            },
            ensure_ascii=False,
        )
    )
    if args.dry_run:
        connection.close()
        return 0
    with connection:
        stats = persist_candidates(connection, sources, all_candidates)
    connection.close()
    print(json.dumps(stats, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
