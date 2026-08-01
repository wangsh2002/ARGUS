#!/usr/bin/env python3
"""Import full report texts without trusting dataset labels or relationships."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sqlite3
import sys


PARSER_NAME = "argus-line-evidence-parser"
PARSER_VERSION = "1.0.0"


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=root / "data" / "corpus" / "annoctr_initial_manifest.json",
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument(
        "--database",
        type=Path,
        default=root / "data" / "argus_cti.db",
    )
    parser.add_argument(
        "--storage-root",
        type=Path,
        default=root / "data" / "corpus" / "artifacts",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def digest_bytes(content: bytes) -> str:
    return sha256(content).hexdigest()


def evidence_lines(content: str) -> list[dict]:
    spans: list[dict] = []
    cursor = 0
    for line_number, raw_line in enumerate(content.splitlines(keepends=True), start=1):
        stripped = raw_line.strip()
        line_start = cursor
        cursor += len(raw_line)
        if not stripped:
            continue
        start = line_start + raw_line.find(stripped)
        spans.append(
            {
                "index": len(spans) + 1,
                "line_number": line_number,
                "start": start,
                "end": start + len(stripped),
                "text": stripped,
                "quote_sha256": digest_bytes(stripped.encode("utf-8")),
            }
        )
    return spans


def require_schema(connection: sqlite3.Connection) -> None:
    applied = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = 11"
    ).fetchone()
    if applied is None:
        raise RuntimeError(
            "Migration 011 is not applied. Run: "
            "sqlite3 data/argus_cti.db < data/migrations/011_evidence_first_corpus.sql"
        )


def import_manifest(
    manifest_path: Path,
    source_root: Path,
    database_path: Path,
    storage_root: Path,
    dry_run: bool,
) -> dict:
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    collection = manifest["collection"]
    manifest_digest = digest_bytes(manifest_bytes)
    collected_at = datetime.now(timezone.utc).isoformat()
    prepared: list[dict] = []

    for report in manifest["reports"]:
        source_path = source_root / report["source_path"]
        if not source_path.is_file():
            raise FileNotFoundError(source_path)
        raw_bytes = source_path.read_bytes()
        actual_digest = digest_bytes(raw_bytes)
        if actual_digest != report["sha256"]:
            raise ValueError(
                f"{report['collection_record_id']} hash mismatch: "
                f"expected {report['sha256']}, got {actual_digest}"
            )
        content = raw_bytes.decode("utf-8")
        if len(content.split()) < 250:
            raise ValueError(
                f"{report['collection_record_id']} is not a full report text"
            )
        artifact_id = f"ART-{actual_digest[:16]}"
        document_id = f"SRC-DOC-{actual_digest[:16]}"
        report_id = f"RPT-CORPUS-{actual_digest[:16]}"
        relative_storage = Path(collection["id"]) / f"{actual_digest[:16]}.txt"
        prepared.append(
            {
                **report,
                "artifact_id": artifact_id,
                "document_id": document_id,
                "report_id": report_id,
                "source_path_absolute": source_path,
                "storage_path_absolute": storage_root / relative_storage,
                "storage_path": str(
                    Path("data") / "corpus" / "artifacts" / relative_storage
                ),
                "raw_bytes": raw_bytes,
                "content": content,
                "spans": evidence_lines(content),
            }
        )

    if dry_run:
        return {
            "status": "validated",
            "collection": collection["id"],
            "reports": len(prepared),
            "spans": sum(len(item["spans"]) for item in prepared),
            "graph_writes": 0,
        }

    database_path.parent.mkdir(parents=True, exist_ok=True)
    storage_root.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        require_schema(connection)
        connection.execute(
            """
            INSERT INTO corpus_collections (
              id, name, owner, upstream_url, version, license,
              manifest_sha256, retrieved_at, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              manifest_sha256 = excluded.manifest_sha256,
              retrieved_at = excluded.retrieved_at,
              notes = excluded.notes
            """,
            (
                collection["id"],
                collection["name"],
                collection["owner"],
                collection["upstream_url"],
                collection["version"],
                collection["license"],
                manifest_digest,
                collection["retrieved_at"],
                collection["notes"],
            ),
        )
        for item in prepared:
            item["storage_path_absolute"].parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(
                item["source_path_absolute"],
                item["storage_path_absolute"],
            )
            connection.execute(
                """
                INSERT INTO source_artifacts (
                  id, collection_id, collection_record_id, title, publisher,
                  canonical_url, acquisition_source, acquisition_url,
                  published_at, collected_at, mime_type, size_bytes, sha256,
                  storage_path, dataset_license, source_license, tlp,
                  archive_status, canonical_verification_state,
                  canonical_verified_at, review_state, metadata_json
                ) VALUES (
                  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                  'parsed', ?
                )
                ON CONFLICT(id) DO UPDATE SET
                  canonical_url = excluded.canonical_url,
                  canonical_verification_state =
                    excluded.canonical_verification_state,
                  canonical_verified_at = excluded.canonical_verified_at,
                  metadata_json = excluded.metadata_json
                """,
                (
                    item["artifact_id"],
                    collection["id"],
                    item["collection_record_id"],
                    item["title"],
                    item["publisher"],
                    item["canonical_url"],
                    collection["name"],
                    collection["upstream_url"],
                    item["published_at"],
                    collected_at,
                    item["mime_type"],
                    len(item["raw_bytes"]),
                    item["sha256"],
                    item["storage_path"],
                    item["dataset_license"],
                    item["source_license"],
                    item["tlp"],
                    item["archive_status"],
                    item["canonical_verification_state"],
                    item["canonical_verified_at"],
                    json.dumps(
                        {
                            "selection_reason": item["selection_reason"],
                            "target_case": item["target_case"],
                            "actor_candidates": item.get("actor_candidates", []),
                            "selection_basis": item.get("selection_basis"),
                            "canonical_source_note": item.get("canonical_source_note"),
                            "dataset_labels_used": False,
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
            connection.execute(
                """
                INSERT INTO source_documents (
                  id, title, publisher, canonical_url, published_at, mime_type,
                  sha256, content, content_size, review_state, artifact_id,
                  collected_at, parser_name, parser_version, license, tlp,
                  canonical_verification_state
                ) VALUES (
                  ?, ?, ?, ?, ?, ?, ?, ?, ?, 'parsed', ?, ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT(id) DO UPDATE SET
                  artifact_id = excluded.artifact_id,
                  collected_at = excluded.collected_at,
                  parser_name = excluded.parser_name,
                  parser_version = excluded.parser_version,
                  license = excluded.license,
                  tlp = excluded.tlp,
                  canonical_verification_state =
                    excluded.canonical_verification_state
                """,
                (
                    item["document_id"],
                    item["title"],
                    item["publisher"],
                    item["canonical_url"],
                    item["published_at"],
                    item["mime_type"],
                    item["sha256"],
                    item["content"],
                    len(item["raw_bytes"]),
                    item["artifact_id"],
                    collected_at,
                    PARSER_NAME,
                    PARSER_VERSION,
                    item["dataset_license"],
                    item["tlp"],
                    item["canonical_verification_state"],
                ),
            )
            connection.executemany(
                """
                INSERT INTO source_spans (
                  id, source_document_id, locator, start_offset, end_offset,
                  text, extraction_method, artifact_id, locator_type,
                  line_start, line_end, block_index, quote_sha256,
                  parser_version, review_state
                ) VALUES (
                  ?, ?, ?, ?, ?, ?, ?, ?, 'line', ?, ?, ?, ?, ?,
                  'machine-parsed'
                )
                ON CONFLICT(id) DO UPDATE SET
                  locator = excluded.locator,
                  start_offset = excluded.start_offset,
                  end_offset = excluded.end_offset,
                  text = excluded.text,
                  extraction_method = excluded.extraction_method,
                  artifact_id = excluded.artifact_id,
                  locator_type = excluded.locator_type,
                  line_start = excluded.line_start,
                  line_end = excluded.line_end,
                  block_index = excluded.block_index,
                  quote_sha256 = excluded.quote_sha256,
                  parser_version = excluded.parser_version
                """,
                (
                    (
                        f"SRC-SPAN-{item['sha256'][:12]}-{span['index']:04d}",
                        item["document_id"],
                        f"line:{span['line_number']}",
                        span["start"],
                        span["end"],
                        span["text"],
                        PARSER_NAME,
                        item["artifact_id"],
                        span["line_number"],
                        span["line_number"],
                        span["index"],
                        span["quote_sha256"],
                        PARSER_VERSION,
                    )
                    for span in item["spans"]
                ),
            )
            connection.execute(
                """
                INSERT INTO raw_reports (
                  id, title, source, report_date, classification, language,
                  original_filename, mime_type, size_bytes, sha256, raw_blob,
                  extracted_text, extraction_note, created_at, source_ref,
                  reliability, external_url, assessment
                ) VALUES (
                  ?, ?, ?, ?, '公开原始报告', 'English', ?, ?, ?, ?, NULL, ?,
                  ?, ?, ?, '原发布方链接已核验 / AnnoCTR 全文副本', ?, ?
                )
                ON CONFLICT(id) DO UPDATE SET
                  external_url = excluded.external_url,
                  assessment = excluded.assessment
                """,
                (
                    item["report_id"],
                    item["title"],
                    item["publisher"],
                    item["published_at"],
                    Path(item["source_path"]).name,
                    item["mime_type"],
                    len(item["raw_bytes"]),
                    item["sha256"],
                    item["content"],
                    (
                        f"{PARSER_NAME}@{PARSER_VERSION}; "
                        "dataset labels intentionally ignored."
                    ),
                    collected_at,
                    item["document_id"],
                    item["canonical_url"],
                    item["selection_reason"],
                ),
            )

    return {
        "status": "imported",
        "collection": collection["id"],
        "reports": len(prepared),
        "spans": sum(len(item["spans"]) for item in prepared),
        "graph_writes": 0,
    }


def main() -> int:
    args = parse_args()
    try:
        result = import_manifest(
            manifest_path=args.manifest.resolve(),
            source_root=args.source_root.resolve(),
            database_path=args.database.resolve(),
            storage_root=args.storage_root.resolve(),
            dry_run=args.dry_run,
        )
    except Exception as error:
        print(f"Corpus import failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
