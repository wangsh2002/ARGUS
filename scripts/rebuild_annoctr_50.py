#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from time import perf_counter

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from argus_backend.application import ArgusApplication  # noqa: E402
from argus_backend.attack_flow_extraction import (  # noqa: E402
    deepseek_attack_flow_from_environment,
)
from argus_backend.repository import SqliteRepository  # noqa: E402
from scripts.import_report_corpus import import_manifest  # noqa: E402
from scripts.refine_showcase_relations import (  # noqa: E402
    apply_showcase_relation_refinements,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "data/corpus/annoctr_rebuild_50_manifest.json",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=ROOT / "data/corpus/upstream/anno-ctr-lrec-coling-2024",
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=ROOT / "data/argus_cti.db",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data/rebuild/annoctr_50_pro_latest.json",
    )
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    load_dotenv(ROOT / ".env.local", override=False)
    model = deepseek_attack_flow_from_environment()
    if model is None:
        raise SystemExit("ARGUS_LLM_BASE_URL/API_KEY/MODEL are required")

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    reports = manifest.get("reports", [])
    if len(reports) != 50:
        raise SystemExit(f"rebuild manifest must contain exactly 50 reports, got {len(reports)}")
    if args.limit is not None and not 1 <= args.limit <= len(reports):
        raise SystemExit("--limit must be between 1 and 50")
    selected_reports = reports[: args.limit] if args.limit else reports

    args.output.parent.mkdir(parents=True, exist_ok=True)
    import_manifest_path = args.manifest
    if args.limit:
        limited_manifest = {**manifest, "reports": selected_reports}
        import_manifest_path = args.output.with_name(
            f"annoctr_{len(selected_reports)}_manifest.json"
        )
        import_manifest_path.write_text(
            json.dumps(limited_manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    imported = import_manifest(
        manifest_path=import_manifest_path,
        source_root=args.source_root,
        database_path=args.database,
        storage_root=ROOT / "data/corpus/artifacts",
        dry_run=False,
    )
    repository = SqliteRepository(args.database)
    repository.ensure_schema()
    application = ArgusApplication(repository, attack_flow_language_model=model)

    results: list[dict] = []
    totals = {
        "reports": len(selected_reports),
        "completed": 0,
        "failed": 0,
        "candidates": 0,
        "published": 0,
        "rejected": 0,
        "entity_only_published": 0,
    }

    for index, report in enumerate(selected_reports, start=1):
        document_id = f"SRC-DOC-{report['sha256'][:16]}"
        started = perf_counter()
        record = {
            "index": index,
            "source_document_id": document_id,
            "title": report["title"],
            "sha256": report["sha256"],
        }
        try:
            staged = application.stage_knowledge_ingestion(
                document_id,
                extract_attack_flows=True,
            )
            candidates = (
                staged["candidates"]
                if staged.get("ingestion_kind") == "attack-flow-batch"
                else [staged]
            )
            record["candidate_count"] = sum(
                item.get("ingestion_kind") == "attack-flow"
                for item in candidates
            )
            record["ingestions"] = []
            totals["candidates"] += record["candidate_count"]
            for item in candidates:
                ingestion = {
                    "id": item["id"],
                    "kind": item.get("ingestion_kind"),
                    "publishable": item.get("publishable", False),
                }
                if item.get("publishable") is True:
                    published = application.publish_knowledge_ingestion(item["id"])
                    ingestion["status"] = published.get("status")
                    ingestion["version_id"] = published.get("version", {}).get("id")
                    if item.get("ingestion_kind") == "attack-flow":
                        totals["published"] += 1
                        ingestion["flow_id"] = published.get(
                            "attack_flow_preview", {}
                        ).get("flow_id")
                    else:
                        totals["entity_only_published"] += 1
                elif item.get("ingestion_kind") == "attack-flow":
                    rejected = application.reject_attack_flow_ingestion(item["id"])
                    ingestion["status"] = rejected.get("status")
                    ingestion["blocking_gates"] = [
                        gate["id"]
                        for gate in item.get("quality_gates", [])
                        if gate.get("status") == "block"
                    ]
                    totals["rejected"] += 1
                else:
                    ingestion["status"] = item.get("status")
                record["ingestions"].append(ingestion)
            totals["completed"] += 1
            record["status"] = "completed"
        except Exception as error:
            totals["failed"] += 1
            record["status"] = "failed"
            record["error"] = f"{type(error).__name__}: {error}"
        record["elapsed_seconds"] = round(perf_counter() - started, 3)
        results.append(record)
        checkpoint = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model": os.environ["ARGUS_LLM_MODEL"],
            "manifest": str(args.manifest.relative_to(ROOT)),
            "import": imported,
            "totals": totals,
            "reports": results,
        }
        args.output.write_text(
            json.dumps(checkpoint, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(
            f"[{index:02d}/{len(selected_reports):02d}] {record['status']} "
            f"{record.get('candidate_count', 0)} candidates "
            f"{record['elapsed_seconds']}s · {report['title']}",
            flush=True,
        )

    showcase_refinements = apply_showcase_relation_refinements(args.database)
    checkpoint["showcase_relation_refinements"] = showcase_refinements
    args.output.write_text(
        json.dumps(checkpoint, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {**totals, "showcase_relation_refinements": showcase_refinements},
            ensure_ascii=False,
        ),
        flush=True,
    )
    return 0 if totals["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
