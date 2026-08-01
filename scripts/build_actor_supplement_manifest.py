#!/usr/bin/env python3
"""Build the manifest for manually reviewed AnnoCTR ext actor reports."""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path

from build_actor_report_manifest import (
    UPSTREAM_COMMIT,
    load_verified_metadata,
    report_metadata,
)


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset-root",
        type=Path,
        default=root
        / "data"
        / "corpus"
        / "upstream"
        / "anno-ctr-lrec-coling-2024",
    )
    parser.add_argument(
        "--review",
        type=Path,
        default=root / "data" / "corpus" / "annoctr_ext_actor_review.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root
        / "data"
        / "corpus"
        / "annoctr_actor_supplement_manifest.json",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    review = json.loads(args.review.resolve().read_text())
    accepted_by_document: dict[str, list[dict]] = defaultdict(list)
    for item in review["accepted"]:
        accepted_by_document[str(item["document"])].append(item)

    corpus_root = args.output.resolve().parent
    verified = load_verified_metadata(corpus_root)
    prepared = []
    for document, decisions in sorted(accepted_by_document.items()):
        actors = {
            str(item["actor_key"]): str(item["actor_label"]) for item in decisions
        }
        decision_summary = "; ".join(
            f"{item['actor_label']}: {item['decision']}" for item in decisions
        )
        prepared.append(
            report_metadata(
                document,
                actors,
                args.dataset_root.resolve()
                / "AnnoCTR"
                / "all"
                / "text"
                / f"{document}.txt",
                verified,
                selection_basis="manual-review-of-annoctr-ext-report",
                selection_note=(
                    "Manually reviewed AnnoCTR ext report accepted for actor "
                    f"coverage. {decision_summary}"
                ),
            )
        )

    manifest = {
        "schema_version": "1.1",
        "collection": {
            "id": "COLL-ANNOCTR-D510B694",
            "name": "AnnoCTR manually reviewed ext actor reports",
            "owner": "Robert Bosch GmbH and research partners",
            "upstream_url": (
                "https://github.com/boschresearch/anno-ctr-lrec-coling-2024"
            ),
            "version": UPSTREAM_COMMIT,
            "license": "CC-BY-SA-4.0",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "notes": (
                "Every actor-report link in this supplemental batch was manually "
                "reviewed against an exact source line. The review decisions are "
                "stored separately and include explicit rejected candidates."
            ),
        },
        "reports": prepared,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(f"{json.dumps(manifest, ensure_ascii=False, indent=2)}\n")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "reports": len(prepared),
                "actor_report_links": len(review["accepted"]),
                "rejected_links": len(review["rejected"]),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
