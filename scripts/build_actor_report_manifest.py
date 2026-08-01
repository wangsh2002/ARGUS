#!/usr/bin/env python3
"""Build an auditable AnnoCTR report manifest for actor coverage.

AnnoCTR GROUP annotations are used only to select and index source reports.
They are not imported as graph facts, attribution evidence, or attack paths.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from urllib.parse import quote


UPSTREAM_COMMIT = "d510b6949e1938d47c93a43eedd562dc538439dc"
VARIANT_SUFFIXES = ("_w_con", "_w_neg", "_w_con_w_neg")
PUBLISHERS = {
    "intel471": "Intel 471",
    "lab52": "Lab52 / S2 Grupo",
    "proofpoint": "Proofpoint",
    "quointelligence": "QuoIntelligence",
    "s2grupo": "S2 Grupo",
    "zscaler": "Zscaler ThreatLabz",
}


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset-root",
        type=Path,
        default=(root / "data" / "corpus" / "upstream" / "anno-ctr-lrec-coling-2024"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "data" / "corpus" / "annoctr_actor_coverage_manifest.json",
    )
    return parser.parse_args()


def load_verified_metadata(corpus_root: Path) -> dict[str, dict]:
    verified: dict[str, dict] = {}
    for manifest_path in sorted(corpus_root.glob("*manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        for report in manifest.get("reports", []):
            source_path = Path(str(report.get("source_path", "")))
            if source_path.suffix != ".txt":
                continue
            verified[source_path.stem] = report
    return verified


def base_linking_files(linking_root: Path) -> list[Path]:
    return [
        path
        for path in sorted(linking_root.glob("*.json"))
        if not any(path.stem.endswith(suffix) for suffix in VARIANT_SUFFIXES)
    ]


def group_index(linking_root: Path) -> dict[str, dict[str, str]]:
    reports: dict[str, dict[str, str]] = defaultdict(dict)
    for path in base_linking_files(linking_root):
        for raw_line in path.read_text().splitlines():
            if not raw_line.strip():
                continue
            record = json.loads(raw_line)
            if record.get("entity_type") != "GROUP":
                continue
            document = str(record["document"])
            link = str(record["label_link"])
            reports[document][link] = str(record["label_title"])
    return reports


def clean_title(value: str) -> str:
    return re.sub(r"^[#*_\s]+|[#*_\s]+$", "", value).strip()


def report_metadata(
    document: str,
    actor_candidates: dict[str, str],
    text_path: Path,
    verified: dict[str, dict],
    *,
    selection_basis: str = "annoctr-group-annotation-index-only",
    selection_note: str | None = None,
) -> dict:
    raw_bytes = text_path.read_bytes()
    content = raw_bytes.decode("utf-8")
    first_line = next(
        (clean_title(line) for line in content.splitlines() if line.strip()),
        document,
    )
    match = re.match(
        r"(?P<publisher>[a-z0-9]+)_(?P<date>\d{4}-\d{2}-\d{2})_(?P<slug>.+)",
        document,
    )
    if match is None:
        raise ValueError(f"Unexpected AnnoCTR document name: {document}")

    known = verified.get(document)
    dataset_path = f"AnnoCTR/all/text/{document}.txt"
    dataset_url = (
        "https://github.com/boschresearch/anno-ctr-lrec-coling-2024/"
        f"blob/{UPSTREAM_COMMIT}/{quote(dataset_path)}"
    )
    canonical_verified = bool(
        known and known.get("canonical_verification_state") == "verified"
    )
    titles = sorted(set(actor_candidates.values()), key=str.casefold)
    ids = sorted(actor_candidates)
    return {
        "collection_record_id": f"annoctr:all:{document}",
        "source_path": dataset_path,
        "sha256": sha256(raw_bytes).hexdigest(),
        "title": str(known.get("title")) if known else first_line,
        "publisher": (
            str(known.get("publisher"))
            if known
            else PUBLISHERS.get(match["publisher"], match["publisher"])
        ),
        "published_at": (str(known.get("published_at")) if known else match["date"]),
        "canonical_url": (
            str(known.get("canonical_url")) if canonical_verified else dataset_url
        ),
        "mime_type": "text/plain",
        "dataset_license": "CC-BY-SA-4.0",
        "source_license": (
            str(known.get("source_license"))
            if canonical_verified
            else "original-terms-unverified; dataset-copy-CC-BY-SA-4.0"
        ),
        "tlp": str(known.get("tlp")) if known else "not-marked-public",
        "archive_status": (
            str(known.get("archive_status")) if canonical_verified else "archived-copy"
        ),
        "canonical_verification_state": (
            "verified" if canonical_verified else "unverified"
        ),
        "canonical_verified_at": (
            known.get("canonical_verified_at") if canonical_verified else None
        ),
        "selection_reason": (
            selection_note
            or (
                "AnnoCTR full-text report selected because its expert annotation "
                f"contains GROUP candidates: {', '.join(titles)}. Candidate labels "
                "are indexing aids only and are not imported as graph evidence."
            )
        ),
        "target_case": f"actor-coverage:{'|'.join(titles)}",
        "actor_candidates": [
            {"id": actor_id, "label": actor_candidates[actor_id]} for actor_id in ids
        ],
        "selection_basis": selection_basis,
        "canonical_source_note": (
            "Original publisher URL verified in an existing curated manifest."
            if canonical_verified
            else "Original publisher URL not yet verified; canonical_url points "
            "to the commit-pinned AnnoCTR full-text copy."
        ),
    }


def main() -> int:
    args = parse_args()
    dataset_root = args.dataset_root.resolve()
    corpus_root = args.output.resolve().parent
    reports = group_index(dataset_root / "AnnoCTR" / "all" / "linking")
    verified = load_verified_metadata(corpus_root)
    prepared = [
        report_metadata(
            document,
            reports[document],
            dataset_root / "AnnoCTR" / "all" / "text" / f"{document}.txt",
            verified,
        )
        for document in sorted(reports)
    ]
    manifest = {
        "schema_version": "1.1",
        "collection": {
            "id": "COLL-ANNOCTR-D510B694",
            "name": "AnnoCTR original report texts",
            "owner": "Robert Bosch GmbH and research partners",
            "upstream_url": (
                "https://github.com/boschresearch/anno-ctr-lrec-coling-2024"
            ),
            "version": UPSTREAM_COMMIT,
            "license": "CC-BY-SA-4.0",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "notes": (
                "Actor coverage batch contains every AnnoCTR full-text report "
                "with at least one GROUP annotation. GROUP annotations are used "
                "only for report selection and indexing; graph facts, paths and "
                "attribution must be re-derived from source evidence."
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
                "candidate_group_ids": len(
                    {
                        item["id"]
                        for report in prepared
                        for item in report["actor_candidates"]
                    }
                ),
                "verified_original_urls": sum(
                    report["canonical_verification_state"] == "verified"
                    for report in prepared
                ),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
