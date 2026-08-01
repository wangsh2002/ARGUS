from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

from dotenv import load_dotenv


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "backend"))

from argus_backend.attack_flow_extraction import (  # noqa: E402
    deepseek_attack_flow_from_environment,
    extract_attack_flow_candidates,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the fixed plaintext-only AnnoCTR AttackFlow acceptance set."
    )
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument(
        "--output",
        type=Path,
        default=REPOSITORY_ROOT
        / "data"
        / "experiments"
        / "attack_flow_extraction_acceptance_latest.json",
    )
    args = parser.parse_args()

    load_dotenv(REPOSITORY_ROOT / ".env.local", override=False)
    model = deepseek_attack_flow_from_environment()
    if model is None:
        raise SystemExit("ARGUS_LLM_BASE_URL/API_KEY/MODEL are required")

    manifest = json.loads(
        (
            REPOSITORY_ROOT
            / "data"
            / "corpus"
            / "attack_flow_extraction_acceptance.json"
        ).read_text(encoding="utf-8")
    )
    selected = [
        case
        for case in manifest["cases"]
        if not args.case_ids or case["id"] in set(args.case_ids)
    ]
    if not selected:
        raise SystemExit("No acceptance cases selected")

    case_results = []
    all_passed = True
    for case in selected:
        artifact = REPOSITORY_ROOT / case["artifact_path"]
        content_bytes = artifact.read_bytes()
        digest = sha256(content_bytes).hexdigest()
        if digest != case["sha256"]:
            raise RuntimeError(f"Source hash mismatch: {case['id']}")
        content = content_bytes.decode("utf-8")
        extraction = extract_attack_flow_candidates(
            model,
            {
                "sha256": digest,
                "title": case["title"],
                "publisher": "AnnoCTR archived report",
                "published_at": "",
                "canonical_url": case["artifact_path"],
            },
            content,
        )
        count = len(extraction.candidates)
        cardinality = case["cardinality"]
        topology = topology_summary(extraction.candidates)
        topology_required = {
            "branch": "branch" in case["scenarios"],
            "merge": "merge" in case["scenarios"],
        }
        passed = (
            cardinality["minimum"] <= count <= cardinality["maximum"]
            and (
                not topology_required["branch"]
                or topology["branch"]
            )
            and (
                not topology_required["merge"]
                or topology["merge"]
            )
        )
        all_passed = all_passed and passed
        case_results.append(
            {
                "id": case["id"],
                "title": case["title"],
                "sha256": digest,
                "scenarios": case["scenarios"],
                "passed": passed,
                "expected_cardinality": cardinality,
                "actual_candidate_count": count,
                "topology": topology,
                "topology_required": topology_required,
                "candidates": [
                    candidate.model_dump() for candidate in extraction.candidates
                ],
                "audit": extraction.audit,
            }
        )
        print(
            f"{case['id']}: {'PASS' if passed else 'FAIL'} "
            f"({count} candidates, "
            f"{len(extraction.audit['rejected_facts'])} rejected facts)",
            flush=True,
        )

    output = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": os.environ["ARGUS_LLM_MODEL"],
        "manifest": "data/corpus/attack_flow_extraction_acceptance.json",
        "plaintext_only": True,
        "passed": all_passed,
        "cases": case_results,
    }
    output_path = args.output
    if not output_path.is_absolute():
        output_path = REPOSITORY_ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(output, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"wrote {output_path}", flush=True)
    return 0 if all_passed else 1


def topology_summary(candidates) -> dict[str, bool]:
    has_branch = False
    has_merge = False
    for candidate in candidates:
        outgoing = {action.id: 0 for action in candidate.actions}
        incoming = {action.id: 0 for action in candidate.actions}
        for relation in candidate.relations:
            outgoing[relation.source_action_id] += 1
            incoming[relation.target_action_id] += 1
        roots = sum(count == 0 for count in incoming.values())
        has_branch = has_branch or roots > 1 or any(
            count > 1 for count in outgoing.values()
        )
        has_merge = has_merge or any(count > 1 for count in incoming.values())
    return {"branch": has_branch, "merge": has_merge}


if __name__ == "__main__":
    raise SystemExit(main())
