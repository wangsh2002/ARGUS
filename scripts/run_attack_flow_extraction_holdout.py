from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import random
import sys

from dotenv import load_dotenv


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "backend"))

from argus_backend.attack_flow_extraction import (  # noqa: E402
    ALLOWED_RELATIONS,
    deepseek_attack_flow_from_environment,
    extract_attack_flow_candidates,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run schema invariants on randomly selected AnnoCTR holdouts."
    )
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20260801)
    parser.add_argument(
        "--output",
        type=Path,
        default=REPOSITORY_ROOT
        / "data"
        / "experiments"
        / "attack_flow_extraction_holdout_latest.json",
    )
    args = parser.parse_args()
    if args.count < 1:
        raise SystemExit("--count must be positive")

    load_dotenv(REPOSITORY_ROOT / ".env.local", override=False)
    model = deepseek_attack_flow_from_environment()
    if model is None:
        raise SystemExit("ARGUS_LLM_BASE_URL/API_KEY/MODEL are required")

    acceptance = json.loads(
        (
            REPOSITORY_ROOT
            / "data"
            / "corpus"
            / "attack_flow_extraction_acceptance.json"
        ).read_text(encoding="utf-8")
    )
    excluded_hashes = {case["sha256"] for case in acceptance["cases"]}
    artifact_root = (
        REPOSITORY_ROOT
        / "data"
        / "corpus"
        / "artifacts"
        / "COLL-ANNOCTR-D510B694"
    )
    eligible = [
        path
        for path in sorted(artifact_root.glob("*.txt"))
        if sha256(path.read_bytes()).hexdigest() not in excluded_hashes
    ]
    if args.count > len(eligible):
        raise SystemExit("--count exceeds available holdout reports")
    selected = random.Random(args.seed).sample(eligible, args.count)

    cases = []
    all_passed = True
    for artifact in selected:
        content_bytes = artifact.read_bytes()
        content = content_bytes.decode("utf-8")
        digest = sha256(content_bytes).hexdigest()
        title = next(
            (line.strip() for line in content.splitlines() if line.strip()),
            artifact.stem,
        )
        extraction = extract_attack_flow_candidates(
            model,
            {
                "sha256": digest,
                "title": title,
                "publisher": "AnnoCTR holdout report",
                "published_at": "",
                "canonical_url": artifact.name,
            },
            content,
        )
        errors = validate_invariants(extraction, content)
        passed = not errors
        all_passed = all_passed and passed
        cases.append(
            {
                "artifact": artifact.name,
                "sha256": digest,
                "title": title,
                "passed": passed,
                "errors": errors,
                "candidate_count": len(extraction.candidates),
                "candidates": [
                    candidate.model_dump() for candidate in extraction.candidates
                ],
                "audit": extraction.audit,
            }
        )
        print(
            f"{artifact.name}: {'PASS' if passed else 'FAIL'} "
            f"({len(extraction.candidates)} candidates)",
            flush=True,
        )

    output = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "selection": {
            "method": "random-with-fixed-seed",
            "seed": args.seed,
            "count": args.count,
            "acceptance_hashes_excluded": True,
        },
        "passed": all_passed,
        "cases": cases,
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


def validate_invariants(extraction, source_text: str) -> list[str]:
    errors: list[str] = []
    for candidate_index, candidate in enumerate(extraction.candidates, start=1):
        action_ids = {action.id for action in candidate.actions}
        if len(candidate.actions) < 2:
            errors.append(f"candidate {candidate_index}: fewer than two actions")
        relation_pairs = set()
        for action in candidate.actions:
            if not action.evidence:
                errors.append(f"candidate {candidate_index}: action without evidence")
            for evidence in action.evidence:
                if evidence.quote not in source_text:
                    errors.append(f"candidate {candidate_index}: invalid action quote")
            for context in action.contexts:
                if not context.evidence:
                    errors.append(f"candidate {candidate_index}: context without evidence")
                for evidence in context.evidence:
                    if evidence.quote not in source_text:
                        errors.append(f"candidate {candidate_index}: invalid context quote")
        for relation in candidate.relations:
            if relation.type not in ALLOWED_RELATIONS:
                errors.append(f"candidate {candidate_index}: invalid relation type")
            if (
                relation.source_action_id not in action_ids
                or relation.target_action_id not in action_ids
            ):
                errors.append(f"candidate {candidate_index}: invalid relation endpoint")
            if not relation.evidence:
                errors.append(f"candidate {candidate_index}: relation without evidence")
            for evidence in relation.evidence:
                if evidence.quote not in source_text:
                    errors.append(f"candidate {candidate_index}: invalid relation quote")
            relation_pairs.add(
                (relation.source_action_id, relation.target_action_id)
            )
        for source_id, target_id in zip(
            candidate.mainline,
            candidate.mainline[1:],
        ):
            if (source_id, target_id) not in relation_pairs:
                errors.append(f"candidate {candidate_index}: unsupported mainline edge")
    return errors


if __name__ == "__main__":
    raise SystemExit(main())
