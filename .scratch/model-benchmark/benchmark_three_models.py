"""PROTOTYPE — compare Pro and Flash on three fixed AttackFlow reports."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from time import perf_counter

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from argus_backend.attack_flow_extraction import (  # noqa: E402
    ALLOWED_RELATIONS,
    DeepSeekAttackFlowExtractor,
    extract_attack_flow_candidates,
)


MODELS = ["deepseek-v4-pro", "deepseek-v4-flash"]
CASE_IDS = [
    "annoctr-no-flow",
    "annoctr-missing-relation-evidence",
    "annoctr-branch-and-merge",
]
OUTPUT = ROOT / ".scratch/model-benchmark/three_case_comparison.json"


def topology(candidates) -> dict[str, bool]:
    has_branch = False
    has_merge = False
    for candidate in candidates:
        outgoing = {action.id: 0 for action in candidate.actions}
        incoming = {action.id: 0 for action in candidate.actions}
        for relation in candidate.relations:
            outgoing[relation.source_action_id] += 1
            incoming[relation.target_action_id] += 1
        roots = sum(count == 0 for count in incoming.values())
        has_branch = has_branch or roots > 1 or any(count > 1 for count in outgoing.values())
        has_merge = has_merge or any(count > 1 for count in incoming.values())
    return {"branch": has_branch, "merge": has_merge}


def invariant_errors(extraction, source_text: str) -> list[str]:
    errors = []
    for candidate_index, candidate in enumerate(extraction.candidates, start=1):
        action_ids = {action.id for action in candidate.actions}
        relation_pairs = set()
        if len(candidate.actions) < 2:
            errors.append(f"candidate {candidate_index}: fewer than two actions")
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
            if relation.source_action_id not in action_ids or relation.target_action_id not in action_ids:
                errors.append(f"candidate {candidate_index}: invalid relation endpoint")
            if not relation.evidence:
                errors.append(f"candidate {candidate_index}: relation without evidence")
            for evidence in relation.evidence:
                if evidence.quote not in source_text:
                    errors.append(f"candidate {candidate_index}: invalid relation quote")
            relation_pairs.add((relation.source_action_id, relation.target_action_id))
        for source_id, target_id in zip(candidate.mainline, candidate.mainline[1:]):
            if (source_id, target_id) not in relation_pairs:
                errors.append(f"candidate {candidate_index}: unsupported mainline edge")
    return errors


def run_case(model, case: dict) -> dict:
    artifact = ROOT / case["artifact_path"]
    content_bytes = artifact.read_bytes()
    content = content_bytes.decode("utf-8")
    started = perf_counter()
    extraction = extract_attack_flow_candidates(
        model,
        {
            "sha256": sha256(content_bytes).hexdigest(),
            "title": case["title"],
            "publisher": "AnnoCTR benchmark",
            "published_at": "",
            "canonical_url": case["artifact_path"],
        },
        content,
    )
    elapsed = perf_counter() - started
    candidate_topology = topology(extraction.candidates)
    count = len(extraction.candidates)
    cardinality = case["cardinality"]
    acceptance_passed = (
        cardinality["minimum"] <= count <= cardinality["maximum"]
        and ("branch" not in case["scenarios"] or candidate_topology["branch"])
        and ("merge" not in case["scenarios"] or candidate_topology["merge"])
    )
    errors = invariant_errors(extraction, content)
    result = {
        "id": case["id"],
        "title": case["title"],
        "scenarios": case["scenarios"],
        "elapsed_seconds": round(elapsed, 3),
        "passed": acceptance_passed and not errors,
        "acceptance_passed": acceptance_passed,
        "invariant_errors": errors,
        "candidate_count": count,
        "action_count": sum(len(candidate.actions) for candidate in extraction.candidates),
        "relation_count": sum(len(candidate.relations) for candidate in extraction.candidates),
        "context_count": sum(
            len(action.contexts)
            for candidate in extraction.candidates
            for action in candidate.actions
        ),
        "topology": candidate_topology,
        "rejected_fact_count": len(extraction.audit["rejected_facts"]),
        "unassigned_evidence_count": len(extraction.audit["unassigned_evidence"]),
        "review_fragment_count": len(extraction.audit["review_fragments"]),
        "candidates": [candidate.model_dump() for candidate in extraction.candidates],
    }
    print(
        f"{model.model} | {case['id']} | "
        f"{'PASS' if result['passed'] else 'FAIL'} | {elapsed:.1f}s | "
        f"{result['candidate_count']} flows, {result['action_count']} actions, "
        f"{result['relation_count']} relations",
        flush=True,
    )
    return result


def main() -> None:
    load_dotenv(ROOT / ".env.local", override=False)
    manifest = json.loads(
        (ROOT / "data/corpus/attack_flow_extraction_acceptance.json").read_text()
    )
    cases = {case["id"]: case for case in manifest["cases"]}
    results = []
    for model_name in MODELS:
        model = DeepSeekAttackFlowExtractor(
            base_url=os.environ["ARGUS_LLM_BASE_URL"],
            api_key=os.environ["ARGUS_LLM_API_KEY"],
            model=model_name,
        )
        model_cases = [run_case(model, cases[case_id]) for case_id in CASE_IDS]
        results.append(
            {
                "model": model_name,
                "passed_cases": sum(case["passed"] for case in model_cases),
                "total_seconds": round(sum(case["elapsed_seconds"] for case in model_cases), 3),
                "cases": model_cases,
            }
        )
    OUTPUT.write_text(json.dumps({"models": results}, ensure_ascii=False, indent=2))
    print(f"wrote {OUTPUT}", flush=True)


if __name__ == "__main__":
    main()
