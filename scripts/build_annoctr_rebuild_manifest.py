#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=root / "data/corpus/annoctr_actor_coverage_manifest.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "data/corpus/annoctr_rebuild_50_manifest.json",
    )
    parser.add_argument("--count", type=int, default=50)
    args = parser.parse_args()

    manifest = json.loads(args.source.read_text(encoding="utf-8"))
    reports = manifest.get("reports", [])
    if args.count < 1 or args.count > len(reports):
        raise SystemExit(f"--count must be between 1 and {len(reports)}")

    rebuilt = {
        "schema_version": manifest["schema_version"],
        "collection": {
            **manifest["collection"],
            "notes": (
                f"Deterministic ARGUS rebuild set: first {args.count} records "
                "from annoctr_actor_coverage_manifest.json. Dataset labels are "
                "selection aids only and are never imported as graph facts."
            ),
        },
        "selection": {
            "source_manifest": str(args.source.relative_to(root)),
            "method": "manifest-order-prefix",
            "count": args.count,
        },
        "reports": reports[: args.count],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        f"{json.dumps(rebuilt, ensure_ascii=False, indent=2)}\n",
        encoding="utf-8",
    )
    print(f"wrote {args.output} ({args.count} reports)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
