#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from argus_backend.actor_knowledge_sync import sync_actor_knowledge


ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
MISP_URL = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/"
    "main/clusters/threat-actor.json"
)


def load_json(path: Path | None, url: str) -> dict:
    if path is not None:
        return json.loads(path.read_text(encoding="utf-8"))
    request = Request(url, headers={"User-Agent": "ARGUS actor knowledge sync"})
    with urlopen(request, timeout=120) as response:
        return json.load(response)


def apply_migration(database: Path) -> None:
    migration = ROOT / "data/migrations/022_actor_knowledge_baseline.sql"
    with sqlite3.connect(database) as connection:
        applied = connection.execute(
            "SELECT 1 FROM schema_migrations WHERE version = 22"
        ).fetchone()
        if applied is None:
            connection.executescript(migration.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Synchronize canonical actor profiles from ATT&CK and MISP."
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=ROOT / "data/argus_cti.db",
    )
    parser.add_argument("--attack-file", type=Path)
    parser.add_argument("--misp-file", type=Path)
    parser.add_argument("--attack-url", default=ATTACK_URL)
    parser.add_argument("--misp-url", default=MISP_URL)
    args = parser.parse_args()

    apply_migration(args.database)
    attack_bundle = load_json(args.attack_file, args.attack_url)
    misp_bundle = load_json(args.misp_file, args.misp_url)
    result = sync_actor_knowledge(args.database, attack_bundle, misp_bundle)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
