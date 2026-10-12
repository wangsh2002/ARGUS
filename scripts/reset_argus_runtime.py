#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sqlite3


PRESERVED_TABLES = {
    "algorithm_configs",
    "response_rules",
    "schema_migrations",
}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database",
        type=Path,
        default=root / "data/argus_cti.db",
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=root / "data/corpus/artifacts/COLL-ANNOCTR-D510B694",
    )
    args = parser.parse_args()

    with sqlite3.connect(args.database) as connection:
        tables = [
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            )
            if row[0] not in PRESERVED_TABLES
        ]
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("BEGIN IMMEDIATE")
        try:
            for table in tables:
                connection.execute(f'DELETE FROM "{table}"')
            connection.execute("DELETE FROM sqlite_sequence")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        connection.execute("PRAGMA foreign_keys = ON")
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(f"foreign key violations after reset: {violations}")
        connection.execute("VACUUM")

    for path in (
        args.artifact_root,
        root / "data/experiments",
        root / "data/rebuild",
        root / ".scratch/model-benchmark",
    ):
        if path.exists():
            shutil.rmtree(path)

    print(f"reset {args.database}; cleared {len(tables)} business tables")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
