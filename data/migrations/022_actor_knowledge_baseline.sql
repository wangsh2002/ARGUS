PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS actor_external_mappings (
  actor_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  canonical_name TEXT NOT NULL,
  mapping_status TEXT NOT NULL CHECK(
    mapping_status IN ('exact-alias', 'associated-name', 'local-only')
  ),
  confidence REAL NOT NULL,
  source_url TEXT NOT NULL DEFAULT '',
  source_version TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (source, external_id),
  UNIQUE (actor_id, source)
);

CREATE INDEX IF NOT EXISTS idx_actor_external_mappings_actor
  ON actor_external_mappings(actor_id, source);

CREATE INDEX IF NOT EXISTS idx_relationships_seed_origin
  ON relationships(seed_origin);

CREATE INDEX IF NOT EXISTS idx_aliases_source
  ON aliases(source);

INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
VALUES (
  22,
  'dynamic_actor_knowledge_baseline',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

COMMIT;
