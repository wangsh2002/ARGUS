PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS knowledge_ingestion_runs (
  id TEXT PRIMARY KEY,
  source_document_id TEXT NOT NULL REFERENCES source_documents(id),
  status TEXT NOT NULL,
  result_json TEXT NOT NULL,
  version_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS knowledge_versions (
  id TEXT PRIMARY KEY,
  ingestion_id TEXT NOT NULL UNIQUE REFERENCES knowledge_ingestion_runs(id),
  status TEXT NOT NULL,
  changes_json TEXT NOT NULL,
  published_at TEXT NOT NULL,
  rolled_back_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_knowledge_ingestion_source
  ON knowledge_ingestion_runs(source_document_id, created_at);

CREATE INDEX IF NOT EXISTS idx_knowledge_versions_status
  ON knowledge_versions(status, published_at);

DROP TABLE IF EXISTS staging_relations;
DROP TABLE IF EXISTS staging_entities;

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (
  10,
  'versioned_knowledge_ingestion',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

COMMIT;
