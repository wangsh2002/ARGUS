PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS flow_source_supports (
  id TEXT PRIMARY KEY,
  path_id TEXT NOT NULL REFERENCES activity_paths(id) ON DELETE CASCADE,
  source_document_id TEXT NOT NULL
    REFERENCES source_documents(id) ON DELETE RESTRICT,
  ingestion_id TEXT NOT NULL REFERENCES knowledge_ingestion_runs(id),
  support_kind TEXT NOT NULL CHECK(
    support_kind IN ('primary', 'additional')
  ),
  candidate_fingerprint TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(path_id, source_document_id),
  UNIQUE(source_document_id, candidate_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_flow_source_support_path
  ON flow_source_supports(path_id, source_document_id);
CREATE INDEX IF NOT EXISTS idx_flow_source_support_source
  ON flow_source_supports(source_document_id, path_id);

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (
  18,
  'flow_source_cardinality_and_merge',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

COMMIT;
