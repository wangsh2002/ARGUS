PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS entity_mentions (
  id TEXT PRIMARY KEY,
  entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  source_document_id TEXT NOT NULL REFERENCES source_documents(id),
  source_span_id TEXT NOT NULL REFERENCES source_spans(id),
  ingestion_id TEXT NOT NULL REFERENCES knowledge_ingestion_runs(id),
  original_value TEXT NOT NULL,
  canonical_value TEXT NOT NULL,
  value_type TEXT NOT NULL,
  confidence REAL NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(entity_id, source_span_id, original_value)
);

CREATE INDEX IF NOT EXISTS idx_entity_mentions_entity
  ON entity_mentions(entity_id, created_at);

CREATE INDEX IF NOT EXISTS idx_entity_mentions_source
  ON entity_mentions(source_document_id, source_span_id);

INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
VALUES (
  12,
  'canonical_entity_mentions_and_no_path_ingestion',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

COMMIT;
