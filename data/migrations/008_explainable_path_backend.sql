PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS source_documents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  publisher TEXT NOT NULL,
  canonical_url TEXT NOT NULL,
  published_at TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  sha256 TEXT NOT NULL UNIQUE,
  content TEXT NOT NULL,
  content_size INTEGER NOT NULL,
  review_state TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS source_spans (
  id TEXT PRIMARY KEY,
  source_document_id TEXT NOT NULL REFERENCES source_documents(id),
  locator TEXT NOT NULL,
  start_offset INTEGER NOT NULL,
  end_offset INTEGER NOT NULL,
  text TEXT NOT NULL,
  extraction_method TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_source_spans_document
  ON source_spans(source_document_id, start_offset);

CREATE TABLE IF NOT EXISTS path_analysis_runs (
  id TEXT PRIMARY KEY,
  source_document_id TEXT NOT NULL REFERENCES source_documents(id),
  query_text TEXT NOT NULL,
  algorithm_version TEXT NOT NULL,
  knowledge_snapshot TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_path_analysis_runs_source
  ON path_analysis_runs(source_document_id, created_at);

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (
  8,
  'explainable_path_backend',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

COMMIT;
