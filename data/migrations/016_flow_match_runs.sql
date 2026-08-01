BEGIN;

CREATE TABLE IF NOT EXISTS flow_match_runs (
  id TEXT PRIMARY KEY,
  query_text TEXT NOT NULL,
  normalized_inputs_json TEXT NOT NULL,
  algorithm_version TEXT NOT NULL,
  knowledge_snapshot TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
VALUES (16, 'flow_match_runs', CURRENT_TIMESTAMP);

COMMIT;
