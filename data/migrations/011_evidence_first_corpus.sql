PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS corpus_collections (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner TEXT NOT NULL,
  upstream_url TEXT NOT NULL,
  version TEXT NOT NULL,
  license TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL,
  retrieved_at TEXT NOT NULL,
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(upstream_url, version)
);

CREATE TABLE IF NOT EXISTS source_artifacts (
  id TEXT PRIMARY KEY,
  collection_id TEXT NOT NULL REFERENCES corpus_collections(id),
  collection_record_id TEXT NOT NULL,
  title TEXT NOT NULL,
  publisher TEXT NOT NULL,
  canonical_url TEXT NOT NULL,
  acquisition_source TEXT NOT NULL,
  acquisition_url TEXT NOT NULL,
  published_at TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
  sha256 TEXT NOT NULL UNIQUE,
  storage_path TEXT NOT NULL,
  dataset_license TEXT NOT NULL,
  source_license TEXT NOT NULL,
  tlp TEXT NOT NULL,
  archive_status TEXT NOT NULL CHECK(
    archive_status IN (
      'canonical-original',
      'canonical-verified-copy',
      'archived-copy',
      'text-only'
    )
  ),
  canonical_verification_state TEXT NOT NULL CHECK(
    canonical_verification_state IN (
      'verified',
      'unavailable',
      'unverified'
    )
  ),
  canonical_verified_at TEXT,
  review_state TEXT NOT NULL CHECK(
    review_state IN (
      'raw',
      'parsed',
      'agent-assisted-reviewed',
      'curator-confirmed',
      'rejected'
    )
  ),
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(collection_id, collection_record_id)
);

CREATE INDEX IF NOT EXISTS idx_source_artifacts_collection
  ON source_artifacts(collection_id, published_at);
CREATE INDEX IF NOT EXISTS idx_source_artifacts_publisher
  ON source_artifacts(publisher, published_at);
CREATE INDEX IF NOT EXISTS idx_source_artifacts_review
  ON source_artifacts(review_state, archive_status);

ALTER TABLE source_documents
  ADD COLUMN artifact_id TEXT REFERENCES source_artifacts(id);
ALTER TABLE source_documents
  ADD COLUMN collected_at TEXT NOT NULL DEFAULT '';
ALTER TABLE source_documents
  ADD COLUMN parser_name TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE source_documents
  ADD COLUMN parser_version TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE source_documents
  ADD COLUMN license TEXT NOT NULL DEFAULT '';
ALTER TABLE source_documents
  ADD COLUMN tlp TEXT NOT NULL DEFAULT '';
ALTER TABLE source_documents
  ADD COLUMN canonical_verification_state TEXT NOT NULL DEFAULT 'unverified';

CREATE UNIQUE INDEX IF NOT EXISTS idx_source_documents_artifact
  ON source_documents(artifact_id)
  WHERE artifact_id IS NOT NULL;

ALTER TABLE source_spans
  ADD COLUMN artifact_id TEXT REFERENCES source_artifacts(id);
ALTER TABLE source_spans
  ADD COLUMN locator_type TEXT NOT NULL DEFAULT 'character-range';
ALTER TABLE source_spans
  ADD COLUMN page_number INTEGER;
ALTER TABLE source_spans
  ADD COLUMN line_start INTEGER;
ALTER TABLE source_spans
  ADD COLUMN line_end INTEGER;
ALTER TABLE source_spans
  ADD COLUMN block_index INTEGER;
ALTER TABLE source_spans
  ADD COLUMN selector TEXT;
ALTER TABLE source_spans
  ADD COLUMN bbox_json TEXT;
ALTER TABLE source_spans
  ADD COLUMN quote_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE source_spans
  ADD COLUMN parser_version TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE source_spans
  ADD COLUMN review_state TEXT NOT NULL DEFAULT 'machine-parsed';

CREATE INDEX IF NOT EXISTS idx_source_spans_artifact
  ON source_spans(artifact_id, line_start, page_number);

CREATE TABLE IF NOT EXISTS activity_paths (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  activity_key TEXT NOT NULL UNIQUE,
  path_kind TEXT NOT NULL CHECK(
    path_kind IN ('historical', 'gold-standard', 'demo')
  ),
  review_state TEXT NOT NULL CHECK(
    review_state IN (
      'draft',
      'agent-assisted-reviewed',
      'curator-confirmed',
      'published',
      'rejected'
    )
  ),
  reviewer_type TEXT NOT NULL CHECK(
    reviewer_type IN ('none', 'agent-assisted', 'human')
  ),
  reviewer_id TEXT,
  reviewed_at TEXT,
  primary_artifact_id TEXT REFERENCES source_artifacts(id),
  started_at TEXT,
  ended_at TEXT,
  victim_scope TEXT NOT NULL DEFAULT '',
  confidence REAL NOT NULL DEFAULT 0.0 CHECK(
    confidence >= 0.0 AND confidence <= 1.0
  ),
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS activity_path_nodes (
  id TEXT PRIMARY KEY,
  path_id TEXT NOT NULL REFERENCES activity_paths(id) ON DELETE CASCADE,
  entity_id TEXT REFERENCES entities(id) ON DELETE SET NULL,
  occurrence_key TEXT NOT NULL,
  label TEXT NOT NULL,
  node_type TEXT NOT NULL,
  phase TEXT NOT NULL DEFAULT '',
  sequence_hint REAL,
  assertion_origin TEXT NOT NULL CHECK(
    assertion_origin IN (
      'source-observed',
      'curator-confirmed',
      'algorithm-reconstructed',
      'algorithm-predicted'
    )
  ),
  review_state TEXT NOT NULL CHECK(
    review_state IN (
      'machine-proposed',
      'agent-assisted-reviewed',
      'curator-confirmed',
      'rejected'
    )
  ),
  confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
  properties_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(path_id, occurrence_key)
);

CREATE TABLE IF NOT EXISTS activity_path_edges (
  id TEXT PRIMARY KEY,
  path_id TEXT NOT NULL REFERENCES activity_paths(id) ON DELETE CASCADE,
  source_node_id TEXT NOT NULL REFERENCES activity_path_nodes(id) ON DELETE CASCADE,
  target_node_id TEXT NOT NULL REFERENCES activity_path_nodes(id) ON DELETE CASCADE,
  edge_type TEXT NOT NULL CHECK(
    edge_type IN (
      'sequence',
      'enables',
      'causes',
      'conditional',
      'branch',
      'merge'
    )
  ),
  branch_group TEXT,
  condition_label TEXT,
  assertion_origin TEXT NOT NULL CHECK(
    assertion_origin IN (
      'source-observed',
      'curator-confirmed',
      'algorithm-reconstructed',
      'algorithm-predicted'
    )
  ),
  review_state TEXT NOT NULL CHECK(
    review_state IN (
      'machine-proposed',
      'agent-assisted-reviewed',
      'curator-confirmed',
      'rejected'
    )
  ),
  confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
  properties_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(path_id, source_node_id, target_node_id, edge_type)
);

CREATE INDEX IF NOT EXISTS idx_activity_path_nodes_path
  ON activity_path_nodes(path_id, sequence_hint);
CREATE INDEX IF NOT EXISTS idx_activity_path_edges_path
  ON activity_path_edges(path_id, source_node_id, target_node_id);

CREATE TABLE IF NOT EXISTS path_evidence_links (
  id TEXT PRIMARY KEY,
  path_id TEXT NOT NULL REFERENCES activity_paths(id) ON DELETE CASCADE,
  node_id TEXT REFERENCES activity_path_nodes(id) ON DELETE CASCADE,
  edge_id TEXT REFERENCES activity_path_edges(id) ON DELETE CASCADE,
  source_span_id TEXT NOT NULL REFERENCES source_spans(id) ON DELETE RESTRICT,
  support_type TEXT NOT NULL CHECK(
    support_type IN ('supports', 'contradicts', 'context')
  ),
  evidence_role TEXT NOT NULL CHECK(
    evidence_role IN ('direct', 'corroborating', 'background')
  ),
  quote TEXT NOT NULL,
  confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
  review_state TEXT NOT NULL CHECK(
    review_state IN (
      'machine-proposed',
      'agent-assisted-reviewed',
      'curator-confirmed',
      'rejected'
    )
  ),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK(
    (node_id IS NOT NULL AND edge_id IS NULL)
    OR (node_id IS NULL AND edge_id IS NOT NULL)
  ),
  UNIQUE(node_id, edge_id, source_span_id, support_type)
);

CREATE INDEX IF NOT EXISTS idx_path_evidence_span
  ON path_evidence_links(source_span_id);
CREATE INDEX IF NOT EXISTS idx_path_evidence_path
  ON path_evidence_links(path_id, node_id, edge_id);

CREATE TABLE IF NOT EXISTS review_records (
  id TEXT PRIMARY KEY,
  target_type TEXT NOT NULL CHECK(
    target_type IN (
      'source-artifact',
      'source-span',
      'activity-path',
      'path-node',
      'path-edge',
      'evidence-link'
    )
  ),
  target_id TEXT NOT NULL,
  decision TEXT NOT NULL CHECK(
    decision IN ('accept', 'revise', 'reject')
  ),
  reviewer_type TEXT NOT NULL CHECK(
    reviewer_type IN ('agent-assisted', 'human')
  ),
  reviewer_id TEXT NOT NULL,
  note TEXT NOT NULL,
  reviewed_at TEXT NOT NULL,
  previous_state TEXT NOT NULL DEFAULT '',
  resulting_state TEXT NOT NULL,
  UNIQUE(target_type, target_id, reviewer_id, reviewed_at)
);

CREATE INDEX IF NOT EXISTS idx_review_records_target
  ON review_records(target_type, target_id, reviewed_at);

CREATE TABLE IF NOT EXISTS gold_evaluation_cases (
  id TEXT PRIMARY KEY,
  path_id TEXT NOT NULL REFERENCES activity_paths(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  split TEXT NOT NULL CHECK(split IN ('development', 'test', 'demo')),
  task_type TEXT NOT NULL CHECK(
    task_type IN (
      'node-reconstruction',
      'edge-reconstruction',
      'next-step-prediction',
      'activity-clustering'
    )
  ),
  masking_spec_json TEXT NOT NULL,
  expected_result_json TEXT NOT NULL,
  source_family_key TEXT NOT NULL,
  review_state TEXT NOT NULL CHECK(
    review_state IN ('draft', 'curator-confirmed', 'published')
  ),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(path_id, name, task_type)
);

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (
  11,
  'evidence_first_report_corpus_and_paths',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

COMMIT;
