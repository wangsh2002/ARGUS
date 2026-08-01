PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

ALTER TABLE activity_path_edges ADD COLUMN v1_relation_type TEXT;

CREATE TABLE IF NOT EXISTS reported_actor_claims (
  id TEXT PRIMARY KEY,
  path_id TEXT NOT NULL REFERENCES activity_paths(id) ON DELETE CASCADE,
  reported_name TEXT NOT NULL,
  actor_id TEXT REFERENCES entities(id) ON DELETE SET NULL,
  confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
  review_state TEXT NOT NULL CHECK(
    review_state IN (
      'machine-proposed',
      'agent-assisted-reviewed',
      'curator-confirmed',
      'rejected'
    )
  ),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_reported_actor_claim_path
  ON reported_actor_claims(path_id);
CREATE INDEX IF NOT EXISTS idx_reported_actor_claim_actor
  ON reported_actor_claims(actor_id, path_id);

CREATE TABLE IF NOT EXISTS reported_actor_evidence_links (
  id TEXT PRIMARY KEY,
  actor_claim_id TEXT NOT NULL
    REFERENCES reported_actor_claims(id) ON DELETE CASCADE,
  source_span_id TEXT NOT NULL REFERENCES source_spans(id) ON DELETE RESTRICT,
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
  UNIQUE(actor_claim_id, source_span_id, quote)
);

CREATE INDEX IF NOT EXISTS idx_reported_actor_evidence_claim
  ON reported_actor_evidence_links(actor_claim_id);

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (
  17,
  'reviewed_attack_flow_publication',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

COMMIT;
