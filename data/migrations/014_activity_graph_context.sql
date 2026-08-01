PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS action_context_links (
  id TEXT PRIMARY KEY,
  path_id TEXT NOT NULL REFERENCES activity_paths(id) ON DELETE CASCADE,
  action_node_id TEXT NOT NULL REFERENCES activity_path_nodes(id) ON DELETE CASCADE,
  entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE RESTRICT,
  role TEXT NOT NULL,
  direction TEXT NOT NULL CHECK(
    direction IN ('action-to-entity', 'entity-to-action')
  ),
  first_seen TEXT,
  last_seen TEXT,
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
  UNIQUE(path_id, action_node_id, entity_id, role)
);

CREATE INDEX IF NOT EXISTS idx_action_context_path
  ON action_context_links(path_id, action_node_id);
CREATE INDEX IF NOT EXISTS idx_action_context_entity
  ON action_context_links(entity_id, path_id);

CREATE TABLE IF NOT EXISTS action_context_evidence_links (
  id TEXT PRIMARY KEY,
  context_link_id TEXT NOT NULL
    REFERENCES action_context_links(id) ON DELETE CASCADE,
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
  UNIQUE(context_link_id, source_span_id, support_type)
);

CREATE INDEX IF NOT EXISTS idx_action_context_evidence_link
  ON action_context_evidence_links(context_link_id);
CREATE INDEX IF NOT EXISTS idx_action_context_evidence_span
  ON action_context_evidence_links(source_span_id);

CREATE TABLE IF NOT EXISTS analysis_projections (
  id TEXT PRIMARY KEY,
  path_id TEXT NOT NULL REFERENCES activity_paths(id) ON DELETE CASCADE,
  projection_kind TEXT NOT NULL CHECK(
    projection_kind IN ('soc-triage', 'incident-response')
  ),
  root_action_refs_json TEXT NOT NULL DEFAULT '[]',
  mainline_action_refs_json TEXT NOT NULL DEFAULT '[]',
  mainline_dependency_refs_json TEXT NOT NULL DEFAULT '[]',
  branch_groups_json TEXT NOT NULL DEFAULT '[]',
  key_context_by_action_json TEXT NOT NULL DEFAULT '{}',
  lane_assignment_json TEXT NOT NULL DEFAULT '{}',
  node_state_json TEXT NOT NULL DEFAULT '{}',
  selection_reason TEXT NOT NULL DEFAULT '',
  algorithm_version TEXT NOT NULL,
  generated_at TEXT NOT NULL,
  UNIQUE(path_id, projection_kind)
);

CREATE INDEX IF NOT EXISTS idx_analysis_projection_path
  ON analysis_projections(path_id, projection_kind);

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (
  14,
  'activity_graph_context',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

COMMIT;
