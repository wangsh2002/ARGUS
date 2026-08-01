PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TEMP TABLE migration_019_guard(should_apply INTEGER NOT NULL);

INSERT INTO migration_019_guard(should_apply)
SELECT CASE
  WHEN EXISTS(SELECT 1 FROM schema_migrations WHERE version = 19) THEN 0
  ELSE 1
END;

CREATE TEMP TABLE migration_019_fake_reports(id TEXT PRIMARY KEY);

INSERT INTO migration_019_fake_reports(id) VALUES
  ('RPT-SEED-d45dbe73f95721745a'),
  ('RPT-SEED-abf4d00002ff6e173d'),
  ('RPT-SEED-7f69a307692b86ad74'),
  ('RPT-SEED-6c94aa06df23f87f44'),
  ('RPT-SEED-e02345ea5345bdda4f'),
  ('RPT-SEED-91f82dc784c3d769ce'),
  ('RPT-SEED-0fde17a8788a5ac8e8'),
  ('RPT-CORE-DEMO-INPUT-23397'),
  ('RPT-SEED-9467c190335880dd6a');

DELETE FROM report_event_graphs
WHERE report_id IN (SELECT id FROM migration_019_fake_reports)
  AND EXISTS(
    SELECT 1 FROM migration_019_guard WHERE should_apply = 1
  );

DELETE FROM evidence
WHERE (
    report_id IN (SELECT id FROM migration_019_fake_reports)
    OR relationship_id IN (
      SELECT id
      FROM relationships
      WHERE seed_origin IN ('legacy_full_graph_v2', 'migration-005-core-demo')
         OR (
           seed_origin = ''
           AND created_at = '2026-07-20T12:02:47+08:00'
         )
    )
  )
  AND EXISTS(
    SELECT 1 FROM migration_019_guard WHERE should_apply = 1
  );

DELETE FROM relationships
WHERE (
    seed_origin IN ('legacy_full_graph_v2', 'migration-005-core-demo')
    OR (
      seed_origin = ''
      AND created_at = '2026-07-20T12:02:47+08:00'
    )
  )
  AND EXISTS(
    SELECT 1 FROM migration_019_guard WHERE should_apply = 1
  );

DELETE FROM entities
WHERE (
    seed_origin IN ('legacy_full_graph_v2', 'migration-005-core-demo')
    OR (
      seed_origin = ''
      AND created_at = '2026-07-20T12:02:47+08:00'
    )
  )
  AND EXISTS(
    SELECT 1 FROM migration_019_guard WHERE should_apply = 1
  );

DELETE FROM import_jobs
WHERE report_id IN (SELECT id FROM migration_019_fake_reports)
  AND EXISTS(
    SELECT 1 FROM migration_019_guard WHERE should_apply = 1
  );

DELETE FROM raw_reports
WHERE id IN (SELECT id FROM migration_019_fake_reports)
  AND EXISTS(
    SELECT 1 FROM migration_019_guard WHERE should_apply = 1
  );

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (
  19,
  'remove_legacy_fake_seed_data',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

DROP TABLE migration_019_fake_reports;
DROP TABLE migration_019_guard;

COMMIT;
