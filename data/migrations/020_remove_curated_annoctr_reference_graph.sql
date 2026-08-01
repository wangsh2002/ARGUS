PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TEMP TABLE migration_020_guard(should_apply INTEGER NOT NULL);

INSERT INTO migration_020_guard(should_apply)
SELECT CASE
  WHEN EXISTS(SELECT 1 FROM schema_migrations WHERE version = 20) THEN 0
  ELSE 1
END;

DELETE FROM activity_paths
WHERE id IN (
    'PATH-ANNOCTR-APT28-ZEBROCY-2020',
    'PATH-ANNOCTR-APT29-DNC-2015',
    'PATH-ANNOCTR-LAZARUS-REDBANC-2018'
  )
  AND EXISTS(
    SELECT 1 FROM migration_020_guard WHERE should_apply = 1
  );

DELETE FROM evidence
WHERE relationship_id IN (
    SELECT id FROM relationships
    WHERE seed_origin = 'annoctr-curated-v1'
  )
  AND EXISTS(
    SELECT 1 FROM migration_020_guard WHERE should_apply = 1
  );

DELETE FROM relationships
WHERE seed_origin = 'annoctr-curated-v1'
  AND EXISTS(
    SELECT 1 FROM migration_020_guard WHERE should_apply = 1
  );

DELETE FROM entities
WHERE seed_origin = 'annoctr-curated-v1'
  AND EXISTS(
    SELECT 1 FROM migration_020_guard WHERE should_apply = 1
  );

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (
  20,
  'remove_curated_annoctr_reference_graph',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

DROP TABLE migration_020_guard;

COMMIT;
