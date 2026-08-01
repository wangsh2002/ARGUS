PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TEMP TABLE migration_015_guard(should_apply INTEGER NOT NULL);

INSERT INTO migration_015_guard(should_apply)
SELECT CASE
  WHEN EXISTS(SELECT 1 FROM schema_migrations WHERE version = 15) THEN 0
  ELSE 1
END;

UPDATE activity_path_edges
SET edge_type = 'causes'
WHERE path_id = 'PATH-ANNOCTR-LAZARUS-REDBANC-2018'
  AND source_node_id = 'PATH-ANNOCTR-LAZARUS-REDBANC-2018-N-03'
  AND edge_type = 'branch'
  AND EXISTS(
    SELECT 1 FROM migration_015_guard WHERE should_apply = 1
  );

DELETE FROM activity_paths
WHERE id NOT IN (
  'PATH-ANNOCTR-APT28-ZEBROCY-2020',
  'PATH-ANNOCTR-APT29-DNC-2015',
  'PATH-ANNOCTR-LAZARUS-REDBANC-2018'
)
AND EXISTS(
  SELECT 1 FROM migration_015_guard WHERE should_apply = 1
);

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (
  15,
  'retained_attack_flows',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

DROP TABLE migration_015_guard;

COMMIT;
