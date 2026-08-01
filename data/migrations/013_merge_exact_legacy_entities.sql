PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

-- Exact ATT&CK identifiers are global entities, not actor-scoped copies.
UPDATE relationships
SET source_entity_id = 'APT28-tech-t1187'
WHERE source_entity_id = '组织 Z-tech-t1187';
UPDATE relationships
SET target_entity_id = 'APT28-tech-t1187'
WHERE target_entity_id = '组织 Z-tech-t1187';
UPDATE entities
SET canonical_key = 'attack-technique:t1187',
    source_count = (
      SELECT SUM(source_count)
      FROM entities
      WHERE id IN ('APT28-tech-t1187', '组织 Z-tech-t1187')
    ),
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = 'APT28-tech-t1187';
DELETE FROM entities WHERE id = '组织 Z-tech-t1187';

UPDATE relationships
SET source_entity_id = 'ENT-ac4a988b3b074974876e625d1749f9ba'
WHERE source_entity_id = 'APT28-tech-t1190';
UPDATE relationships
SET target_entity_id = 'ENT-ac4a988b3b074974876e625d1749f9ba'
WHERE target_entity_id = 'APT28-tech-t1190';
UPDATE entities
SET canonical_key = 'attack-technique:t1190',
    source_count = (
      SELECT SUM(source_count)
      FROM entities
      WHERE id IN (
        'ENT-ac4a988b3b074974876e625d1749f9ba',
        'APT28-tech-t1190'
      )
    ),
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = 'ENT-ac4a988b3b074974876e625d1749f9ba';
DELETE FROM entities WHERE id = 'APT28-tech-t1190';

UPDATE relationships
SET source_entity_id = 'APT29-tech-t1566'
WHERE source_entity_id = '组织 Z-tech-t1566';
UPDATE relationships
SET target_entity_id = 'APT29-tech-t1566'
WHERE target_entity_id = '组织 Z-tech-t1566';
UPDATE entities
SET canonical_key = 'attack-technique:t1566.002',
    source_count = (
      SELECT SUM(source_count)
      FROM entities
      WHERE id IN ('APT29-tech-t1566', '组织 Z-tech-t1566')
    ),
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = 'APT29-tech-t1566';
DELETE FROM entities WHERE id = '组织 Z-tech-t1566';

-- The literal observable is global; report/activity usage remains on relations.
UPDATE relationships
SET source_entity_id = 'Lazarus-infra-market-ip'
WHERE source_entity_id = 'CORE-23397-ioc-demo-smb';
UPDATE relationships
SET target_entity_id = 'Lazarus-infra-market-ip'
WHERE target_entity_id = 'CORE-23397-ioc-demo-smb';
UPDATE entities
SET canonical_key = 'ipv4:203.0.113.77',
    source_count = (
      SELECT SUM(source_count)
      FROM entities
      WHERE id IN (
        'Lazarus-infra-market-ip',
        'CORE-23397-ioc-demo-smb'
      )
    ),
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = 'Lazarus-infra-market-ip';
DELETE FROM entities WHERE id = 'CORE-23397-ioc-demo-smb';

-- Jaguar Tooth is an exact known software identity in both legacy records.
UPDATE relationships
SET source_entity_id = 'APT28-malware-jaguartooth'
WHERE source_entity_id = 'ENT-d6f8c193d8b845aaa3dec96dcd6502af';
UPDATE relationships
SET target_entity_id = 'APT28-malware-jaguartooth'
WHERE target_entity_id = 'ENT-d6f8c193d8b845aaa3dec96dcd6502af';
UPDATE entities
SET canonical_key = 'software-name:jaguartooth',
    source_count = (
      SELECT SUM(source_count)
      FROM entities
      WHERE id IN (
        'APT28-malware-jaguartooth',
        'ENT-d6f8c193d8b845aaa3dec96dcd6502af'
      )
    ),
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = 'APT28-malware-jaguartooth';
DELETE FROM entities WHERE id = 'ENT-d6f8c193d8b845aaa3dec96dcd6502af';

INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
VALUES (
  13,
  'merge_exact_legacy_ioc_technique_and_software_entities',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

COMMIT;
