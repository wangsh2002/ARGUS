PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS curated_extraction_baselines (
  source_sha256 TEXT PRIMARY KEY,
  profile_name TEXT NOT NULL,
  observations_json TEXT NOT NULL,
  review_note TEXT NOT NULL,
  reviewed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS extraction_cache (
  source_sha256 TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  model TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (source_sha256, prompt_version, model)
);

INSERT OR REPLACE INTO curated_extraction_baselines (
  source_sha256,
  profile_name,
  observations_json,
  review_note,
  reviewed_at
) VALUES (
  '794045a1f5fdb454066fd876afc9ac90336515ba04baa8d7546b0a43685183a3',
  'jaguar-tooth-partial-alert-v1',
  '[
    {
      "value": "CVE-2017-6742",
      "kind": "vulnerability",
      "confidence": 1.0,
      "locators": ["paragraph:1"],
      "quote": "CVE-2017-6742"
    },
    {
      "value": "Jaguar Tooth",
      "kind": "malware",
      "confidence": 1.0,
      "locators": ["paragraph:1"],
      "quote": "Jaguar Tooth"
    },
    {
      "value": "系统信息收集",
      "kind": "behavior",
      "confidence": 0.98,
      "locators": ["paragraph:1"],
      "quote": "通过 CLI 执行 show version、show interfaces 等系统信息收集命令"
    }
  ]',
  '赛前逐项复核：三个观测均可由同一告警段落直接定位；不将补全和预测步骤伪装为输入事实。',
  '2026-07-28T16:10:00+08:00'
);

UPDATE source_documents
SET review_state = 'curated'
WHERE sha256 = '794045a1f5fdb454066fd876afc9ac90336515ba04baa8d7546b0a43685183a3';

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
VALUES (
  9,
  'curated_observation_extraction',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

COMMIT;
