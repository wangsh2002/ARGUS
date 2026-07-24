PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS actor_profiles (
  actor_id TEXT PRIMARY KEY REFERENCES entities(id) ON DELETE CASCADE,
  profile_status TEXT NOT NULL DEFAULT 'verified',
  origin_label TEXT NOT NULL,
  active_from TEXT,
  active_to TEXT,
  public_attribution TEXT NOT NULL,
  motivations_json TEXT NOT NULL DEFAULT '[]',
  target_sectors_json TEXT NOT NULL DEFAULT '[]',
  source_refs_json TEXT NOT NULL DEFAULT '[]',
  source_urls_json TEXT NOT NULL DEFAULT '[]',
  source_grade REAL NOT NULL DEFAULT 0.5,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS algorithm_configs (
  id TEXT PRIMARY KEY,
  algorithm_version TEXT NOT NULL,
  weights_json TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attribution_runs (
  id TEXT PRIMARY KEY,
  query_text TEXT NOT NULL,
  report_id TEXT REFERENCES raw_reports(id) ON DELETE SET NULL,
  mode TEXT NOT NULL,
  algorithm_config_id TEXT NOT NULL REFERENCES algorithm_configs(id),
  knowledge_snapshot TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attribution_candidates (
  run_id TEXT NOT NULL REFERENCES attribution_runs(id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL REFERENCES entities(id) ON DELETE RESTRICT,
  rank INTEGER NOT NULL,
  entity_score REAL NOT NULL,
  technique_score REAL NOT NULL,
  path_score REAL NOT NULL,
  source_score REAL NOT NULL,
  negative_penalty REAL NOT NULL,
  final_score REAL NOT NULL,
  summary TEXT NOT NULL,
  PRIMARY KEY (run_id, actor_id)
);

CREATE TABLE IF NOT EXISTS attribution_evidence (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES attribution_runs(id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL REFERENCES entities(id) ON DELETE RESTRICT,
  evidence_role TEXT NOT NULL,
  entity_id TEXT REFERENCES entities(id) ON DELETE SET NULL,
  relationship_id TEXT REFERENCES relationships(id) ON DELETE SET NULL,
  report_id TEXT REFERENCES raw_reports(id) ON DELETE SET NULL,
  source_ref TEXT NOT NULL DEFAULT '',
  contribution REAL NOT NULL,
  reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS response_rules (
  id TEXT PRIMARY KEY,
  match_entity_type TEXT NOT NULL,
  priority TEXT NOT NULL,
  action_template TEXT NOT NULL,
  rationale TEXT NOT NULL,
  source_url TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_attribution_runs_created
  ON attribution_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attribution_candidates_run
  ON attribution_candidates(run_id, rank);
CREATE INDEX IF NOT EXISTS idx_attribution_evidence_run
  ON attribution_evidence(run_id, actor_id);

INSERT OR REPLACE INTO actor_profiles (
  actor_id, profile_status, origin_label, active_from, active_to,
  public_attribution, motivations_json, target_sectors_json,
  source_refs_json, source_urls_json, source_grade, updated_at
) VALUES
(
  'ENT-ACTOR-fbde425d47a0',
  'verified',
  '俄罗斯 / GRU 第 26165 部队',
  '2004',
  NULL,
  'MITRE ATT&CK 将 APT28 归因于俄罗斯总参谋部情报总局第 26165 部队；UK NCSC 与美国合作机构公开披露其 Cisco 路由器活动。',
  '["战略情报","军事与外交情报","网络侦察"]',
  '["政府机构","国防部门","外交机构","国际组织","媒体"]',
  '["SRC-A28-H10-NCSC"]',
  '["https://attack.mitre.org/groups/G0007/","https://www.ncsc.gov.uk/news/apt28-exploits-known-vulnerability-to-carry-out-reconnaissance-and-deploy-malware-on-cisco-routers"]',
  1.0,
  '2026-07-24T15:40:00+08:00'
),
(
  'ENT-ACTOR-480b4b9fd4a2',
  'verified',
  '俄罗斯 / 对外情报局 SVR',
  '2008',
  NULL,
  'MITRE ATT&CK 将 APT29 归因于俄罗斯对外情报局，公开资料记录其长期针对欧洲及北约国家政府网络、科研机构和智库。',
  '["战略情报","外交情报","云与身份访问"]',
  '["政府网络","科研机构","智库","云服务环境"]',
  '["SRC-A29-H3","SRC-A29-H6"]',
  '["https://attack.mitre.org/groups/G0016/"]',
  0.95,
  '2026-07-24T15:40:00+08:00'
),
(
  'ENT-ACTOR-03cf30aa129e',
  'verified',
  '俄罗斯 / FSB 第 16 中心',
  '2004',
  NULL,
  'MITRE ATT&CK 将 Turla 归因于俄罗斯联邦安全局；CISA 联合公告将 Snake 行动归因于 FSB 第 16 中心的已知单位。',
  '["网络间谍","长期驻留","情报收集"]',
  '["政府机构","使馆","军事部门","教育科研","制药企业"]',
  '["SRC-TUR-H4","SRC-TUR-H7","SRC-TUR-H11"]',
  '["https://attack.mitre.org/groups/G0010/","https://www.cisa.gov/sites/default/files/2023-05/aa23-129a_snake_malware_2.pdf"]',
  1.0,
  '2026-07-24T15:40:00+08:00'
),
(
  'ENT-ACTOR-5e9f20fdcf58',
  'verified',
  '朝鲜 / 侦察总局 RGB',
  '2009',
  NULL,
  'MITRE ATT&CK 将 Lazarus 描述为朝鲜国家支持、归属于侦察总局的威胁组，并提醒该名称常被作为多个朝鲜网络行动者的统称。',
  '["情报收集","破坏行动","金融获取"]',
  '["金融服务","加密货币行业","国防工业","软件供应链"]',
  '["SRC-LAZ-H12","SRC-LAZARUS-H15"]',
  '["https://attack.mitre.org/groups/G0032/","https://www.cisa.gov/news-events/analysis-reports/ar21-048e"]',
  1.0,
  '2026-07-24T15:40:00+08:00'
),
(
  'ENT-ACTOR-f9828932b6c7',
  'internal_cluster',
  '未确认',
  '2026',
  NULL,
  '内部待归并活动簇。现有证据只能支持远程认证和云凭据行为相似，不支持国家归属，也不能与 APT28 等已知组织等同。',
  '["待研判"]',
  '["云服务","企业邮箱"]',
  '["SRC-Z-H5","SRC-Z-H8"]',
  '[]',
  0.58,
  '2026-07-24T15:40:00+08:00'
);

INSERT OR REPLACE INTO algorithm_configs (
  id, algorithm_version, weights_json, description, created_at
) VALUES (
  'CFG-ATTR-REAL-001',
  'argus-rules-1.0.0',
  '{"entity":0.25,"technique":0.20,"path":0.35,"source":0.20,"negative_penalty":0.15}',
  '确定性图谱匹配：实体重合、ATT&CK 技术重合、同事件有向路径连续度和证据来源可靠性加权；negative 关系单独扣减。得分仅用于候选排序，不表示统计概率。',
  '2026-07-24T15:40:00+08:00'
);

INSERT OR REPLACE INTO response_rules (
  id, match_entity_type, priority, action_template, rationale, source_url
) VALUES
(
  'RULE-CVE-P0',
  'CVE',
  'P0',
  '核查受影响产品与版本，按厂商公告完成修复或缓解，并复核漏洞利用日志。',
  '漏洞实体只有在报告明确观察或官方来源确认时才触发此规则。',
  ''
),
(
  'RULE-IOC-P0',
  'IOC/基础设施',
  'P0',
  '在 DNS、代理、防火墙和终端遥测中检索该指标；确认恶意上下文后实施阻断，不对离线或共享基础设施直接自动封禁。',
  'IOC 稳定性有限，必须结合来源时间、关系方向和当前环境命中结果。',
  ''
),
(
  'RULE-TOOL-P1',
  '恶意软件/工具',
  'P1',
  '围绕工具进程、文件、配置和网络行为开展同源排查，并保留样本与内存证据。',
  '工具重合通常比单一 IOC 更稳定，但仍需攻击链上下文。',
  ''
),
(
  'RULE-TTP-P1',
  'ATT&CK 技术',
  'P1',
  '将已命中的 ATT&CK 技术映射到现有检测能力，补充缺失的日志源和关联规则。',
  'TTP 用于检测补强，不单独作为组织归因结论。',
  'https://attack.mitre.org/'
),
(
  'RULE-NEGATIVE-P1',
  '反证',
  'P1',
  '保留路径断点与反证，不得将部分行为相似升级为已确认组织归因。',
  'negative 关系在候选评分中单独扣减，并在报告中显式呈现。',
  ''
);

INSERT OR REPLACE INTO schema_migrations (version, name, applied_at)
VALUES (3, 'real_data_layer_and_reproducible_attribution', '2026-07-24T15:40:00+08:00');
