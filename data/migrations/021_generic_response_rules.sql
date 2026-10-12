PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

INSERT INTO response_rules (
  id, match_entity_type, priority, action_template, rationale, source_url,
  title, group_label, match_event
) VALUES
(
  'RULE-GENERIC-CONTAIN',
  '*',
  'P1',
  '核对当前环境中的进程、网络、账号与资产命中；确认恶意后隔离相关终端，并阻断已验证的恶意指标。',
  '优先阻断已观测环节，避免将补全或预测节点误当成已发生事实。',
  '',
  '复核并隔离已命中对象',
  '立即遏制',
  ''
),
(
  'RULE-GENERIC-PRESERVE',
  '*',
  'P1',
  '保留命中时间窗内的终端、网络、身份和应用日志，记录处置前的进程树、连接与登录状态。',
  '完整证据是确认攻击链范围和复核补全结果的前提。',
  '',
  '保全关键证据后再处置',
  '立即遏制',
  ''
),
(
  'RULE-GENERIC-HUNT',
  '*',
  'P2',
  '以已命中实体和时间窗为起点，向前检查初始访问，向后检查执行、持久化、横向移动与外传痕迹。',
  '利用攻击链上下文查找单个 IOC 检索容易遗漏的关联行为。',
  '',
  '围绕攻击链扩展狩猎',
  '排查狩猎',
  ''
),
(
  'RULE-GENERIC-SCOPE',
  '*',
  'P2',
  '按相同指标、工具、账号、目标资产和 ATT&CK 技术检索其他命中，建立受影响对象清单。',
  '攻击链可能横跨多台资产与多个身份，需要在处置前确定边界。',
  '',
  '确认受影响资产与身份范围',
  '排查狩猎',
  ''
),
(
  'RULE-GENERIC-ERADICATE',
  '*',
  'P2',
  '清除已确认的恶意文件、任务、服务和账号权限；轮换受影响凭据，并从可信基线恢复系统。',
  '恢复前同时处理恶意留存和凭据风险，降低攻击者重新进入的可能。',
  '',
  '清除恶意留存并恢复可信状态',
  '清除恢复',
  ''
),
(
  'RULE-GENERIC-HARDEN',
  '*',
  'P3',
  '为已确认步骤补充行为检测，为关键边界增加阻断控制，并用同类攻击链回放验证覆盖率。',
  '从单点 IOC 防护升级为对攻击行为和链路的持续检测。',
  '',
  '将攻击路径转化为检测与防护覆盖',
  '长期加固',
  ''
)
ON CONFLICT(id) DO UPDATE SET
  match_entity_type = excluded.match_entity_type,
  priority = excluded.priority,
  action_template = excluded.action_template,
  rationale = excluded.rationale,
  source_url = excluded.source_url,
  title = excluded.title,
  group_label = excluded.group_label,
  match_event = excluded.match_event;

INSERT OR REPLACE INTO schema_migrations (version, name, applied_at)
VALUES (
  21,
  'generic_configurable_response_rules',
  '2026-08-03T00:00:00+08:00'
);

COMMIT;
