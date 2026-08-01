PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

UPDATE raw_reports
SET
  title = 'ARGUS 核心演示输入：Outlook 与 Exchange 关联告警包',
  extracted_text = '合成演示输入仅包含四条不完整遥测：可疑提醒属性、OUTLOOK.EXE 对外 TCP/445 成功连接、SMBClient 30800 事件，以及同一外部地址发起的 Exchange ReverseProxy NTLM 认证。输入不包含完整攻击路径、EWS 操作或邮箱权限变更记录。',
  assessment = '该输入用于验证从碎片化告警归一化、攻击路径补全、候选分支研判到后续行为预测的完整链路。补全与预测结果必须通过右侧证据缺口继续验证。'
WHERE id = 'RPT-CORE-DEMO-INPUT-23397';

UPDATE entities
SET properties_json = json_set(
  properties_json,
  '$.analysis_state', 'observed',
  '$.raw_signal', 'Calendar reminder item with external reminder file property',
  '$.verification_needed', '保留原始邮件与 MAPI 属性，确认该提醒项目确实进入目标邮箱。'
)
WHERE id = 'APT28-event-H2-step-0';

UPDATE entities
SET properties_json = json_set(
  properties_json,
  '$.analysis_state', 'observed',
  '$.raw_signal', 'PidLidReminderFileParameter=\\203.0.113.77\share\reminder.wav',
  '$.verification_needed', '核对消息属性原值、投递时间与目标邮箱，排除合法内部 UNC 资源。'
)
WHERE id = 'APT28-event-H2-step-1';

UPDATE entities
SET
  description = '输入中没有进程启动或用户点击记录。系统依据恶意提醒属性、OUTLOOK.EXE 后续外连和该漏洞无交互触发机制，补全 Outlook 自动处理环节。',
  properties_json = json_set(
    properties_json,
    '$.analysis_state', 'reconstructed',
    '$.inference_basis', '恶意提醒属性与 OUTLOOK.EXE 对外 SMB 连接在 2 秒内连续出现，且公开机制支持无交互触发。',
    '$.verification_needed', '调取 Outlook ETW、邮件项目 LastModificationTime 与进程网络关联，验证触发时间是否一致。'
  )
WHERE id = 'APT28-event-H2-step-2';

UPDATE entities
SET properties_json = json_set(
  properties_json,
  '$.analysis_state', 'observed',
  '$.raw_signal', 'OUTLOOK.EXE -> 203.0.113.77:445 ConnectionSuccess; SMBClient Event 30800',
  '$.verification_needed', '核对防火墙会话字节数和 SMB 协商包，确认连接并非仅发起后失败。'
)
WHERE id = 'APT28-event-H2-step-3';

UPDATE entities
SET
  description = '输入没有直接采集 Net-NTLMv2 响应内容。系统依据成功的外部 SMB 会话、SMBClient 事件和公开漏洞机制，补全协商材料泄露环节。',
  properties_json = json_set(
    properties_json,
    '$.analysis_state', 'reconstructed',
    '$.inference_basis', 'OUTLOOK.EXE 对外 TCP/445 成功连接与 NTLM 协商机制共同支持，但尚无原始流量直接证明响应已外泄。',
    '$.verification_needed', '提取对应时间窗 PCAP 或 NDR 会话，检查 NTLMSSP AUTH 消息与目标地址。'
  )
WHERE id = 'CORE-23397-step-4';

UPDATE entities
SET
  description = 'Exchange 反向代理记录同一外部地址使用受影响身份进行 NTLM 认证，和前序外连在时间与身份上形成关联，支持中继路径。',
  properties_json = json_set(
    properties_json,
    '$.analysis_state', 'observed',
    '$.raw_signal', 'AuthenticationType=NTLM User=finance-ops ClientIp=203.0.113.77',
    '$.verification_needed', '核对 IIS、HttpProxy 与身份审计的 CorrelationId，排除合法代理或同址登录。'
  )
WHERE id = 'CORE-23397-step-5';

UPDATE entities
SET
  first_seen = NULL,
  last_seen = NULL,
  description = '当前输入尚未观察到 EWS 操作。系统依据已出现的 Exchange NTLM 认证、公开历史活动和可用接口，预测攻击者可能首先枚举邮箱目录。',
  properties_json = json_set(
    properties_json,
    '$.analysis_state', 'predicted',
    '$.status', 'partial',
    '$.evidence_class', 'public-confirmed',
    '$.prediction_basis', '已取得 Exchange 认证会话，历史活动中 EWS FindFolder 是常见的紧随行为。',
    '$.prediction_horizon', '0-6 小时',
    '$.verification_needed', '监测 EWS FindFolder、GetFolder 与异常 User-Agent，并关联相同身份和 ClientIp。'
  )
WHERE id = 'CORE-23397-step-6';

UPDATE entities
SET
  first_seen = NULL,
  last_seen = NULL,
  description = '当前输入尚未观察到邮箱权限修改。系统依据公开历史活动与前序 Exchange 访问能力，预测攻击者可能修改 Default 权限维持访问。',
  properties_json = json_set(
    properties_json,
    '$.analysis_state', 'predicted',
    '$.status', 'partial',
    '$.evidence_class', 'public-confirmed',
    '$.prediction_basis', '公开历史活动确认攻击者曾在取得邮箱访问后修改文件夹权限。',
    '$.prediction_horizon', '6-24 小时',
    '$.verification_needed', '重点监测 UpdateFolder、Set-MailboxFolderPermission 与 Default=Owner 变更。'
  )
WHERE id = 'CORE-23397-step-7';

UPDATE entities
SET properties_json = json_set(
  properties_json,
  '$.analysis_state', 'candidate',
  '$.verification_needed', '查找离线破解迹象、密码复用和随后出现的成功交互式登录。'
)
WHERE id IN ('CORE-23397-branch-offline-crack', 'CORE-23397-branch-valid-account');

UPDATE entities
SET properties_json = json_set(properties_json, '$.analysis_state', 'blocked')
WHERE id IN (
  'CORE-23397-branch-smb-blocked',
  'CORE-23397-branch-webdav',
  'CORE-23397-branch-no-leak'
);

UPDATE entities
SET properties_json = json_set(
  properties_json,
  '$.analysis_state', 'predicted',
  '$.evidence_class', 'public-confirmed',
  '$.verification_needed', '查询 Exchange 邮箱审计，确认当前事件是否真的出现对应权限修改。'
)
WHERE id = 'CORE-23397-evidence-folder-owner';

UPDATE relationships
SET properties_json = json_set(properties_json, '$.analysis_state', 'reconstructed')
WHERE id IN ('REL-CORE-23397-MAIN-1-2', 'REL-CORE-23397-MAIN-3-4');

UPDATE relationships
SET properties_json = json_set(properties_json, '$.analysis_state', 'predicted')
WHERE id IN ('REL-CORE-23397-MAIN-5-6', 'REL-CORE-23397-MAIN-6-7');

UPDATE relationships
SET properties_json = json_set(properties_json, '$.analysis_state', 'candidate')
WHERE id IN ('REL-CORE-23397-BR-OFFLINE', 'REL-CORE-23397-BR-VALID');

INSERT OR REPLACE INTO evidence (
  id, relationship_id, report_id, job_id, excerpt, confidence, created_at,
  source_ref, location
) VALUES
(
  'EVD-CORE-23397-STEP5-6',
  'REL-CORE-23397-MAIN-5-6',
  'RPT-SEED-0479167078fc49d324',
  'ING-SEED-0479167078fc49d324',
  '公开历史活动表明，在取得 Exchange 认证能力后，攻击者可能使用 EWS 枚举邮箱目录；当前演示输入没有 FindFolder 日志，因此该步骤仅作为后续预测。',
  0.82,
  '2026-07-26T23:30:00+08:00',
  'SRC-A28-H2',
  'Credential access / EWS activity（预测依据）'
),
(
  'EVD-CORE-23397-STEP6-7-B',
  'REL-CORE-23397-MAIN-6-7',
  'RPT-CORE-POL-DKWOC-23397',
  'ING-CORE-POL-DKWOC-23397',
  '公开通报确认攻击者曾在邮箱访问后修改 Default 文件夹权限。当前演示输入没有 UpdateFolder 日志，因此该行为保留为 6-24 小时预测。',
  0.84,
  '2026-07-26T23:30:00+08:00',
  'SRC-POL-DKWOC-23397',
  'Description / mailbox folder permissions（预测依据）'
);

INSERT OR REPLACE INTO schema_migrations (version, name, applied_at)
VALUES (6, 'incomplete_path_reconstruction', '2026-07-26T23:30:00+08:00');

COMMIT;
