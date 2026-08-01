PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

ALTER TABLE response_rules ADD COLUMN title TEXT NOT NULL DEFAULT '';
ALTER TABLE response_rules ADD COLUMN group_label TEXT NOT NULL DEFAULT '';
ALTER TABLE response_rules ADD COLUMN match_event TEXT NOT NULL DEFAULT '';

INSERT INTO raw_reports (
  id, title, source, report_date, classification, language,
  original_filename, mime_type, size_bytes, sha256, raw_blob,
  extracted_text, extraction_note, created_at, source_ref, reliability,
  external_url, assessment
) VALUES
(
  'RPT-CORE-MS-MSRC-23397',
  'Microsoft Mitigates Outlook Elevation of Privilege Vulnerability',
  'Microsoft Security Response Center',
  '2023-03-14',
  '公开来源',
  'English',
  NULL,
  'text/html',
  0,
  'fd92a881a8b7ad547ad3e57746ee96ab35fac86b22c24a4eea04ec547d631ac8',
  NULL,
  'ARGUS 结构化摘要：Windows 版 Outlook 在处理包含外部 UNC 路径的 PidLidReminderFileParameter 扩展 MAPI 属性时，可在无需用户交互的情况下向攻击者控制的 SMB 服务发起 NTLM 协商。微软要求安装 Outlook 安全更新，Exchange 更新不能替代客户端修复。',
  '基于 MSRC 官方页面人工提炼；非原文转载。',
  '2026-07-26T22:00:00+08:00',
  'SRC-MS-MSRC-23397',
  '官方厂商公告',
  'https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/',
  '该来源确认漏洞触发条件、无需用户交互、受影响产品边界以及 Outlook 客户端更新要求。'
),
(
  'RPT-CORE-POL-DKWOC-23397',
  'Detecting malicious activity against Microsoft Exchange servers',
  'Polish Cyber Command',
  '2023-12-04',
  '公开来源',
  'English',
  NULL,
  'text/html',
  0,
  '9846da099454de720412c307f72a9ec5ff540d87ffdc6b0802ad531baa36ce9b',
  NULL,
  'ARGUS 结构化摘要：波兰网络司令部确认攻击者在通过 CVE-2023-23397 或密码喷洒获得邮箱访问后，修改邮箱文件夹权限，将 Default 权限提升为 Owner，以维持对邮件内容的隐蔽访问。其公开评估将相关活动与 APT28 / Forest Blizzard 行动重叠关联。',
  '基于波兰网络司令部公开页面人工提炼；非原文转载。',
  '2026-07-26T22:00:00+08:00',
  'SRC-POL-DKWOC-23397',
  '政府机构公开通报',
  'https://www.wojsko-polskie.pl/woc/articles/aktualnosci-w/detecting-malicious-activity-against-microsoft-exchange-servers/',
  '该来源支持 Exchange 邮箱权限持久化节点及其与 CVE-2023-23397 后续活动的关联。'
),
(
  'RPT-CORE-MS-CSS-23397',
  'CVE-2023-23397 script',
  'Microsoft CSS-Exchange',
  '2023-03-24',
  '公开来源',
  'English',
  NULL,
  'text/html',
  0,
  '8beb1a5572425b3529111f861a27fee974fd2b94c8201456034727eb8ace3d5a',
  NULL,
  'ARGUS 结构化摘要：微软官方 CVE-2023-23397 PowerShell 脚本可在 Exchange Online 或本地 Exchange 中审计邮件、日历与任务项目的可疑提醒属性，并支持清除恶意属性或删除恶意项目。脚本输出仍需管理员判断。',
  '基于 Microsoft CSS-Exchange 官方文档人工提炼；非脚本内容转载。',
  '2026-07-26T22:00:00+08:00',
  'SRC-MS-CSS-23397',
  '官方运维工具文档',
  'https://microsoft.github.io/CSS-Exchange/Security/CVE-2023-23397/',
  '该来源支持邮箱范围审计、恶意项目清理和批量排查建议。'
),
(
  'RPT-CORE-DEMO-INPUT-23397',
  'ARGUS 核心演示输入：CVE-2023-23397 关联告警包',
  'ARGUS Competition Scenario',
  '2023-11-21',
  '演示输入 / 非公开情报',
  'Chinese / English',
  'cve-2023-23397-core-incident.json',
  'application/json',
  0,
  'b4c1f8992dbac8d5549c84c73fbcd63b55c0d22448546f7ad761ef426c1dd8f0',
  NULL,
  '合成演示输入包含邮件扩展属性、Outlook 对外 SMB 连接、NTLM-Challenge 网络签名、Exchange 反向代理 NTLM 认证、EWS FindFolder 与 UpdateFolder 行为。资产名、邮箱和 RFC 5737 地址均为演示数据。',
  '比赛演示用合成遥测，不代表真实受害者或公开 IOC；知识关联仅来自公开来源。',
  '2026-07-26T22:00:00+08:00',
  'SRC-DEMO-INPUT-23397',
  '演示输入',
  '',
  '该输入用于验证从告警解析到路径还原、分支研判、证据回溯与处置建议的完整链路。'
)
ON CONFLICT(id) DO UPDATE SET
  title = excluded.title,
  source = excluded.source,
  report_date = excluded.report_date,
  classification = excluded.classification,
  language = excluded.language,
  original_filename = excluded.original_filename,
  mime_type = excluded.mime_type,
  sha256 = excluded.sha256,
  extracted_text = excluded.extracted_text,
  extraction_note = excluded.extraction_note,
  source_ref = excluded.source_ref,
  reliability = excluded.reliability,
  external_url = excluded.external_url,
  assessment = excluded.assessment;

INSERT INTO import_jobs (
  id, report_id, title, status, stage, entity_count, relation_count,
  published_entity_count, published_relation_count, created_at, updated_at,
  published_at
) VALUES
(
  'ING-CORE-MS-MSRC-23397',
  'RPT-CORE-MS-MSRC-23397',
  'MSRC CVE-2023-23397 漏洞机制',
  '已发布',
  'published',
  4,
  5,
  4,
  5,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00'
),
(
  'ING-CORE-POL-DKWOC-23397',
  'RPT-CORE-POL-DKWOC-23397',
  '波兰网络司令部 Exchange 后渗透活动',
  '已发布',
  'published',
  4,
  5,
  4,
  5,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00'
),
(
  'ING-CORE-MS-CSS-23397',
  'RPT-CORE-MS-CSS-23397',
  'Microsoft CSS-Exchange 审计与清理脚本',
  '已发布',
  'published',
  2,
  3,
  2,
  3,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00'
),
(
  'ING-CORE-DEMO-INPUT-23397',
  'RPT-CORE-DEMO-INPUT-23397',
  'ARGUS 核心演示告警包',
  '已发布',
  'published',
  12,
  12,
  12,
  12,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00'
)
ON CONFLICT(id) DO UPDATE SET
  title = excluded.title,
  status = excluded.status,
  stage = excluded.stage,
  entity_count = excluded.entity_count,
  relation_count = excluded.relation_count,
  published_entity_count = excluded.published_entity_count,
  published_relation_count = excluded.published_relation_count,
  updated_at = excluded.updated_at,
  published_at = excluded.published_at;

UPDATE entities
SET
  label = '核心案例：Outlook NTLM 凭据窃取',
  normalized_value = '核心案例 outlook ntlm 凭据窃取 exchange 持久化',
  description = '核心演示案例聚合微软与波兰网络司令部公开材料，并用明确标注的合成 SOC 遥测还原从恶意 Outlook 提醒到 Exchange 邮箱权限持久化的调查路径。',
  first_seen = '2022-04-01',
  last_seen = '2023-12-04',
  source_count = 4,
  properties_json = '{"ui_type":"event","sub":"核心演示案例","actor":"APT28","event":"H2","legacy_id":"APT28-event-H2","categories":["chain","technique","detection","response"],"confidence":0.94,"status":"hot","source_ref":"SRC-A28-H2","evidence_class":"public-confirmed","demo_case":"CVE-2023-23397"}',
  seed_origin = 'migration-005-core-demo',
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE id = 'APT28-event-H2';

UPDATE entities
SET
  canonical_key = '攻击步骤:core23397:恶意提醒消息投递',
  label = '恶意提醒消息投递',
  normalized_value = '恶意提醒消息投递 tnef calendar reminder',
  description = '攻击者向目标邮箱投递带提醒的特制 TNEF 邮件、日历或任务项目。邮件正文不需要包含显眼恶意链接。',
  first_seen = '2022-04-01',
  last_seen = '2023-11-21',
  source_count = 2,
  properties_json = '{"ui_type":"evidence","sub":"H2 · 第 1 步","actor":"APT28","event":"H2","entity_value":"TNEF calendar reminder","categories":["chain"],"confidence":0.95,"status":"hot","evidence_class":"public-confirmed","phase":"初始访问"}',
  seed_origin = 'migration-005-core-demo',
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE id = 'APT28-event-H2-step-0';

UPDATE entities
SET
  canonical_key = '攻击步骤:core23397:外部unc路径植入',
  label = '外部 UNC 路径植入',
  normalized_value = '外部 unc 路径植入 pidlidreminderfileparameter',
  description = '特制项目的 PidLidReminderFileParameter 扩展 MAPI 属性指向攻击者控制的外部 UNC 共享。',
  first_seen = '2022-04-01',
  last_seen = '2023-11-21',
  source_count = 2,
  properties_json = '{"ui_type":"evidence","sub":"H2 · 第 2 步","actor":"APT28","event":"H2","entity_value":"PidLidReminderFileParameter=\\\\\\\\203.0.113.77\\\\share\\\\reminder.wav","categories":["chain"],"confidence":0.96,"status":"hot","evidence_class":"public-confirmed","phase":"触发准备"}',
  seed_origin = 'migration-005-core-demo',
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE id = 'APT28-event-H2-step-1';

UPDATE entities
SET
  canonical_key = '攻击步骤:core23397:outlook无交互触发',
  label = 'Outlook 无交互触发',
  normalized_value = 'outlook 无交互触发 reminder',
  description = 'Windows 版 Outlook 在提醒触发时处理远程路径，无需用户打开或点击消息即可启动外连。',
  first_seen = '2022-04-01',
  last_seen = '2023-11-21',
  source_count = 2,
  properties_json = '{"ui_type":"tool","sub":"H2 · 第 3 步","actor":"APT28","event":"H2","entity_value":"OUTLOOK.EXE","categories":["chain"],"confidence":0.95,"status":"hot","evidence_class":"public-confirmed","phase":"执行"}',
  seed_origin = 'migration-005-core-demo',
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE id = 'APT28-event-H2-step-2';

UPDATE entities
SET
  canonical_key = '攻击步骤:core23397:对外smb445认证',
  label = '对外 SMB 445 认证',
  normalized_value = '对外 smb 445 认证 ntlm challenge',
  description = '演示输入显示 OUTLOOK.EXE 向 RFC 5737 外部地址的 TCP/445 连接并出现 NTLM-Challenge 网络签名。',
  first_seen = '2023-11-21T09:14:22Z',
  last_seen = '2023-11-21T09:14:24Z',
  source_count = 2,
  properties_json = '{"ui_type":"tool","sub":"H2 · 第 4 步","actor":"APT28","event":"H2","entity_value":"203.0.113.77:445 / SMB","categories":["chain"],"confidence":0.93,"status":"hot","evidence_class":"demo-observed","phase":"凭据访问"}',
  seed_origin = 'migration-005-core-demo',
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE id = 'APT28-event-H2-step-3';

INSERT INTO entities (
  id, entity_type, canonical_key, label, normalized_value, description,
  first_seen, last_seen, source_count, created_at, updated_at,
  properties_json, seed_origin
) VALUES
(
  'CORE-23397-step-4',
  '攻击步骤',
  '攻击步骤:core23397:net-ntlmv2材料泄露',
  'Net-NTLMv2 材料泄露',
  'net-ntlmv2 材料泄露 challenge response',
  '公开机制表明对外 SMB 协商会发送 Net-NTLMv2 挑战响应；演示输入中的成功连接与 NTLM-Challenge 签名共同提高了泄露判断强度。',
  '2023-11-21T09:14:22Z',
  '2023-11-21T09:14:22Z',
  3,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"result","sub":"H2 · 第 5 步","actor":"APT28","event":"H2","entity_value":"Net-NTLMv2 challenge-response","categories":["chain"],"confidence":0.91,"status":"hot","evidence_class":"correlated","phase":"凭据访问"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-step-5',
  '攻击步骤',
  '攻击步骤:core23397:ntlm中继至exchange',
  'NTLM 中继至 Exchange',
  'ntlm 中继 exchange reverse proxy',
  '公开调查指南描述了将泄露的 Net-NTLMv2 协商中继至 Exchange 的初始访问场景；演示反向代理日志记录了外部来源的 NTLM 认证。',
  '2023-11-21T09:15:08Z',
  '2023-11-21T09:15:08Z',
  3,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"result","sub":"H2 · 第 6 步","actor":"APT28","event":"H2","entity_value":"Exchange NTLM relay","categories":["chain"],"confidence":0.88,"status":"hot","evidence_class":"correlated","phase":"初始访问"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-step-6',
  '攻击步骤',
  '攻击步骤:core23397:ews邮箱访问',
  'EWS 邮箱访问',
  'ews 邮箱访问 findfolder',
  '演示 EWS 日志记录受影响身份执行 FindFolder；公开报告指出攻击者可利用 EWS 枚举邮箱并继续投递恶意提醒。',
  '2023-11-21T09:17:41Z',
  '2023-11-21T09:17:41Z',
  3,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"tool","sub":"H2 · 第 7 步","actor":"APT28","event":"H2","entity_value":"EWS FindFolder","categories":["chain"],"confidence":0.9,"status":"hot","evidence_class":"correlated","phase":"发现"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-step-7',
  '攻击步骤',
  '攻击步骤:core23397:邮箱权限持久化',
  '邮箱权限持久化',
  '邮箱权限持久化 updatefolder default owner',
  '波兰网络司令部公开确认攻击者会将邮箱文件夹 Default 权限修改为 Owner；演示 EWS 日志包含对应 UpdateFolder 行为。',
  '2023-11-21T09:19:03Z',
  '2023-11-21T09:19:03Z',
  3,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"result","sub":"H2 · 第 8 步","actor":"APT28","event":"H2","entity_value":"UpdateFolder Default=Owner","categories":["chain"],"confidence":0.92,"status":"hot","evidence_class":"demo-observed","phase":"持久化"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-branch-offline-crack',
  '攻击步骤',
  '攻击步骤:core23397:离线口令破解',
  '离线口令破解',
  '离线口令破解 net-ntlmv2',
  '微软说明泄露的 Net-NTLMv2 材料可能被离线破解以恢复口令；核心演示没有观察到破解成功证据。',
  NULL,
  NULL,
  1,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"tool","sub":"候选分支 · 凭据破解","actor":"APT28","event":"H2","entity_value":"offline password cracking","categories":["chain"],"confidence":0.64,"status":"partial","evidence_class":"inference","phase":"凭据访问"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-branch-valid-account',
  '攻击步骤',
  '攻击步骤:core23397:有效账户访问',
  '有效账户访问',
  '有效账户访问 valid account',
  '仅当离线破解或密码复用得到进一步身份日志支持时，才能将该分支升级为已确认。',
  NULL,
  NULL,
  1,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"result","sub":"候选分支 · 账户使用","actor":"APT28","event":"H2","entity_value":"valid account access","categories":["chain"],"confidence":0.55,"status":"partial","evidence_class":"inference","phase":"初始访问"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-branch-smb-blocked',
  '攻击步骤',
  '攻击步骤:core23397:smb出口被阻断',
  'SMB 出口被阻断',
  'smb 出口被阻断 firewall tcp 445',
  '当边界策略阻断对外 TCP/445 时，SMBClient 失败事件只能证明外连尝试，不能证明凭据已经泄露。',
  NULL,
  NULL,
  2,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"evidence","sub":"阻断分支 · 边界控制","event":"H2","entity_value":"Block outbound TCP/445","categories":["chain"],"confidence":0.96,"status":"negative","evidence_class":"blocked","phase":"防御阻断"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-branch-webdav',
  '攻击步骤',
  '攻击步骤:core23397:webdav回退尝试',
  'WebDAV 回退尝试',
  'webdav 回退尝试 rundll32 davclnt',
  '微软指出 SMB 失败后 Windows 可能回退到 WebDAV，并产生可狩猎的进程事件。',
  NULL,
  NULL,
  1,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"tool","sub":"阻断分支 · 回退行为","event":"H2","entity_value":"WebDAV process creation","categories":["chain"],"confidence":0.84,"status":"negative","evidence_class":"blocked","phase":"执行"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-branch-no-leak',
  '攻击步骤',
  '攻击步骤:core23397:未证明凭据泄露',
  '未证明凭据泄露',
  '未证明凭据泄露 webdav',
  'WebDAV 回退和 SMBClient 错误事件本身不能确认凭据泄露，应保留为阻断结果而不是攻击成功。',
  NULL,
  NULL,
  2,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"result","sub":"阻断分支 · 反证结论","event":"H2","entity_value":"credential leak not confirmed","categories":["chain"],"confidence":0.95,"status":"negative","evidence_class":"blocked","phase":"研判结论"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-branch-ews-propagate',
  '攻击步骤',
  '攻击步骤:core23397:ews继续投递',
  'EWS 继续投递恶意提醒',
  'ews 继续投递恶意提醒',
  '微软应急调查指南描述攻击者使用 EWS 向组织内外其他用户发送带恶意提醒属性的消息。',
  NULL,
  NULL,
  2,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"tool","sub":"扩散分支 · 邮箱投递","actor":"APT28","event":"H2","entity_value":"EWS CreateItem malicious reminder","categories":["chain"],"confidence":0.86,"status":"positive","evidence_class":"public-confirmed","phase":"横向移动"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-cve',
  'CVE',
  'CVE:cve-2023-23397',
  'CVE-2023-23397',
  'cve-2023-23397',
  'Windows 版 Outlook 关键特权提升漏洞，可通过恶意提醒属性触发对外 NTLM 认证，无需用户交互。',
  '2023-03-14',
  '2023-05-09',
  4,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"evidence","sub":"Microsoft Outlook for Windows","entity_value":"CVE-2023-23397","categories":["chain","response"],"confidence":0.99,"status":"hot","evidence_class":"public-confirmed","cvss":"9.8"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-evidence-mapi',
  '检测证据',
  '检测证据:core23397:pidlidreminderfileparameter',
  'PidLidReminderFileParameter',
  'pidlidreminderfileparameter external unc internetzone',
  '邮件、日历或任务项目中的关键扩展 MAPI 属性；指向 InternetZone 的外部服务器时应视为恶意。',
  '2023-11-21T09:14:20Z',
  '2023-11-21T09:14:20Z',
  3,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"evidence","sub":"邮件扩展属性","entity_value":"\\\\\\\\203.0.113.77\\\\share\\\\reminder.wav","categories":["detection"],"confidence":0.98,"status":"hot","evidence_class":"demo-observed"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-evidence-tnef',
  '检测证据',
  '检测证据:core23397:tnef',
  'TNEF / Winmail.dat',
  'tnef winmail.dat reminder mapi',
  '微软说明特制提醒属性通过 TNEF 传输，可存在于邮件、会议请求或任务项目中。',
  NULL,
  NULL,
  2,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"evidence","sub":"消息封装格式","entity_value":"TNEF","categories":["detection"],"confidence":0.94,"status":"positive","evidence_class":"public-confirmed"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-evidence-smbclient',
  '检测证据',
  '检测证据:core23397:smbclient-event',
  'SMBClient Event ID 30800',
  'smbclient connectivity 30800 servername',
  'SMBClient Connectivity 事件可显示对不受信任服务器的失败外连，但不能单独证明凭据泄露。',
  '2023-11-21T09:14:24Z',
  '2023-11-21T09:14:24Z',
  2,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"evidence","sub":"Windows 事件日志","entity_value":"Microsoft-Windows-SMBClient/Connectivity 30800","categories":["detection"],"confidence":0.78,"status":"partial","evidence_class":"demo-observed"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-evidence-firewall',
  '检测证据',
  '检测证据:core23397:firewall-445',
  '边界防火墙 TCP/445',
  '边界防火墙 tcp 445 outbound public ip',
  '用于确认外部 SMB 是否成功、被阻断以及远程端点；需与 NTLM 网络签名和身份日志关联。',
  '2023-11-21T09:14:22Z',
  '2023-11-21T09:14:22Z',
  2,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"evidence","sub":"网络边界遥测","entity_value":"RemotePort=445 Action=ConnectionSuccess","categories":["detection"],"confidence":0.9,"status":"hot","evidence_class":"demo-observed"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-evidence-ews-auth',
  '检测证据',
  '检测证据:core23397:ews-ntlm-auth',
  'EWS AuthenticationType=NTLM',
  'ews authenticationtype ntlm clientip authenticateduser',
  'Exchange EWS 与反向代理日志可用于识别外部来源的 NTLM 中继认证，并按客户端 IP 和用户聚合。',
  '2023-11-21T09:15:08Z',
  '2023-11-21T09:17:41Z',
  3,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"evidence","sub":"Exchange 认证日志","entity_value":"AuthenticationType=NTLM ClientIp=203.0.113.77","categories":["detection"],"confidence":0.91,"status":"hot","evidence_class":"demo-observed"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-evidence-folder-owner',
  '检测证据',
  '检测证据:core23397:updatefolder-owner',
  'UpdateFolder Default=Owner',
  'updatefolder default owner mailbox permission',
  'EWS UpdateFolder 操作将 Inbox 的 Default 权限改为 Owner，与公开披露的邮箱权限持久化方式一致。',
  '2023-11-21T09:19:03Z',
  '2023-11-21T09:19:03Z',
  3,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"evidence","sub":"Exchange 邮箱审计","entity_value":"UpdateFolder Inbox Default Owner","categories":["detection"],"confidence":0.95,"status":"hot","evidence_class":"demo-observed"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-evidence-webdav',
  '检测证据',
  '检测证据:core23397:webdav-process',
  'WebDAV 进程回退证据',
  'webdav rundll32 davclnt.dll process creation',
  'SMB 失败时可能出现 WebDAV 回退进程；该证据说明触发尝试，但微软明确指出其不能确认凭据泄露。',
  NULL,
  NULL,
  2,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"evidence","sub":"端点进程证据","entity_value":"rundll32.exe davclnt.dll","categories":["detection"],"confidence":0.82,"status":"negative","evidence_class":"blocked"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-asset-workstation',
  '资产',
  '资产:core23397:ws-fin-023',
  'WS-FIN-023',
  'ws-fin-023 outlook workstation',
  '核心演示输入中的 Windows Outlook 工作站；名称为合成资产标识。',
  '2023-11-21T09:14:20Z',
  '2023-11-21T09:14:24Z',
  1,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"asset","sub":"演示输入资产","entity_value":"WS-FIN-023","categories":["asset"],"confidence":1.0,"status":"hot","evidence_class":"demo-observed","origin":"synthetic-input"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-asset-exchange',
  '资产',
  '资产:core23397:exch-01',
  'EXCH-01',
  'exch-01 on-premises exchange',
  '核心演示输入中的本地 Exchange 服务器；名称为合成资产标识。',
  '2023-11-21T09:15:08Z',
  '2023-11-21T09:19:03Z',
  1,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"asset","sub":"演示输入资产","entity_value":"EXCH-01","categories":["asset"],"confidence":1.0,"status":"hot","evidence_class":"demo-observed","origin":"synthetic-input"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-identity-mailbox',
  '身份',
  '身份:core23397:finance-ops-example',
  'finance-ops@example.org',
  'finance-ops@example.org target mailbox',
  '核心演示输入中的目标邮箱；example.org 为保留示例域名。',
  '2023-11-21T09:14:20Z',
  '2023-11-21T09:19:03Z',
  1,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"identity","sub":"演示输入身份","entity_value":"finance-ops@example.org","categories":["identity"],"confidence":1.0,"status":"hot","evidence_class":"demo-observed","origin":"synthetic-input"}',
  'migration-005-core-demo'
),
(
  'CORE-23397-ioc-demo-smb',
  'IOC/基础设施',
  'IOC/基础设施:core23397:203.0.113.77',
  '203.0.113.77',
  '203.0.113.77',
  'RFC 5737 文档地址，仅代表从核心演示输入解析出的外部 SMB 端点，不是公开恶意 IOC。',
  '2023-11-21T09:14:22Z',
  '2023-11-21T09:15:08Z',
  1,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"evidence","sub":"演示输入外部端点","entity_value":"203.0.113.77:445","categories":["infrastructure"],"confidence":1.0,"status":"partial","evidence_class":"demo-observed","origin":"synthetic-input","not_public_ioc":true}',
  'migration-005-core-demo'
),
(
  'APT28-tech-t1557-001',
  'ATT&CK 技术',
  'ATT&CK 技术:apt28:t1557-001',
  'T1557.001',
  't1557.001 smb relay',
  'LLMNR/NBT-NS Poisoning and SMB Relay；用于表达 NTLM 中继行为，不单独构成组织归因。',
  NULL,
  NULL,
  2,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"tool","sub":"SMB Relay","actor":"APT28","event":"H2","entity_value":"T1557.001","categories":["technique"],"confidence":0.9,"status":"positive","evidence_class":"public-confirmed"}',
  'migration-005-core-demo'
),
(
  'APT28-tech-t1110-002',
  'ATT&CK 技术',
  'ATT&CK 技术:apt28:t1110-002',
  'T1110.002',
  't1110.002 password cracking',
  'Password Cracking；对应离线破解候选分支，当前核心演示没有确认该行为实际发生。',
  NULL,
  NULL,
  1,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"tool","sub":"Password Cracking","actor":"APT28","event":"H2","entity_value":"T1110.002","categories":["technique"],"confidence":0.65,"status":"partial","evidence_class":"inference"}',
  'migration-005-core-demo'
),
(
  'APT28-tech-t1098-002',
  'ATT&CK 技术',
  'ATT&CK 技术:apt28:t1098-002',
  'T1098.002',
  't1098.002 additional email delegate permissions',
  'Additional Email Delegate Permissions；对应公开披露的邮箱文件夹权限持久化行为。',
  NULL,
  NULL,
  2,
  '2026-07-26T22:00:00+08:00',
  '2026-07-26T22:00:00+08:00',
  '{"ui_type":"tool","sub":"Additional Email Delegate Permissions","actor":"APT28","event":"H2","entity_value":"T1098.002","categories":["technique"],"confidence":0.94,"status":"positive","evidence_class":"public-confirmed"}',
  'migration-005-core-demo'
)
ON CONFLICT(id) DO UPDATE SET
  entity_type = excluded.entity_type,
  canonical_key = excluded.canonical_key,
  label = excluded.label,
  normalized_value = excluded.normalized_value,
  description = excluded.description,
  first_seen = excluded.first_seen,
  last_seen = excluded.last_seen,
  source_count = excluded.source_count,
  properties_json = excluded.properties_json,
  seed_origin = excluded.seed_origin,
  updated_at = excluded.updated_at;

UPDATE relationships
SET
  relation_type = '起始步骤',
  canonical_key = 'core23397:event>step0',
  confidence = 0.95,
  evidence_count = 2,
  status = 'hot',
  properties_json = '{"sequence":0,"evidence_class":"public-confirmed"}',
  seed_origin = 'migration-005-core-demo',
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE id = 'REL-SEED-25b783a4437cd1d407';

UPDATE relationships
SET
  relation_type = '植入恶意属性',
  canonical_key = 'core23397:step0>step1',
  confidence = 0.96,
  evidence_count = 2,
  status = 'hot',
  properties_json = '{"sequence":1,"evidence_class":"public-confirmed"}',
  seed_origin = 'migration-005-core-demo',
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE id = 'REL-SEED-e8fcc05a46e831a4a3';

UPDATE relationships
SET
  relation_type = '提醒到期触发',
  canonical_key = 'core23397:step1>step2',
  confidence = 0.95,
  evidence_count = 2,
  status = 'hot',
  properties_json = '{"sequence":2,"evidence_class":"public-confirmed","user_interaction":false}',
  seed_origin = 'migration-005-core-demo',
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE id = 'REL-SEED-2753b52ad848acf9e4';

UPDATE relationships
SET
  relation_type = '自动发起认证',
  canonical_key = 'core23397:step2>step3',
  confidence = 0.94,
  evidence_count = 3,
  status = 'hot',
  properties_json = '{"sequence":3,"evidence_class":"correlated","port":445}',
  seed_origin = 'migration-005-core-demo',
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE id = 'REL-SEED-76f6f0c25f418ddc02';

UPDATE relationships
SET
  source_entity_id = 'APT28-event-H2-step-3',
  target_entity_id = 'CORE-23397-ioc-demo-smb',
  relation_type = '演示输入端点',
  canonical_key = 'core23397:step3>demo-ioc',
  confidence = 1.0,
  evidence_count = 1,
  status = 'partial',
  properties_json = '{"evidence_class":"demo-observed","not_public_ioc":true}',
  seed_origin = 'migration-005-core-demo',
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE id = 'REL-SEED-6a58461ef8c6b1ca22';

UPDATE relationships
SET
  source_entity_id = 'APT28-event-H2-step-3',
  relation_type = '映射技术',
  canonical_key = 'core23397:step3>t1187',
  confidence = 0.95,
  evidence_count = 2,
  status = 'positive',
  properties_json = '{"evidence_class":"public-confirmed"}',
  seed_origin = 'migration-005-core-demo',
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE id = 'REL-SEED-1b8462fbbadae3278f';

UPDATE relationships
SET
  confidence = 0.94,
  evidence_count = 2,
  status = 'hot',
  properties_json = '{"evidence_class":"public-attribution","source_scope":"Microsoft and Polish Cyber Command"}',
  seed_origin = 'migration-005-core-demo',
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE id = 'REL-SEED-4c69f753ca723017e0';

INSERT INTO relationships (
  id, source_entity_id, target_entity_id, relation_type, canonical_key,
  confidence, evidence_count, first_seen, last_seen, created_at, updated_at,
  category, status, properties_json, seed_origin
) VALUES
('REL-CORE-23397-MAIN-3-4','APT28-event-H2-step-3','CORE-23397-step-4','泄露协商材料','core23397:step3>step4',0.91,3,'2023-11-21T09:14:22Z','2023-11-21T09:14:22Z','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','chain','hot','{"sequence":4,"evidence_class":"correlated"}','migration-005-core-demo'),
('REL-CORE-23397-MAIN-4-5','CORE-23397-step-4','CORE-23397-step-5','中继认证','core23397:step4>step5',0.88,3,'2023-11-21T09:15:08Z','2023-11-21T09:15:08Z','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','chain','hot','{"sequence":5,"evidence_class":"correlated"}','migration-005-core-demo'),
('REL-CORE-23397-MAIN-5-6','CORE-23397-step-5','CORE-23397-step-6','建立 EWS 会话','core23397:step5>step6',0.9,3,'2023-11-21T09:17:41Z','2023-11-21T09:17:41Z','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','chain','hot','{"sequence":6,"evidence_class":"correlated"}','migration-005-core-demo'),
('REL-CORE-23397-MAIN-6-7','CORE-23397-step-6','CORE-23397-step-7','修改文件夹权限','core23397:step6>step7',0.92,3,'2023-11-21T09:19:03Z','2023-11-21T09:19:03Z','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','chain','hot','{"sequence":7,"evidence_class":"public-confirmed"}','migration-005-core-demo'),
('REL-CORE-23397-BR-OFFLINE','CORE-23397-step-4','CORE-23397-branch-offline-crack','可能离线破解','core23397:step4>offline-crack',0.64,1,NULL,NULL,'2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','chain','partial','{"branch":"credential-cracking","evidence_class":"inference"}','migration-005-core-demo'),
('REL-CORE-23397-BR-VALID','CORE-23397-branch-offline-crack','CORE-23397-branch-valid-account','候选账户访问','core23397:offline-crack>valid-account',0.55,1,NULL,NULL,'2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','chain','partial','{"branch":"credential-cracking","evidence_class":"inference"}','migration-005-core-demo'),
('REL-CORE-23397-BR-BLOCK','APT28-event-H2-step-3','CORE-23397-branch-smb-blocked','被边界策略阻断','core23397:step3>smb-blocked',0.96,2,NULL,NULL,'2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','chain','negative','{"branch":"blocked-counterfactual","evidence_class":"blocked"}','migration-005-core-demo'),
('REL-CORE-23397-BR-WEBDAV','CORE-23397-branch-smb-blocked','CORE-23397-branch-webdav','回退 WebDAV','core23397:smb-blocked>webdav',0.84,1,NULL,NULL,'2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','chain','negative','{"branch":"blocked-counterfactual","evidence_class":"blocked"}','migration-005-core-demo'),
('REL-CORE-23397-BR-NOLEAK','CORE-23397-branch-webdav','CORE-23397-branch-no-leak','不足以证明泄露','core23397:webdav>no-leak',0.95,2,NULL,NULL,'2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','chain','negative','{"branch":"blocked-counterfactual","evidence_class":"blocked"}','migration-005-core-demo'),
('REL-CORE-23397-BR-PROPAGATE','CORE-23397-step-6','CORE-23397-branch-ews-propagate','继续投递恶意项目','core23397:step6>ews-propagate',0.86,2,NULL,NULL,'2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','chain','positive','{"branch":"mailbox-propagation","evidence_class":"public-confirmed"}','migration-005-core-demo'),
('REL-CORE-23397-EVENT-CVE','APT28-event-H2','CORE-23397-cve','利用漏洞','core23397:event>cve',0.98,3,'2022-04-01','2023-12-04','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','chain','hot','{"evidence_class":"public-confirmed"}','migration-005-core-demo'),
('REL-CORE-23397-STEP0-TNEF','APT28-event-H2-step-0','CORE-23397-evidence-tnef','消息封装','core23397:step0>tnef',0.94,2,NULL,NULL,'2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','detection','positive','{"evidence_class":"public-confirmed"}','migration-005-core-demo'),
('REL-CORE-23397-STEP1-MAPI','APT28-event-H2-step-1','CORE-23397-evidence-mapi','关键属性','core23397:step1>mapi',0.98,3,'2023-11-21T09:14:20Z','2023-11-21T09:14:20Z','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','detection','hot','{"evidence_class":"demo-observed"}','migration-005-core-demo'),
('REL-CORE-23397-STEP2-ASSET','APT28-event-H2-step-2','CORE-23397-asset-workstation','发生于','core23397:step2>workstation',1.0,1,'2023-11-21T09:14:22Z','2023-11-21T09:14:22Z','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','asset','hot','{"evidence_class":"demo-observed"}','migration-005-core-demo'),
('REL-CORE-23397-STEP3-SMBLOG','APT28-event-H2-step-3','CORE-23397-evidence-smbclient','产生事件','core23397:step3>smbclient-log',0.78,2,'2023-11-21T09:14:24Z','2023-11-21T09:14:24Z','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','detection','partial','{"evidence_class":"demo-observed","limitation":"cannot prove leak alone"}','migration-005-core-demo'),
('REL-CORE-23397-STEP3-FWLOG','APT28-event-H2-step-3','CORE-23397-evidence-firewall','边界连接证据','core23397:step3>firewall-log',0.9,2,'2023-11-21T09:14:22Z','2023-11-21T09:14:22Z','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','detection','hot','{"evidence_class":"demo-observed"}','migration-005-core-demo'),
('REL-CORE-23397-STEP3-IDENTITY','APT28-event-H2-step-3','CORE-23397-identity-mailbox','使用身份','core23397:step3>identity',0.92,1,'2023-11-21T09:14:22Z','2023-11-21T09:14:22Z','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','identity','hot','{"evidence_class":"demo-observed"}','migration-005-core-demo'),
('REL-CORE-23397-STEP5-EXCHANGE','CORE-23397-step-5','CORE-23397-asset-exchange','中继目标','core23397:step5>exchange',0.91,2,'2023-11-21T09:15:08Z','2023-11-21T09:15:08Z','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','asset','hot','{"evidence_class":"correlated"}','migration-005-core-demo'),
('REL-CORE-23397-STEP5-EWSAUTH','CORE-23397-step-5','CORE-23397-evidence-ews-auth','认证日志证据','core23397:step5>ews-auth',0.91,3,'2023-11-21T09:15:08Z','2023-11-21T09:15:08Z','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','detection','hot','{"evidence_class":"correlated"}','migration-005-core-demo'),
('REL-CORE-23397-STEP7-FOLDERLOG','CORE-23397-step-7','CORE-23397-evidence-folder-owner','权限变更证据','core23397:step7>folder-owner',0.95,3,'2023-11-21T09:19:03Z','2023-11-21T09:19:03Z','2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','detection','hot','{"evidence_class":"correlated"}','migration-005-core-demo'),
('REL-CORE-23397-WEBDAV-EVIDENCE','CORE-23397-branch-webdav','CORE-23397-evidence-webdav','产生回退证据','core23397:webdav>process-evidence',0.82,2,NULL,NULL,'2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','detection','negative','{"evidence_class":"blocked"}','migration-005-core-demo'),
('REL-CORE-23397-STEP5-T1557','CORE-23397-step-5','APT28-tech-t1557-001','映射技术','core23397:step5>t1557-001',0.9,2,NULL,NULL,'2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','technique','positive','{"evidence_class":"public-confirmed"}','migration-005-core-demo'),
('REL-CORE-23397-OFFLINE-T1110','CORE-23397-branch-offline-crack','APT28-tech-t1110-002','映射技术','core23397:offline>t1110-002',0.65,1,NULL,NULL,'2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','technique','partial','{"evidence_class":"inference"}','migration-005-core-demo'),
('REL-CORE-23397-VALID-T1078','CORE-23397-branch-valid-account','APT28-tech-t1078','映射技术','core23397:valid>t1078',0.6,1,NULL,NULL,'2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','technique','partial','{"evidence_class":"inference"}','migration-005-core-demo'),
('REL-CORE-23397-STEP7-T1098','CORE-23397-step-7','APT28-tech-t1098-002','映射技术','core23397:step7>t1098-002',0.94,2,NULL,NULL,'2026-07-26T22:00:00+08:00','2026-07-26T22:00:00+08:00','technique','positive','{"evidence_class":"public-confirmed"}','migration-005-core-demo')
ON CONFLICT(id) DO UPDATE SET
  source_entity_id = excluded.source_entity_id,
  target_entity_id = excluded.target_entity_id,
  relation_type = excluded.relation_type,
  canonical_key = excluded.canonical_key,
  confidence = excluded.confidence,
  evidence_count = excluded.evidence_count,
  first_seen = excluded.first_seen,
  last_seen = excluded.last_seen,
  updated_at = excluded.updated_at,
  category = excluded.category,
  status = excluded.status,
  properties_json = excluded.properties_json,
  seed_origin = excluded.seed_origin;

DELETE FROM evidence
WHERE relationship_id IN (
  'REL-SEED-25b783a4437cd1d407',
  'REL-SEED-e8fcc05a46e831a4a3',
  'REL-SEED-2753b52ad848acf9e4',
  'REL-SEED-76f6f0c25f418ddc02',
  'REL-SEED-6a58461ef8c6b1ca22',
  'REL-SEED-1b8462fbbadae3278f',
  'REL-SEED-4c69f753ca723017e0'
);

INSERT INTO evidence (
  id, relationship_id, report_id, job_id, excerpt, confidence,
  created_at, source_ref, location
) VALUES
('EVD-CORE-23397-EVENT-START','REL-SEED-25b783a4437cd1d407','RPT-CORE-MS-MSRC-23397','ING-CORE-MS-MSRC-23397','MSRC 确认攻击者通过特制 Outlook 项目触发无需用户交互的 NTLM 认证；该节点作为公开确认的链路起点。',0.95,'2026-07-26T22:00:00+08:00','SRC-MS-MSRC-23397','Technical Details（ARGUS 结构化摘要）'),
('EVD-CORE-23397-STEP0-1','REL-SEED-e8fcc05a46e831a4a3','RPT-CORE-MS-MSRC-23397','ING-CORE-MS-MSRC-23397','恶意项目包含指向不受信任 SMB 服务器的 UNC 路径扩展属性，消息正文无需包含恶意链接。',0.96,'2026-07-26T22:00:00+08:00','SRC-MS-MSRC-23397','Technical Details（ARGUS 结构化摘要）'),
('EVD-CORE-23397-STEP1-2','REL-SEED-2753b52ad848acf9e4','RPT-SEED-0479167078fc49d324','ING-SEED-0479167078fc49d324','Windows 版 Outlook 在提醒到期时处理 PidLidReminderFileParameter，用户无需点击或打开消息。',0.95,'2026-07-26T22:00:00+08:00','SRC-A28-H2','Understanding the vulnerability（ARGUS 结构化摘要）'),
('EVD-CORE-23397-STEP2-3','REL-SEED-76f6f0c25f418ddc02','RPT-SEED-0479167078fc49d324','ING-SEED-0479167078fc49d324','Outlook 对外部 UNC 位置发起 SMB/TCP 445 连接并开始 NTLM 协商；应结合网络和端点遥测判断是否成功。',0.94,'2026-07-26T22:00:00+08:00','SRC-A28-H2','Artifacts on endpoints（ARGUS 结构化摘要）'),
('EVD-CORE-23397-STEP3-4-A','REL-CORE-23397-MAIN-3-4','RPT-SEED-0479167078fc49d324','ING-SEED-0479167078fc49d324','微软说明成功的远程 SMB 协商会把用户 Net-NTLMv2 挑战响应发送到攻击者控制的服务器。',0.93,'2026-07-26T22:00:00+08:00','SRC-A28-H2','Exploit scenario（ARGUS 结构化摘要）'),
('EVD-CORE-23397-STEP3-4-B','REL-CORE-23397-MAIN-3-4','RPT-CORE-DEMO-INPUT-23397','ING-CORE-DEMO-INPUT-23397','演示网络遥测同时出现 ConnectionSuccess、外部 TCP/445 和 NTLM-Challenge；三项组合用于支持泄露判断。',0.91,'2026-07-26T22:00:00+08:00','SRC-DEMO-INPUT-23397','endpoint_and_network[0]'),
('EVD-CORE-23397-STEP4-5-A','REL-CORE-23397-MAIN-4-5','RPT-SEED-0479167078fc49d324','ING-SEED-0479167078fc49d324','公开调查指南列出将泄露的 Net-NTLMv2 协商中继至支持 NTLM 的 Exchange 服务作为已观察攻击场景。',0.9,'2026-07-26T22:00:00+08:00','SRC-A28-H2','Initial access / authentication bypass（ARGUS 结构化摘要）'),
('EVD-CORE-23397-STEP4-5-B','REL-CORE-23397-MAIN-4-5','RPT-CORE-DEMO-INPUT-23397','ING-CORE-DEMO-INPUT-23397','演示反向代理日志显示受影响身份从外部 RFC 5737 地址以 NTLM 方式认证到 EXCH-01。',0.88,'2026-07-26T22:00:00+08:00','SRC-DEMO-INPUT-23397','exchange_evidence[0]'),
('EVD-CORE-23397-STEP5-6','REL-CORE-23397-MAIN-5-6','RPT-CORE-DEMO-INPUT-23397','ING-CORE-DEMO-INPUT-23397','紧随中继认证后，演示 EWS 日志记录同一身份执行 FindFolder，形成邮箱访问时间关联。',0.9,'2026-07-26T22:00:00+08:00','SRC-DEMO-INPUT-23397','exchange_evidence[1]'),
('EVD-CORE-23397-STEP6-7-A','REL-CORE-23397-MAIN-6-7','RPT-CORE-POL-DKWOC-23397','ING-CORE-POL-DKWOC-23397','波兰网络司令部确认攻击者在取得邮箱访问后，将 Default 文件夹权限从 None 修改为 Owner 以维持隐蔽访问。',0.95,'2026-07-26T22:00:00+08:00','SRC-POL-DKWOC-23397','Description / mailbox folder permissions（ARGUS 结构化摘要）'),
('EVD-CORE-23397-STEP6-7-B','REL-CORE-23397-MAIN-6-7','RPT-CORE-DEMO-INPUT-23397','ING-CORE-DEMO-INPUT-23397','演示 EWS 日志记录 Inbox 的 UpdateFolder 操作，权限主体为 Default，级别为 Owner。',0.92,'2026-07-26T22:00:00+08:00','SRC-DEMO-INPUT-23397','exchange_evidence[2]'),
('EVD-CORE-23397-BR-OFFLINE','REL-CORE-23397-BR-OFFLINE','RPT-SEED-0479167078fc49d324','ING-SEED-0479167078fc49d324','微软说明攻击者可能离线破解 Net-NTLMv2 以恢复口令；核心演示没有对应成功日志，因此保持为候选分支。',0.64,'2026-07-26T22:00:00+08:00','SRC-A28-H2','Understanding the vulnerability（分析推断）'),
('EVD-CORE-23397-BR-BLOCK','REL-CORE-23397-BR-BLOCK','RPT-SEED-0479167078fc49d324','ING-SEED-0479167078fc49d324','官方建议阻断对外 TCP/445；SMBClient 失败事件可支持阻断判断，但不能证明凭据泄露。',0.96,'2026-07-26T22:00:00+08:00','SRC-A28-H2','SMBClient event logs / Mitigations（ARGUS 结构化摘要）'),
('EVD-CORE-23397-BR-WEBDAV','REL-CORE-23397-BR-WEBDAV','RPT-SEED-0479167078fc49d324','ING-SEED-0479167078fc49d324','微软指出 SMB 连接失败后 Windows 可能回退到 WebDAV，并产生可供狩猎的进程创建事件。',0.84,'2026-07-26T22:00:00+08:00','SRC-A28-H2','WebDAV Process Creation events（ARGUS 结构化摘要）'),
('EVD-CORE-23397-BR-NOLEAK','REL-CORE-23397-BR-NOLEAK','RPT-SEED-0479167078fc49d324','ING-SEED-0479167078fc49d324','WebDAV 回退进程只能说明漏洞消息触发了失败的外连尝试，不能确认凭据已经泄露。',0.95,'2026-07-26T22:00:00+08:00','SRC-A28-H2','WebDAV Process Creation events（反证约束）'),
('EVD-CORE-23397-BR-PROPAGATE','REL-CORE-23397-BR-PROPAGATE','RPT-SEED-0479167078fc49d324','ING-SEED-0479167078fc49d324','微软披露攻击者可使用已获得的 EWS 访问向组织内外其他用户发送带恶意提醒属性的消息。',0.86,'2026-07-26T22:00:00+08:00','SRC-A28-H2','Credential access / lateral movement（ARGUS 结构化摘要）'),
('EVD-CORE-23397-EVENT-CVE','REL-CORE-23397-EVENT-CVE','RPT-CORE-MS-MSRC-23397','ING-CORE-MS-MSRC-23397','MSRC 将该 Outlook 漏洞登记为 CVE-2023-23397，并确认所有受支持 Windows Outlook 版本需要安装客户端更新。',0.99,'2026-07-26T22:00:00+08:00','SRC-MS-MSRC-23397','Summary / Impacted Products（ARGUS 结构化摘要）'),
('EVD-CORE-23397-MAPI','REL-CORE-23397-STEP1-MAPI','RPT-CORE-MS-CSS-23397','ING-CORE-MS-CSS-23397','微软官方脚本审计邮件、日历和任务项目中非空的提醒文件属性，并输出 CSV 供管理员判断。',0.98,'2026-07-26T22:00:00+08:00','SRC-MS-CSS-23397','Audit Mode（ARGUS 结构化摘要）'),
('EVD-CORE-23397-SMBLOG','REL-CORE-23397-STEP3-SMBLOG','RPT-SEED-0479167078fc49d324','ING-SEED-0479167078fc49d324','SMBClient Connectivity 事件中的 ServerName 可用于发现不受信任服务器，但事件本身不能确认凭据泄露。',0.78,'2026-07-26T22:00:00+08:00','SRC-A28-H2','SMBClient event logs（证据限制）'),
('EVD-CORE-23397-FWLOG','REL-CORE-23397-STEP3-FWLOG','RPT-CORE-DEMO-INPUT-23397','ING-CORE-DEMO-INPUT-23397','演示边界遥测记录 OUTLOOK.EXE 到外部 TCP/445 的成功连接和 NTLM-Challenge 网络签名。',0.9,'2026-07-26T22:00:00+08:00','SRC-DEMO-INPUT-23397','endpoint_and_network[0]'),
('EVD-CORE-23397-EWSAUTH','REL-CORE-23397-STEP5-EWSAUTH','RPT-SEED-0479167078fc49d324','ING-SEED-0479167078fc49d324','官方指南建议在 EWS 日志中筛选 AuthenticationType=NTLM，并按 ClientIpAddress 与 AuthenticatedUser 聚合异常。',0.91,'2026-07-26T22:00:00+08:00','SRC-A28-H2','EWSLogs（ARGUS 结构化摘要）'),
('EVD-CORE-23397-FOLDERLOG','REL-CORE-23397-STEP7-FOLDERLOG','RPT-CORE-POL-DKWOC-23397','ING-CORE-POL-DKWOC-23397','公开通报将 Default=Owner 的异常邮箱文件夹权限作为需要排查和恢复的关键行为。',0.95,'2026-07-26T22:00:00+08:00','SRC-POL-DKWOC-23397','Detection / mitigation guidance（ARGUS 结构化摘要）'),
('EVD-CORE-23397-ACTOR-MS','REL-SEED-4c69f753ca723017e0','RPT-SEED-0479167078fc49d324','ING-SEED-0479167078fc49d324','微软后续更新确认 Forest Blizzard 积极利用 CVE-2023-23397 取得 Exchange 邮箱访问；归因作为底部辅助结论而非主展示。',0.94,'2026-07-26T22:00:00+08:00','SRC-A28-H2','December 2023 update（ARGUS 结构化摘要）'),
('EVD-CORE-23397-ACTOR-POL','REL-SEED-4c69f753ca723017e0','RPT-CORE-POL-DKWOC-23397','ING-CORE-POL-DKWOC-23397','波兰网络司令部评估相关活动与 APT28 / Forest Blizzard 已公开行动重叠，但页面仍保留证据解释。',0.92,'2026-07-26T22:00:00+08:00','SRC-POL-DKWOC-23397','Summary（ARGUS 结构化摘要）'),
('EVD-CORE-23397-CLEANUP','REL-CORE-23397-STEP1-MAPI','RPT-CORE-MS-CSS-23397','ING-CORE-MS-CSS-23397','微软脚本 Cleanup 模式可清除恶意属性或删除恶意项目；操作前需要管理员审查审计结果。',0.96,'2026-07-26T22:00:00+08:00','SRC-MS-CSS-23397','Cleanup Mode（ARGUS 结构化摘要）');

INSERT INTO response_rules (
  id, match_entity_type, priority, action_template, rationale, source_url,
  title, group_label, match_event
) VALUES
(
  'RULE-CORE-23397-PATCH',
  '攻击步骤',
  'P0',
  '确认所有 Windows 版 Outlook 客户端已安装 CVE-2023-23397 及相关绕过修复。不要把 Exchange Server 更新误认为 Outlook 客户端修复。',
  'MSRC 明确指出漏洞位于 Windows Outlook 客户端，所有邮件托管方式都需要安装 Outlook 安全更新。',
  'https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/',
  '修复 Outlook 客户端漏洞',
  '立即遏制',
  'H2'
),
(
  'RULE-CORE-23397-BLOCK-SMB',
  '攻击步骤',
  'P0',
  '在边界、防火墙和 VPN 分流策略中阻断到互联网的 TCP/445，并核查远程办公终端是否绕过企业出口控制。',
  '阻断外部 SMB 可防止 Outlook 向远程文件共享发送 NTLM 协商材料。',
  'https://www.microsoft.com/en-us/security/blog/2023/03/24/guidance-for-investigating-attacks-using-cve-2023-23397/',
  '阻断对外 SMB 认证',
  '立即遏制',
  'H2'
),
(
  'RULE-CORE-23397-MAILBOX-AUDIT',
  '攻击步骤',
  'P0',
  '使用 Microsoft CVE-2023-23397 脚本以 Audit 模式扫描高价值邮箱及 2022 年以来项目，优先复核 InternetZone 外部路径。',
  '恶意属性可能隐藏在邮件、日历或任务项目中，普通正文检查不足以发现。',
  'https://microsoft.github.io/CSS-Exchange/Security/CVE-2023-23397/',
  '扫描恶意提醒属性',
  '排查狩猎',
  'H2'
),
(
  'RULE-CORE-23397-CORRELATE',
  '攻击步骤',
  'P1',
  '按时间关联邮件属性、SMBClient 事件、边界 TCP/445、NTLM-Challenge、反向代理和 EWS 日志。不要仅凭 SMBClient 或 WebDAV 单点事件判定泄露成功。',
  '微软调查指南明确说明多个端点事件只能证明尝试，必须使用网络与身份日志确认后续访问。',
  'https://www.microsoft.com/en-us/security/blog/2023/03/24/guidance-for-investigating-attacks-using-cve-2023-23397/',
  '验证泄露与中继是否成功',
  '排查狩猎',
  'H2'
),
(
  'RULE-CORE-23397-REMEDIATE-EWS',
  '攻击步骤',
  'P1',
  '复核受影响身份的 EWS FindFolder、CreateItem 与 UpdateFolder 操作，恢复异常 Default/Anonymous 文件夹权限，并保全反向代理和 EWS 日志。',
  '公开案例显示攻击者会利用邮箱权限修改维持访问，即使密码重置也可能继续暴露邮件内容。',
  'https://www.wojsko-polskie.pl/woc/articles/aktualnosci-w/detecting-malicious-activity-against-microsoft-exchange-servers/',
  '清除 Exchange 邮箱持久化',
  '清除恢复',
  'H2'
),
(
  'RULE-CORE-23397-CLEAN-ITEMS',
  '攻击步骤',
  'P1',
  '在管理员复核后使用官方脚本清除恶意提醒属性或删除恶意项目，并检查是否通过 EWS 向更多邮箱继续投递。',
  '官方脚本支持 Audit 与 Cleanup 两种模式，清理动作需要基于审计结果执行。',
  'https://microsoft.github.io/CSS-Exchange/Security/CVE-2023-23397/',
  '清理恶意邮件与扩散项目',
  '清除恢复',
  'H2'
),
(
  'RULE-CORE-23397-HARDEN-NTLM',
  '攻击步骤',
  'P2',
  '评估限制或禁用 NTLM，持续监测外部 NTLM 认证、对外 SMB、异常 EWS 客户端地址和邮箱权限变更。',
  '减少 NTLM 暴露并建立跨邮件、网络与身份的数据关联，可降低同类强制认证与中继风险。',
  'https://www.microsoft.com/en-us/security/blog/2023/03/24/guidance-for-investigating-attacks-using-cve-2023-23397/',
  '补强身份与邮件检测覆盖',
  '长期加固',
  'H2'
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

UPDATE actor_profiles
SET
  source_refs_json = '["SRC-A28-H2","SRC-POL-DKWOC-23397","SRC-A28-H10-NCSC"]',
  source_urls_json = '["https://www.microsoft.com/en-us/security/blog/2023/03/24/guidance-for-investigating-attacks-using-cve-2023-23397/","https://www.wojsko-polskie.pl/woc/articles/aktualnosci-w/detecting-malicious-activity-against-microsoft-exchange-servers/","https://attack.mitre.org/groups/G0007/"]',
  public_attribution = 'Microsoft 将积极利用 CVE-2023-23397 并访问 Exchange 邮箱的活动关联到 Forest Blizzard；波兰网络司令部披露的邮箱权限持久化活动与 APT28 / Forest Blizzard 已公开行动重叠。组织归因仅作为辅助研判。',
  source_grade = 1.0,
  updated_at = '2026-07-26T22:00:00+08:00'
WHERE actor_id = 'ENT-ACTOR-fbde425d47a0';

INSERT OR REPLACE INTO schema_migrations (version, name, applied_at)
VALUES (5, 'cve23397_core_demo', '2026-07-26T22:00:00+08:00');

COMMIT;
