PRAGMA foreign_keys = ON;

-- Public demo reports are stored as metadata plus an ARGUS-derived summary.
-- The complete source remains at the publisher URL; no full article is copied.

UPDATE raw_reports
SET
  title = 'Guidance for investigating attacks using CVE-2023-23397',
  source = 'Microsoft Incident Response',
  report_date = '2023-03-24',
  classification = '公开来源',
  language = 'English',
  original_filename = NULL,
  mime_type = 'text/html',
  extracted_text = 'ARGUS 结构化摘要：恶意方可通过带有远程 UNC 路径的特制 Outlook 消息触发外连 SMB，并导致 Net-NTLMv2 凭据材料泄露。分析时应把消息属性、SMB 客户端事件、边界网络遥测与后续 Exchange 活动按时间关联；单独出现外连尝试不能证明凭据已经泄露。',
  extraction_note = '基于发布机构公开页面人工提炼的 Demo 节点与摘要；非报告原文转载。',
  reliability = '官方厂商研究',
  external_url = 'https://www.microsoft.com/en-us/security/blog/2023/03/24/guidance-for-investigating-attacks-using-cve-2023-23397/',
  assessment = '公开报告支持“特制 Outlook 消息 → 远程 SMB 连接 → Net-NTLMv2 泄露风险”的链路。是否发生后续凭据滥用，仍需结合身份、Exchange 与网络日志判断。'
WHERE id = 'RPT-SEED-0479167078fc49d324';

UPDATE evidence
SET location = 'ARGUS 结构化摘录（基于公开报告，非逐字引文）'
WHERE report_id = 'RPT-SEED-0479167078fc49d324';

UPDATE raw_reports
SET
  title = 'Hunting Russian Intelligence “Snake” Malware',
  source = 'CISA / FBI / NSA / Five Eyes',
  report_date = '2023-05-09',
  classification = 'TLP:CLEAR / 公开来源',
  language = 'English',
  original_filename = 'aa23-129a_snake_malware_2.pdf',
  mime_type = 'application/pdf',
  extracted_text = 'ARGUS 结构化摘要：联合网络安全公告披露了 Snake 的主机组件、加密虚拟文件系统、网络通信和检测方法。样例链路保留安装器、持久化组件、加密存储与点对点通信等可追溯节点，具体命中仍应由样本与主机证据确认。',
  extraction_note = '基于 AA23-129A 公开公告人工提炼的 Demo 节点与摘要；非报告原文转载。',
  reliability = '政府联合公告',
  external_url = 'https://www.cisa.gov/sites/default/files/2023-05/aa23-129a_snake_malware_2.pdf',
  assessment = '该来源适合支持 Snake 技术链和检测线索，不应仅凭某一驱动、密钥格式或网络特征作出确定归因。'
WHERE id = 'RPT-SEED-30f7f4d08cc35b19e3';

UPDATE evidence
SET location = 'ARGUS 结构化摘录（基于 AA23-129A，非逐字引文）'
WHERE report_id = 'RPT-SEED-30f7f4d08cc35b19e3';

UPDATE raw_reports
SET
  title = 'Midnight Blizzard: Guidance for responders on nation-state attack',
  source = 'Microsoft Threat Intelligence',
  report_date = '2024-01-25',
  classification = '公开来源',
  language = 'English',
  original_filename = NULL,
  mime_type = 'text/html',
  extracted_text = 'ARGUS 结构化摘要：该活动从低频密码喷洒进入旧测试租户账户，继而滥用高权限 OAuth 应用访问 Exchange Online。公开指导强调传统 IP IOC 不足以覆盖高换手住宅代理，应结合身份登录、服务主体、OAuth 授权与邮箱访问活动研判。',
  extraction_note = '基于发布机构公开页面人工提炼的 Demo 节点与摘要；非报告原文转载。',
  reliability = '官方厂商研究',
  external_url = 'https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/',
  assessment = '公开报告支持“密码喷洒 → 旧租户账户 → 高权限 OAuth 应用 → Exchange 邮箱访问”的行为链；组织关联仅作为有来源的辅助假设呈现。'
WHERE id = 'RPT-SEED-4296b034cca50574da';

UPDATE evidence
SET location = 'ARGUS 结构化摘录（基于公开报告，非逐字引文）'
WHERE report_id = 'RPT-SEED-4296b034cca50574da';

INSERT OR REPLACE INTO schema_migrations (version, name, applied_at)
VALUES (4, 'public_demo_report_sources', '2026-07-25T21:00:00+08:00');
