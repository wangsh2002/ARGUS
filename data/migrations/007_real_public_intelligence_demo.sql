PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

UPDATE raw_reports
SET
  title = 'APT28 campaign directed against Polish government institutions',
  source = 'CERT Polska / CSIRT MON',
  report_date = '2024-05-08',
  classification = '公开来源',
  language = 'English',
  reliability = '国家级 CSIRT 一手公开通报',
  external_url = 'https://cert.pl/en/posts/2024/05/apt28-kampania/',
  extracted_text = 'CERT Polska 与 CSIRT MON 观察到针对波兰政府机构的 APT28 恶意邮件活动。邮件链接经 run.mocky.io 跳转至 webhook.site，并下载伪装成照片的 ZIP。压缩包包含重命名的 Windows Calculator、隐藏 BAT 脚本和伪造的 WindowsCodecs.dll。运行诱饵程序后触发 DLL Side-Loading，脚本继续利用 Microsoft Edge 和合法互联网服务下载命令，最终收集主机 IP 与多个目录信息。CERT Polska 指出该流程与此前公开的 HEADLACE 活动一致。',
  extraction_note = '依据 CERT Polska 公开技术分析人工提炼；非报告原文转载。',
  assessment = '该来源支持“恶意邮件—重定向服务—ZIP 图片诱饵—DLL 侧载—脚本分阶段下载—主机信息收集”的真实公开路径。',
  source_ref = 'SRC-CERTPL-APT28-20240508'
WHERE id = 'RPT-SEED-9c0e382b56ac4bd291';

UPDATE entities
SET
  label = '诱导点击的钓鱼邮件',
  normalized_value = '诱导点击的钓鱼邮件',
  description = 'CERT Polska 披露的 APT28 邮件入口，正文使用吸引收件人点击的叙事并包含外部链接。',
  properties_json = json_set(
    properties_json,
    '$.entity_value', 'APT28 phishing email targeting Polish government institutions',
    '$.analysis_state', 'observed',
    '$.evidence_class', 'public-confirmed',
    '$.source_ref', 'SRC-CERTPL-APT28-20240508'
  )
WHERE id = 'APT28-event-H1-step-0';

UPDATE entities
SET
  label = '合法服务重定向',
  normalized_value = '合法服务重定向',
  description = '邮件链接先访问 run.mocky.io，再跳转至 webhook.site，以常用开发服务降低恶意链接被发现的概率。',
  properties_json = json_set(
    properties_json,
    '$.entity_value', 'run.mocky.io → webhook.site',
    '$.analysis_state', 'observed',
    '$.evidence_class', 'public-confirmed',
    '$.source_ref', 'SRC-CERTPL-APT28-20240508'
  )
WHERE id = 'APT28-event-H1-step-1';

UPDATE entities
SET
  label = 'ZIP 图片诱饵',
  normalized_value = 'zip 图片诱饵',
  description = '从 webhook.site 下载的 ZIP 名称以 IMG- 开头，包含伪装成图片的 Windows Calculator、隐藏 BAT 脚本和伪造 DLL。',
  properties_json = json_set(
    properties_json,
    '$.entity_value', 'IMG-*.zip',
    '$.analysis_state', 'observed',
    '$.evidence_class', 'public-confirmed',
    '$.source_ref', 'SRC-CERTPL-APT28-20240508'
  )
WHERE id = 'APT28-event-H1-step-2';

UPDATE entities
SET
  label = 'DLL Side-Loading',
  normalized_value = 'dll side-loading',
  description = '运行重命名的 Windows Calculator 后加载攻击者放置的 WindowsCodecs.dll，并由伪造 DLL 启动隐藏 BAT 脚本。',
  properties_json = json_set(
    properties_json,
    '$.entity_value', 'Calculator.exe → WindowsCodecs.dll → BAT',
    '$.analysis_state', 'reconstructed',
    '$.evidence_class', 'public-confirmed',
    '$.inference_basis', '输入摘要保留 ZIP、隐藏 DLL/BAT 与后续脚本行为，系统依据 CERT Polska 完整公开链恢复侧载关系。',
    '$.source_ref', 'SRC-CERTPL-APT28-20240508'
  )
WHERE id = 'APT28-event-H1-step-3';

UPDATE entities
SET
  label = 'Edge 分阶段下载',
  normalized_value = 'edge 分阶段下载',
  description = 'BAT 脚本使用 Microsoft Edge 访问 webhook.site，下载后续脚本并通过更改扩展名后执行。',
  properties_json = json_set(
    properties_json,
    '$.entity_value', 'msedge.exe → webhook.site → CMD',
    '$.analysis_state', 'observed',
    '$.evidence_class', 'public-confirmed',
    '$.source_ref', 'SRC-CERTPL-APT28-20240508'
  )
WHERE id = 'APT28-event-H1-step-4';

UPDATE entities
SET
  label = '主机信息收集',
  normalized_value = '主机信息收集',
  description = '公开分析最终观察到主机 IP 以及桌面、下载、文档和程序目录信息被收集并发送至控制端。',
  properties_json = json_set(
    properties_json,
    '$.entity_value', 'IP and directory discovery',
    '$.analysis_state', 'predicted',
    '$.evidence_class', 'public-confirmed',
    '$.prediction_basis', '该行为已在公开历史链中确认，但在当前不完整输入中作为应优先监测的后续行为。',
    '$.source_ref', 'SRC-CERTPL-APT28-20240508'
  )
WHERE id = 'APT28-event-H1-step-5';

UPDATE relationships
SET relation_type = CASE id
  WHEN 'REL-SEED-145c5f56ee2aae05bd' THEN '跳转'
  WHEN 'REL-SEED-8ee46f891d5d9c3795' THEN '下载'
  WHEN 'REL-SEED-dc003a9aa297489020' THEN '触发侧载'
  WHEN 'REL-SEED-69a3cbea8c13fec8fe' THEN '分阶段下载'
  WHEN 'REL-SEED-26563638bb1db6892c' THEN '执行发现'
  ELSE relation_type
END
WHERE id IN (
  'REL-SEED-145c5f56ee2aae05bd',
  'REL-SEED-8ee46f891d5d9c3795',
  'REL-SEED-dc003a9aa297489020',
  'REL-SEED-69a3cbea8c13fec8fe',
  'REL-SEED-26563638bb1db6892c'
);

INSERT OR REPLACE INTO schema_migrations (version, name, applied_at)
VALUES (7, 'real_public_intelligence_demo', '2026-07-28T15:00:00+08:00');

COMMIT;
