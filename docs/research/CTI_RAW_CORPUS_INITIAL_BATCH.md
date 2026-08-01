# ARGUS 原始报告语料首批落地记录

## 结论

首批不使用论文数据集提供的实体、ATT&CK 标签或关系，只使用 AnnoCTR 发布的
完整原始报告文本。报告文本进入不可变原件层，历史路径由原文证据重新整理。

AnnoCTR 官方仓库说明其语料包含商业 CTI 厂商提供的完整报告文本，语料目录采用
CC-BY-SA 4.0；本次固定到提交
`d510b6949e1938d47c93a43eedd562dc538439dc`。

- 数据集仓库：https://github.com/boschresearch/anno-ctr-lrec-coling-2024
- 论文：https://aclanthology.org/2024.lrec-main.103/
- 本地清单：`data/corpus/annoctr_initial_manifest.json`

## 首批6份报告

| 发布方 | 报告 | 官方原文 |
| --- | --- | --- |
| Lab52 / S2 Grupo | Mustang Panda Recent Activity: Dll-Sideloading trojans with temporal C2 servers | https://lab52.io/blog/mustang-panda-recent-activity-dll-sideloading-trojans-with-temporal-c2-servers/ |
| Proofpoint | Whatta TA: TA505 Ramps Up Activity, Delivers New FlawedGrace Variant | https://www.proofpoint.com/uk/blog/threat-insight/whatta-ta-ta505-ramps-activity-delivers-new-flawedgrace-variant |
| Zscaler ThreatLabz | Targeted Attack on Government Organizations Delivers Netwire RAT | https://www.zscaler.com/blogs/security-research/targeted-attack-government-organizations-delivers-netwire-rat |
| Zscaler ThreatLabz | Squirrelwaffle: New Loader Delivering Cobalt Strike | https://www.zscaler.com/blogs/security-research/squirrelwaffle-new-loader-delivering-cobalt-strike |
| Zscaler ThreatLabz | CloudFall Targets Researchers and Scientists | https://www.zscaler.com/blogs/security-research/cloudfall-targets-researchers-and-scientists-invited-international-military |
| QuoIntelligence | APT28 Delivers Zebrocy Malware Campaign using NATO Theme as Lure | https://quointelligence.eu/2020/09/apt28-zebrocy-malware-campaign-nato-theme/ |

选择标准是正文完整、官方页面仍可核验，并且包含明确的多阶段行为或分支。

## 首批历史路径

当前整理3条代理辅助复核路径，尚未冒充人工确认金标准：

1. TA505：4种邮件入口分支，汇合到 Excel 宏、两级 MSI、MirrorBlast、
   ReflectiveGnome 与 FlawedGrace。
2. Squirrelwaffle：Word/VBS/PowerShell 和 Excel 4.0 macro 双入口，汇合到
   Squirrelwaffle Loader 与 Cobalt Strike。
3. CloudFall：两种 Word 模板注入和持久化变体，汇合到相似的载荷行为。

三条路径共38个节点、40条边和78条证据链接。每个节点和边均引用一条原文行；
数据库中没有把任何算法补全或预测写成历史事实。

## 数据边界

- `source_artifacts`：数据集保存的完整文本副本及哈希。
- `source_documents/source_spans`：解析版本与逐行证据锚点。
- `activity_paths`：原文支持的历史活动路径。
- `path_evidence_links`：节点或边到原文位置的链接。
- `path_analysis_runs`：在线算法补全和预测快照。

现阶段报告审核状态为 `parsed`，路径审核状态为
`agent-assisted-reviewed`。只有用户最终确认的路径才会升级为
`curator-confirmed` 或金标准。
