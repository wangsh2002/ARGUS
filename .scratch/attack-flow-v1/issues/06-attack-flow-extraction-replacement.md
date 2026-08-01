# 06 — 按 AttackFlow 标准重写模型抽取

**What to build:** 让已归档报告直接抽取为零到多个简化 AttackFlow 暂存候选，模型只负责来源内的行为、允许关系、Context、reported Actor、mainline 建议和原文 quote，随后进入已经验证的复核发布流程。

**Blocked by:** 05 — 支持零到多 Flow 与多来源合并

**Status:** completed

- [x] 模型输出使用局部临时身份，不生成或覆盖全局 Flow、Action、Entity 或 Actor 身份。
- [x] Action 使用简洁动宾名称，完整来源句子只作为 description 或 Evidence quote。
- [x] IOC、工具、恶意软件、漏洞、账户、文件和资产输出为 Action Context，不作为过程推进 Action。
- [x] Relation 只允许 `precedes`、`leads_to`、`enables`、`causes`、`on_success` 和 `on_failure`。
- [x] 缺少关系 quote 时保持断开，不调用修复逻辑为了图形完整性补造边。
- [x] ATT&CK 映射保持可选，模型不负责技术名称、tactic、查询得分或 matched/reconstructed/predicted 状态。
- [x] 一份来源可输出零、一或多个活动候选，并保留无法归属的证据供复核而不是静默丢弃。
- [x] 所有模型 quote 在进入复核候选前经过原文验证；验证失败的事实被拒绝并留下审计原因。
- [x] 抽取结果完全复用现有暂存、复核、实体解析、发布和回滚能力，不建立第二条发布链路。
- [x] 固定来源验收集覆盖 no-flow、多活动、分支、汇合、冲突归因、缺关系证据和可选 ATT&CK。

## Validation

- `data/corpus/attack_flow_extraction_acceptance.json` 固定 8 篇 AnnoCTR 原文及 SHA-256，禁止使用其标注答案。
- `data/experiments/attack_flow_extraction_acceptance_latest.json` 保存最新真实模型实跑候选和拒绝审计。
- 抽取采用通用的“活动分段 → 保守归并 → 变体清单 → Action 抽取 → Relation 抽取 → 证据图投影”流程，主干从已验证关系图推导，不使用报告名、样本哈希或固定节点的特判。
- 2026-08-01 固定验收集最新实跑：8/8 严格用例通过，接受 7 个符合规范的多步 Flow 候选，拒绝 47 项无效或无法验证的模型事实；分支/汇合场景不再只校验候选数量。
- `data/experiments/attack_flow_extraction_holdout_latest.json` 保存从固定验收集之外随机选取的留出集结果；最新使用新随机种子的 5/5 通过，包含 2 篇无攻击流报告和 3 篇产生多步攻击流的报告。
