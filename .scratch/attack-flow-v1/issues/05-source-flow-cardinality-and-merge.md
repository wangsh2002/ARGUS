# 05 — 支持零到多 Flow 与多来源合并

**What to build:** 让入库流程正确处理来源与 AttackFlow 的真实基数：无过程证据的来源只发布实体证据，多活动来源产生多个待复核 Flow，多份来源可以经审核共同支持一个既有 Flow。

**Blocked by:** 04 — 复核并发布一条新 AttackFlow

**Status:** completed

- [x] IOC-only、能力说明或纯上下文来源可以形成有效 no-flow 结果并发布实体证据，不创建空 Flow 或伪造 Action。
- [x] 一份包含多个独立攻击活动的来源产生多个隔离候选，Actor、时间或版面相邻不会自动把它们连成一条 Flow。
- [x] 每个候选可以独立修正、拒绝或发布，一个候选失败不会污染其他候选。
- [x] 新 Source 可以作为附加支持关联到既有 Flow，并保留该 Source 自己的 Evidence 和 reported Actor claim。
- [x] 共享 Actor 名称或 ATT&CK 技术不足以合并 Flow；只有强身份锚点、兼容行为结构和显式复核才提出或完成合并。
- [x] 同一 Source 的重复入库以及同一 Flow-Source 支持关系保持幂等，不重复增加事实或证据计数。
- [x] 入库预览明确显示 no-flow、候选数量、建议新建、建议合并及需要人工决定的原因。
- [x] 测试覆盖零 Flow、单 Flow、多 Flow、多来源同 Flow、错误合并拒绝和重复发布。
