# 04 — 复核并发布一条新 AttackFlow

**What to build:** 让分析人员通过现有情报入库和复核流程检查一条 AttackFlow 候选，在系统完成证据验证、实体解析和结构校验后事务发布，并能立即查看或回滚该 Flow。

**Blocked by:** 02 — 迁移全部历史攻击流

**Status:** completed

- [x] 候选 Flow 在发布前与正式 AttackFlow 隔离，暂存和复核不会修改历史图谱。
- [x] 每个 Action、Relation、Context Link 和 reported Actor claim 都能关联到相应来源证据。
- [x] 系统验证原文 quote 并计算 Source Span 或 locator，不信任候选提供的偏移量。
- [x] Context 在发布阶段解析为规范 Entity；确定性 IOC 复用已有身份，模糊名称保持待复核。
- [x] 发布校验拒绝未知 Relation 类型、缺少证据、非法 mainline、断开的相邻 mainline Action 和不属于该 Flow 的引用。
- [x] reported Actor 保留来源口径、定性置信度和证据，不显示为 ARGUS 已确认归因。
- [x] 任一校验失败时数据库没有部分写入；成功发布保持幂等并生成可回滚的知识版本。
- [x] 发布成功后，新 Flow 无需重新构建静态数据即可出现在 AttackFlow 运行时读取和现有攻击链页面。
- [x] 当前情报入库与路径复核页面保留主要交互，并清楚区分暂存、阻塞、已发布和已回滚状态。
- [x] 外部行为测试覆盖暂存、验证失败、修正后发布、重复发布、即时读取和回滚。
