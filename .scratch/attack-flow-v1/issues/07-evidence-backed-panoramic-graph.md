# 07 — 贯通证据化全景图谱

**What to build:** 让 AttackFlow、Action、Entity、Actor 和 Source 通过同一组规范身份进入运行时全景图谱，并允许分析人员从任一核心对象出发探索可解释关联。

**Blocked by:** 02 — 迁移全部历史攻击流；04 — 复核并发布一条新 AttackFlow

**Status:** completed

- [x] 从 IOC、Actor、Source、AttackFlow 和 Action 任一身份开始都能运行时展开相邻节点和关系。
- [x] AttackFlow 详情与全景图谱使用同一 Flow、Action 和 Entity 身份，不维护相互独立的图谱副本。
- [x] Flow membership、Flow Source support、Action Context、reported Actor claim 和 Evidence 均以规范原子关系参与展开。
- [x] Actor-to-IOC、Flow-to-IOC 等跨层捷径在查询时动态聚合，不作为重复事实写入存储。
- [x] 每条聚合边返回其底层节点和关系路径，前端可以解释“为什么相关”。
- [x] 兼容迁移的历史 Flow 与新发布 Flow 都能在同一图谱查询中出现。
- [x] 现有全景图谱页面使用运行时展开结果，并保留当前探索、返回和详情交互。
- [x] 图谱为空、后端不可用或局部节点无更多关系时，界面给出真实状态而不是回退到虚构示例。
- [x] 测试分别从五类入口验证双向遍历、身份一致性、证据可达、动态聚合和聚合边不落库。

## Validation

- 新增 `GET /v1/graph/nodes` 与 `GET /v1/graph/neighborhoods/{node_id}`，统一返回规范节点、原子边、动态聚合边及底层解释路径。
- 历史 Flow 的 Actor 由已保存的策展元数据按规范 Actor 身份解析；新发布 Flow 直接读取 reported Actor claim，不创建第二份图谱事实。
- `backend/tests/test_panoramic_graph_api.py` 覆盖五类入口、双向 Action Context、AttackFlow 身份一致、证据与来源可达、动态聚合不落库及新发布 Flow 自动出现。
- 2026-08-01 后端全量验证：`107 passed`；前端交互验证：`36 passed`；TypeScript、相关 ESLint 与 `vinext build` 均通过。
