# 02 — 收敛人工精选攻击流

**What to build:** 仅保留最早人工整理且前端展示质量稳定的 APT28、APT29 和 Lazarus 三条历史路径，将它们收敛为 AttackFlow V1；删除后续模型实验产生的路径数据、缓存和批次输出，不迁移低质量实验结果。

**Blocked by:** 01 — 贯通第一条 AttackFlow

**Status:** completed

- [x] AttackFlow 列表只返回 APT28 Zebrocy、APT29 DNC 和 Lazarus Redbanc 三条人工精选 Flow。
- [x] 三条 Flow 均可通过详情接口读取，并保留稳定 Flow、Action、Source、Context 和 Evidence 身份。
- [x] 每条 Flow 都具有显式 mainline；相邻 mainline Action 均存在已保存且有证据的 Relation。
- [x] Lazarus 的双结果分支改为普通 `causes` Relation 拓扑，不再使用 `branch` 作为过程语义。
- [x] 后续模型实验产生的历史路径 JSON、缓存、批次输出和专用金标文件从仓库删除。
- [x] 当前前端 Snapshot 仍只展示这三条精选路径，既有查询和攻击链详情保持可用。
- [x] 历史 AttackFlow 不写入 reconstructed 或 predicted 查询状态，缺少支持的旧元数据不提升为事实。
- [x] 迁移在当前 SQLite 数据副本上保持三条 Flow 的 Action、Relation、Context、Entity、Source 和 Evidence 身份。
- [x] 三条当前历史 Flow 共用同一个运行时 AttackFlow 详情读取入口，不为每条路径编写专用前端逻辑。
- [x] 回归测试覆盖多步主干、已知入口缺口、双结果分支和 Context 密集案例。
