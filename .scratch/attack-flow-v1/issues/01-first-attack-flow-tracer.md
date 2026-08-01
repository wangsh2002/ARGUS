# 01 — 贯通第一条 AttackFlow

**What to build:** 让一条当前已整理的历史攻击路径以 AttackFlow V1 的形式贯穿规范领域模型、持久化读取、运行时接口、前端适配和现有攻击链详情页面，证明新契约可以在不重做界面的情况下落地。

**Blocked by:** None — can start immediately

**Status:** completed

- [x] 运行时接口返回带版本、稳定 Flow 身份、稳定 Action 身份、Actions、Relations 和显式 mainline 的 AttackFlow。
- [x] 选定历史 Flow 的来源、证据、Context 和当前可用描述能够通过新契约读取，不从静态卡片补造字段。
- [x] mainline 由后端契约明确给出，前端不使用 Action 数组顺序、标签、ATT&CK tactic 或图遍历推断。
- [x] 现有攻击链页面通过同源运行时请求显示该 Flow，并保持当前横向主干、关联内容和详情交互。
- [x] 新读取路径与当前 Snapshot 路径可以暂时共存，接口失败时不会破坏其他尚未迁移页面。
- [x] Action、Relation、Context 和 Evidence 的前端映射集中在一个兼容适配边界，不散落到展示组件。
- [x] 后端 HTTP 测试和前端交互测试共同覆盖从数据库记录到可见攻击链的完整示踪路径。
