# Attack Flow、FlowViz 与 ARGUS 攻击过程对比

日期：2026-08-01

## 结论摘要

- **Attack Flow** 是攻击行为图的标准语言和工具链，不负责自动从报告中抽取攻击过程。它以 STIX 2.1 扩展表达 action、condition、operator、asset 和 flow scope，强调边表示行为依赖和状态效果，而不只是时间先后。
- **FlowViz** 是面向文章输入的 LLM 可视化工具：自动生成 React Flow 节点和边，提供流式展示、Story Mode 和 PNG/STIX/AFB/JSON 导出。它更像“快速生成攻击故事图”的应用，而不是证据治理或研判平台。
- **ARGUS** 当前已经不是普通的线性攻击链。它把行为实例、过程依赖、上下文实体、证据锚点、推断来源、审阅状态和分析投影分层建模，并区分直接观测、算法补全和预测。因此 ARGUS 的强项是可追溯研判，弱项是缺少 Attack Flow 兼容的交换层和显式 AND/OR、true/false 条件语义。

## 1. Attack Flow 实际做什么

Attack Flow 当前文档版本为 v3.2.0。项目将自身定义为描述攻击者如何组合和排序攻击技术的机器可读语言，并作为 STIX 2.1 扩展与 STIX 生态互操作。

核心语义包括：

- `attack-flow`：描述名称、范围和一个或多个起点；范围可以是 incident、campaign、threat-actor、malware、emulation-plan、attack-tree 等。
- `attack-action`：一次离散的攻击者行为或技术执行。
- `attack-condition`：描述行为产生的状态或结果，并通过 true/false 路径表达成功、失败和替代方案。
- `attack-operator`：使用 AND/OR 汇合多条路径，明确后续行为需要全部前置效果还是任一前置效果。
- STIX 对象和 asset：为行为补充账户、进程、文件、基础设施、受影响对象等上下文。

Attack Flow 特别强调：动作之间的箭头表示**依赖**，即后续动作依赖前序动作成功产生的效果；它不等同于“动作 B 时间上发生在动作 A 之后”。

来源：

- [Attack Flow v3.2.0 文档](https://center-for-threat-informed-defense.github.io/attack-flow/)
- [Attack Flow Language](https://center-for-threat-informed-defense.github.io/attack-flow/language/)
- [Attack Flow Introduction](https://center-for-threat-informed-defense.github.io/attack-flow/introduction/)
- [Attack Flow GitHub](https://github.com/center-for-threat-informed-defense/attack-flow)

## 2. FlowViz 实际做什么

FlowViz 是一个 React/TypeScript 应用，输入安全文章 URL 或文本后，通过 Anthropic、OpenAI 或 Ollama 生成攻击图，并提供实时构图、ATT&CK 映射、Story Mode、保存加载和多格式导出。

它的主提示词直接要求模型输出 React Flow 的 `nodes` 和 `edges`，节点包括 action、tool、malware、asset、infrastructure、URL、vulnerability 和 AND/OR operator；同时要求每个节点保留 `source_excerpt`。

FlowViz 的优势是交互速度和演示效果，但当前实现存在几项语义风险：

1. 提示词要求按 ATT&CK tactic 顺序组织故事，并用 `Leads to` 连接动作；转换器在没有 operator 时也会按 tactic 顺序自动增加 `Followed by` 边。这可能把分类顺序或叙事顺序误当成过程依赖。
2. 提示词一方面要求抽取“mentioned or implied”的技术，另一方面又要求不得推断，约束存在冲突。
3. 内部类型声明了 condition，但主转换器没有 condition converter；operator 输入查找代码还把“condition”匹配成 AND/OR operator 类型，说明复杂分支语义尚未完全闭合。
4. 名为 V3 的 AFB 导出器实际写出 `attack_flow_v2` schema，并依赖 Builder 的迁移兼容，因此“能导出 AFB”不等于内部模型天然满足当前 Attack Flow 语言语义。

来源：

- [FlowViz GitHub](https://github.com/davidljohnson/flowviz)
- [FlowViz direct flow prompt](https://raw.githubusercontent.com/davidljohnson/flowviz/main/src/features/flow-analysis/services/directFlowPrompts.ts)
- [FlowViz action converter](https://raw.githubusercontent.com/davidljohnson/flowviz/main/src/features/flow-analysis/services/converters/ActionNodeConverter.ts)
- [FlowViz operator converter](https://raw.githubusercontent.com/davidljohnson/flowviz/main/src/features/flow-analysis/services/converters/OperatorNodeConverter.ts)
- [FlowViz AFB exporter](https://raw.githubusercontent.com/davidljohnson/flowviz/main/src/features/flow-export/services/attackFlowV3Exporter.ts)

## 3. ARGUS 当前攻击过程是什么

ARGUS 的领域模型已经明确区分：

- 行为实例：活动上下文中的原子攻击者动作；
- 过程依赖：enables、causes、conditional、branch、merge 等有解释的执行关系；
- 行为上下文关系：动作与 IOC、工具、漏洞、资产、ATT&CK 技术之间的角色关系；
- 路径假设：可分支、可修改、可拒绝的行为解释；
- 补全步骤与预测步骤：与直接观测严格分离；
- 研判投影：从完整活动图计算主干、分支折叠、泳道和关键上下文，不把展示主干当作事实本体。

对应实现位于：

- `CONTEXT.md`：统一领域语言；
- `data/migrations/011_evidence_first_corpus.sql`：行为节点、依赖边、节点/边证据和审阅状态；
- `data/migrations/014_activity_graph_context.sql`：动作上下文和可替换分析投影；
- `backend/argus_backend/attack_mainline.py`：按 SOC/IR 目标生成主干和分支投影，明确不使用 ATT&CK tactic 顺序推断时间；
- `backend/argus_backend/report_graph_quality.py`：分别验证核心过程、证据、活动聚类和审阅队列。

当前 SQLite 快照中有 3 条 agent-assisted-reviewed 历史路径，共 16 个 source-observed 行为节点和 13 条依赖边；其中 Lazarus 样例已经包含一个双臂真实分支，但当前已审阅数据还没有 merge 边，说明模型能力已经具备，语料覆盖仍较小。

## 4. 关键差异矩阵

| 维度 | Attack Flow | FlowViz | ARGUS 当前实现 |
|---|---|---|---|
| 核心定位 | 标准语言、交换格式、Builder | 自动抽取和可视化应用 | 证据化攻击过程研判平台 |
| 主要输入 | 人工/工具生成的结构化 flow | URL、文章文本、PDF | 来源文档、告警线索、历史知识快照 |
| 核心节点 | action、condition、operator、asset/STIX | ATT&CK action + 工具/资产/IOC 类节点 | behavior-action；实体通过 context link 挂接 |
| 边的含义 | 前置效果与行为依赖 | 大量为 Leads to/Followed by/Uses/Targets | enables、causes、conditional、branch、merge |
| 分支逻辑 | true/false、AND/OR、成功/失败 | 有 operator 概念，但当前实现不完整 | branch/merge/condition label，尚无一等 AND/OR 节点 |
| 证据 | STIX external references，可粗可细 | 节点上的 source excerpt | 可定位 source span；支持/反证/上下文；节点、边和 context 均可挂证据 |
| 推断治理 | 由生产者决定 | LLM 直接生成，confidence 较粗 | observed/reconstructed/predicted + assertion origin + review state |
| 活动边界 | 通过 scope 描述 | 通常一篇文章生成一张图 | 先做 activity cluster，避免一篇报告强行合成一条链 |
| 展示与事实 | flow 本身就是交换对象 | React Flow 图是主要产物 | 完整活动图与 analysis projection 分离 |
| 互操作 | STIX 2.1 原生 | 支持导出，但内部模型自定义 | 当前主要是 ARGUS 自有 JSON/SQLite 模型 |

## 5. ARGUS 相对优势

1. **证据粒度更强**：不只是保存摘录字符串，而是保存可定位 span，并能说明证据支持、反驳还是只提供上下文。
2. **不会把推断冒充事实**：补全、预测、来源观测和人工确认是不同 assertion origin。
3. **活动边界更合理**：允许一篇报告包含多个活动、共享恶意软件能力或无路径结果，而不是默认生成一条完整故事线。
4. **事实图与展示投影分离**：可以针对 SOC 二线和应急响应选择不同主干，仍保留同一底层活动图。
5. **过程语义优于时间排序**：当前主干算法明确把 ATT&CK tactic 视为语义目标，而非固定时间线，避免 FlowViz 的主要风险。

## 6. ARGUS 当前短板

1. **缺少标准交换层**：自有 `activity_path_*` 模型没有直接映射为 Attack Flow/STIX bundle，难以与其他工具交换。
2. **复杂控制流不够显式**：branch、merge 和 `condition_label` 能表达拓扑，但无法无歧义表示 true/false、AND/OR、成功/失败回退。
3. **在线分析接口仍偏简化**：`PathAnalysisResponse` 仍以 sequence、steps、edges 为主，无法完整返回活动簇、多根、逻辑节点和投影视图。
4. **语料成熟度不足**：当前已审阅路径仅 3 条，分支只有一个样例，尚无已审阅 merge、conditional 或复杂多活动示例。
5. **缺少导入能力**：目前不能把外部 Attack Flow corpus 直接作为 reference flow 导入、校验和检索。

## 7. 建议路线

### P0：保留 ARGUS 本体，不改成 Attack Flow 本体

ARGUS 的 evidence、assertion origin、review state、activity cluster 和 projection 是 Attack Flow 标准本身没有替你解决的研判能力。不要为了兼容标准而把这些字段压扁。

### P1：增加 Attack Flow 适配层

- `ARGUS activity graph -> Attack Flow STIX bundle`：用于对外交换和 Builder 查看；
- `Attack Flow STIX bundle -> reference flow`：导入公开 corpus，作为检索候选，而不是当前事件事实；
- 导出时把 ARGUS 专有证据和审阅信息保存在 extension/custom properties 中。

### P2：补齐一等逻辑语义

在现有边类型之上增加逻辑节点或逻辑组：

- condition：表达具体状态；
- true/false effect；
- AND/OR join；
- fallback/retry；
- ambiguous join：明确表示来源本身无法确定 AND 还是 OR。

### P3：借鉴 FlowViz 的产品体验，不照搬其过程推断

可以借鉴：流式构图、Story Mode、节点详情、快速导出和 Builder 兼容。

不应照搬：按 ATT&CK tactic 固定排序、默认连接相邻 action、把一篇文章默认当作一个 incident flow、仅靠单个 source excerpt 作为证据。

## 最终判断

这两个项目都在做“攻击流”，但层次不同：

- Attack Flow 解决“攻击流如何标准表达和交换”；
- FlowViz 解决“如何快速从文章生成一张好看的攻击流图”；
- ARGUS 解决“如何从不完整情报中形成可追溯、可审阅、可补全的攻击过程研判”。

对 ARGUS 最合理的方向不是替换，而是：**以 ARGUS 作为内部证据化领域模型，以 Attack Flow 作为外部交换和可视化兼容层，以 FlowViz 作为交互体验参考。**
