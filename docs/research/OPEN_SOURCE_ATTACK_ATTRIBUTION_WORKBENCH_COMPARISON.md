# ARGUS 攻击链归因工作台：开源项目相似度与前端借鉴研究

> 研究对象：ARGUS 当前“输入威胁报告、告警、IOC 或文件 → 综合分析 → 攻击路径搜索与还原 → 缺失路径补全与下一步预测 → 知识图谱及攻击阶段泳道 → 节点与来源详情 → 处置建议 → 可解释归因”的桌面端工作流。  
> 目标用户：SOC 二线分析员、应急响应人员。  
> 数据边界：仅使用公开威胁情报。  
> 来源边界：只采用项目官方仓库、官方文档、官方演示与官方发布说明。  
> 最后核对：2026-07-27

## 1. 结论先行

如果必须只说一个有名的开源项目，ARGUS 当前模式与 **OpenCTI** 最相似：两者都以威胁知识图谱为底座，把报告、可观测对象、攻击技术、组织和来源关联起来，并通过调查图谱、右侧详情、Case/Report 和导出完成研判闭环。OpenCTI 官方把自身定义为管理 CTI 知识与可观测对象的平台，强调技术与非技术情报、主来源、置信度、关系及推断的统一表达。[OpenCTI 官方仓库](https://github.com/OpenCTI-Platform/opencti)

但从完整产品形态看，更准确的结论是：

> **ARGUS ≈ OpenCTI 的调查工作流 + MITRE/CTID Attack Flow 的行为路径语义 + CTID Technique Inference Engine 的补全/预测表达 + Timesketch/DFIR-IRIS 的事件还原与响应叙事。**

ARGUS 不应做成“缩小版 OpenCTI”。它真正能拉开价值差异的部分，是把不完整输入直接转化为四个可操作结果：

1. 哪些攻击步骤已经在输入中出现；
2. 哪些缺失步骤是用公开情报补全的；
3. 攻击者接下来最可能做什么；
4. SOC 或应急人员现在应优先查什么、封什么、保全什么证据。

目前没有一个被比较项目把这四点在同一结果页里作为主叙事完整实现。OpenCTI 擅长知识与证据，Attack Flow 擅长路径结构，TIE 擅长相关技术预测，Timesketch 和 DFIR-IRIS 擅长事件调查；ARGUS 的机会是把它们收敛成一条结果导向的研判链路。

## 2. 比较口径

为避免把“知识库”“攻击流程绘图工具”和“应急案件系统”混为一谈，本研究分别比较两类相似度：

- **平台工作流相似度**：输入、分析、图谱调查、证据来源、处置/报告能否形成连续工作流；
- **关键能力相似度**：攻击路径、分支、路径补全、下一步预测和防守落点的表达是否相似。

“相似”不代表应该照搬。以下排序是对 ARGUS 当前产品模式的匹配程度判断，不是对项目成熟度或能力强弱的排名。

## 3. 平台工作流相似度排序

| 排名 | 项目 | 与 ARGUS 相似的核心 | 明显缺口 | 判断 |
|---|---|---|---|---|
| 1 | OpenCTI | 文件导入工作台、知识图谱、调查扩展、来源与置信度、Case/Report、导出 | 不以自动攻击路径还原和下一步预测为单页核心 | 整体骨架最相似 |
| 2 | IntelOwl | 文件/IOC 扫描、多分析器聚合、可视化器、Pivot、分支式 Investigation | 不是成熟的攻击链语义或归因平台 | 输入与分析交互最相似 |
| 3 | Yeti | CTI 与 DFIR 桥接、批量 IOC、实体/可观测对象 Threat Graph、自动分析 | 响应处置和路径叙事较弱 | 数据关联目标相似 |
| 4 | MISP | Event、IOC、Galaxy、自动关联、相关图、事件报告和导出 | 页面偏数据管理；图易密集；不负责路径预测 | 情报事件和相关图相似 |
| 5 | Timesketch | 文件导入、搜索、上下文查询、时间线、分析器、调查 Story | 主要面向终端/日志时间线，不是 CTI 知识图谱 | 路径还原的调查方式相似 |
| 6 | DFIR-IRIS | 案件、IOC、资产、证据、树状时间线、图、报告导出 | 偏人工案件管理，CTI 关联和预测较弱 | 下半页响应叙事相似 |
| 7 | TheHive | 告警到 Case、Observable、TTP、任务、时间线、报告 | 强调协作、任务与案件生命周期；当前 v5 也不宜简单视为纯开源参照 | 邻近的 SOC/IR 产品 |

### 3.1 第一名：OpenCTI

OpenCTI 的 Analyst Workbench 在文件导入后由连接器识别实体，分析员先在草稿空间中审核、增删和修改，只有点击验证后才写入知识库。这种“机器识别结果先进入待审空间”的产品语义，很适合 ARGUS 区分本次观测、公开情报补全和算法预测。[OpenCTI Analyst Workbench](https://docs.opencti.io/latest/usage/workbench/)

OpenCTI 的 Investigation 允许从任何实体或关系进行 Pivot。选中节点后显示右侧详情；节点徽标给出尚未显示的关联实体数量；展开时可限定实体和关系类型；图谱变得无用时可回退最近十次展开。它还支持把调查导出为 PDF、图片或 STIX，或转入 Incident Response、Report 等容器。[OpenCTI Pivot and investigate](https://docs.opencti.io/latest/usage/pivoting/)

OpenCTI 还强调所有知识回到主来源：Report 是知识提取入口，实体、关系、置信度、首次/末次出现等信息与报告、MISP Event 等来源相连；平台也允许从已有关系推断新关系。[OpenCTI 官方仓库](https://github.com/OpenCTI-Platform/opencti)

这与 ARGUS 的“真实知识图谱 + 源报告 + 可解释归因路径”高度接近。区别是 OpenCTI 更像通用 CTI 操作系统，而 ARGUS 应是面向一次告警或报告的专用研判产品。

### 3.2 第二名：IntelOwl

IntelOwl 支持对文件和 IP、域名、URL、Hash 等可观测对象执行多个分析器，通过 GUI 发起分析，并用 Visualizer 把多个分析结果聚合为自定义表达。它还提供 Playbook、Pivot、Ingestor 和 Investigation：Pivot 可以从一个分析结果选择字段发起下一次分析，多个 Job 会以分支形式连入同一个 Investigation。[IntelOwl 官方仓库](https://github.com/intelowlproject/IntelOwl)

官方 GUI 文档展示了三种 Pivot：从可视化结果中的字段继续分析、从 Investigation 中的 Job 重新分析、由 Playbook 条件自动触发后续 Job。Investigation 是多个分析 Job 的上层容器，允许点击 Job 查看结果或移除分支。[IntelOwl Usage：Pivots、Visualizers、Investigations](https://intelowlproject.github.io/docs/IntelOwl/usage/)

因此，ARGUS 的“输入文件/情报/告警后综合分析”和分支扩展体验与 IntelOwl 很接近。可借鉴的是输入与结果的连续 Pivot，不适合照搬的是把用户暴露在大量分析器名称、插件执行状态和原始报告列表里。

### 3.3 第三名：Yeti

Yeti 明确把自己定位为连接 CTI 和 DFIR 的 Forensics Intelligence 平台，目标包括批量搜索可观测对象、判断威胁性质，以及从威胁反向列出 TTP、恶意软件和 DFIR 证据。[Yeti 官方仓库](https://github.com/yeti-platform/yeti)

Yeti 的模型将数据分为 Observables、Entities 和 Indicators，并允许任意对象通过 Threat Graph 关联；Analytics 可从一个 Observable 提取或丰富出新的 Observables。它也支持从文本、文件和 URL 批量导入可观测对象。[Yeti Key Concepts](https://yeti-platform.io/docs/key-concepts/)、[Yeti API：导入 Observables](https://yeti-platform.io/docs/api/)

它与 ARGUS 的共同点是“从有限 IOC 回到威胁实体和 TTP”，但 Yeti 更像可编程关联后端，没有把路径还原、下一步预测和处置建议做成结果页主线。

### 3.4 第四名：MISP

MISP 的 Event 可承载属性、对象、Galaxy、ATT&CK、报告和分析员数据；自动关联引擎负责把重复或近似属性与其他事件连接起来，并提供 Event Graph 和 Correlation Graph。[MISP 官方功能说明](https://www.misp-project.org/features/)、[MISP 官方仓库](https://github.com/MISP/MISP)

MISP 相关图已经实现了威胁组织、工具、Taxonomy、Attribute 和 Object 多层节点；官方专门加入了大图快捷导航、快速扩展和“当前选择/悬停节点”的上下文信息面板。[MISP 相关图发布说明](https://www.misp-project.org/2017/09/18/MISP.2.4.81.released.html/)

MISP 对 ARGUS 最有价值的不是整体页面风格，而是两个局部：选中/悬停上下文面板，以及在密集图中按需扩展。MISP 的属性表格密度、图谱拥挤和后台管理感不宜复制。

### 3.5 第五名：Timesketch

Timesketch 是协作式取证时间线分析工具。Sketch 可导入 Plaso、CSV 或 JSONL 时间线；Explore 负责查询、过滤、图表和保存 View；Story 负责把保存的搜索、聚合和原始事件组织成调查叙事。[Timesketch Sketch Overview](https://timesketch.org/guides/user/sketch-overview/)、[Timesketch Basic Concepts](https://timesketch.org/guides/user/basic-concepts/)

事件行可加星、标签、评论，并发起 Context Query 查找时间邻域内的相关事件。Intelligence 视图可从事件文本识别 IOC，点击放大镜回到 Explore 搜索所有相关事件。[Timesketch Sketch Overview](https://timesketch.org/guides/user/sketch-overview/)、[Timesketch Intelligence](https://timesketch.org/guides/user/intelligence/)

ARGUS 可借鉴 Timesketch 的“原始事实视图”和“策展后的调查故事”分层，但不应把结果页改造成日志检索器。ARGUS 只有开源 CTI，不能假装拥有 Timesketch 那种受害环境遥测完整度。

### 3.6 第六名：DFIR-IRIS

DFIR-IRIS 是开源协作式事件响应平台，核心包含 Case、IOC、资产、证据、任务、时间线和报告；模块可执行 MISP、VirusTotal 等 IOC 丰富。[DFIR-IRIS 官方仓库](https://github.com/dfir-iris/iris-web)

其时间线事件可关联资产、IOC、MITRE ATT&CK 类别和来源，并分别决定是否进入 Graph 和 Summary。官方版本还引入了树状 Timeline 和子事件，以表达一个事件下面继续发生的分支。[DFIR-IRIS Client Case API](https://client.docs.dfir-iris.org/en/latest/case.html)、[DFIR-IRIS Changelog](https://docs.dfir-iris.org/2.4.21/changelog/)

IRIS 支持从调查数据生成 DOCX 或 Markdown 报告。[DFIR-IRIS Reports](https://docs.dfir-iris.org/2.4.6/operations/reports/)

它对 ARGUS 的启发是：同一事件是否进入主图、摘要或报告应该可控；时间线可以有父子层级。其任务分派、案件权限、证据库等功能会把比赛展示拖向通用 IR 系统，不应复制。

### 3.7 第七名：TheHive

TheHive 把 Case 作为调查中心，集中 Observable、Task、TTP 和 Attachment；Case 可以由告警、检测工具、MISP Event 或手工输入产生。[TheHive About Cases](https://docs.strangebee.com/thehive/user-guides/analyst-corner/cases/about-cases/)

Case Timeline 可用 Graph 或 List 显示告警发生、任务完成、IOC sighting 和 ATT&CK Pattern；Observable 还用于发现相似告警与相似 Case，并在抽屉中展示共同 Observable。[TheHive Case Timelines](https://docs.strangebee.com/thehive/user-guides/analyst-corner/cases/case-timelines/about-case-timelines/)、[TheHive About Observables](https://docs.strangebee.com/thehive/user-guides/analyst-corner/cases/observables/about-observables/)

TheHive 更适合借鉴“共同证据解释两个事件为何相似”和“攻击/响应共同时间线”，不适合照搬案件负责人、任务、SLA、协作日志等运营能力。还需注意，TheHive 5 官方发布说明明确当前 Community 版本需要注册并申请社区许可证，因此它应作为邻近产品参考，而非无条件归入纯开源项目。[TheHive 5.3 Release Notes](https://docs.strangebee.com/thehive/release-notes/release-notes-5.3/)

## 4. 关键能力最相似的项目

### 4.1 攻击路径结构：MITRE/CTID Attack Flow

Attack Flow 不是完整 CTI 平台，而是一套描述攻击者如何组合和排序攻击行为的语言与工具。它用 Action 表达具体攻击行为，用 Asset 表达受影响或作为后续前提的对象，用 Condition 与 AND/OR Operator 表达分支、成功/失败和多路径汇聚。[Attack Flow Introduction](https://center-for-threat-informed-defense.github.io/attack-flow/introduction/)、[Attack Flow Language](https://center-for-threat-informed-defense.github.io/attack-flow/language/)

这与 ARGUS 的主路径横向排开、其他节点树状延伸、下方阶段泳道高度一致。Attack Flow 官方明确认为复杂攻击不能只用技术清单表示；攻击行为之间的先后、依赖和分支才是防守决策需要理解的对象。[Attack Flow Overview](https://center-for-threat-informed-defense.github.io/attack-flow/overview/)

其 Builder 采用画布加右侧属性栏：未选中节点时显示整条 Flow 的属性，选中节点后显示该 Action 的 Technique ID、描述和来源；校验错误可从侧栏直接定位到对应节点；整图和选区均可导出图片。[Attack Flow Builder](https://center-for-threat-informed-defense.github.io/attack-flow/builder/)

Attack Flow 还提供 Tactic Table、ATT&CK Matrix、Timeline 和 Treemap 等不同 Lens，说明同一数据不应强迫一张图承担所有阅读任务。[Attack Flow Visualization](https://center-for-threat-informed-defense.github.io/attack-flow/visualization/)

### 4.2 缺失路径与下一步预测：CTID Technique Inference Engine

Technique Inference Engine（TIE）从已经观测到的 ATT&CK 技术推断相关技术，官方目标正是帮助防守者预测攻击者下一步并补足对攻击行为的理解。其公开数据包含 6,236 份 CTI 报告中的 43,899 条技术观测。[TIE 官方仓库](https://github.com/center-for-threat-informed-defense/technique-inference-engine)

TIE 的前端把输入和输出明确分开：

- 上方是 **Observed Techniques**；
- 下方是 **Predicted Techniques**；
- 预测结果可按 Rank、ID、Name 排序；
- 可按 Tactic 分组，并按推断分数、平台、攻击组织或 Campaign 过滤；
- 可导出 ATT&CK Navigator Layer 或 CSV。[TIE 官方 Web 工具](https://center-for-threat-informed-defense.github.io/technique-inference-engine/)、[CTID 对 TIE 的官方介绍](https://ctid.mitre.org/blog/2024/09/09/know-your-adversarys-next-move-with-tie/)

这比在同一张图里把预测节点混成普通节点更清楚。ARGUS 可以把 TIE 的“Observed 输入 → Ranked Prediction 输出”语法融入现有图例、节点状态和右栏，但不必增加独立预测大模块。

值得注意的是，CTID 2026 路线图已提出把 TIE 的预测模型整合进 Attack Flow。这从侧面验证了 ARGUS“已观测路径 + 补全/预测”的产品方向，但也说明产品必须严格区分已经发生与模型推荐，不能把关联预测包装成事实。[CTID 2026 Roadmap](https://ctid.mitre.org/roadmap/)

### 4.3 次要但直接的 UI 参照：Kanvas

Kanvas 知名度和成熟度低于前述项目，但它把横向移动攻击链、事件时间线、MITRE Flow Builder、D3FEND 映射和报告导出放在同一应急调查工具中，是一个直接的界面参照。[Kanvas 官方仓库](https://github.com/WithSecureLabs/Kanvas)

它说明“路径图 + 时间线 + 防守映射 + 报告”可以形成自然组合。但 Kanvas 以桌面端和 Spreadsheet of Doom 为数据中心，很多流程依赖人工填写和预先映射 ATT&CK，不能作为 ARGUS 的整体产品模板。

## 5. 最值得借鉴的前端表达

### 5.1 借 OpenCTI：把“还有什么没展开”显示在节点上

OpenCTI 在节点上显示尚未进入画布的关联数量，并允许按实体类型和关系类型选择性展开，也可以回退最近的展开操作。[OpenCTI Pivot and investigate](https://docs.opencti.io/latest/usage/pivoting/)

ARGUS 已有“一跳展开”和“全部展开直接邻居”，最合适的优化不是再加一排按钮，而是：

- 在节点角标显示“未展开 8”；
- 单击仍只选中节点；
- 右栏保留“一跳展开”和“展开直接邻居”；
- “展开直接邻居”旁用轻量 Popover 选择 IOC、工具、漏洞、TTP、组织、来源；
- 增加一个“撤销上次展开”，避免用户只能靠重置图谱恢复。

### 5.2 借 OpenCTI：选中状态应强调证据焦点，而不是只改节点颜色

OpenCTI 在调查图中保留选中节点颜色，压暗其他节点；当前右栏查看的节点用实线边框，其他多选节点用虚线边框。[OpenCTI Pivot and investigate](https://docs.opencti.io/latest/usage/pivoting/)

ARGUS 可以更克制地采用：

- 点击路径节点后，主路径保留完整亮度；
- 无关分支降低到约 35%—45% 视觉权重；
- 与该节点直接相关的来源、IOC、处置建议保持高亮；
- 右栏当前节点用实线强调，不让“选中、高亮、预测”争抢同一种颜色。

### 5.3 借 OpenCTI：右栏展示“原文证据 → 结构化节点”的映射

OpenCTI 的内容映射把原报告文本与结构化对象并置，允许从原文中识别和审核实体；其 Workbench 也强调机器抽取先审后入库。[OpenCTI Explore Knowledge Overview](https://docs.opencti.io/latest/usage/overview/)、[OpenCTI Analyst Workbench](https://docs.opencti.io/latest/usage/workbench/)

ARGUS 右栏不必成为编辑器，但应固定为三层：

1. **行为结论**：该节点在攻击中做了什么；
2. **证据锚点**：来自哪一份报告、哪一段原文或哪条告警，显示短摘录和页码/链接；
3. **系统判断**：为何映射到某个 IOC、资产、ATT&CK 技术或候选组织，状态是本次观测、情报补全还是预测。

这样用户点击图谱不是为了“看节点百科”，而是验证路径是否可信。

### 5.4 借 Attack Flow：把图谱关系分成行为、资产和条件

Attack Flow 的 Action、Asset、Condition 和 Operator 能避免所有实体都挤进同一种圆形节点。[Attack Flow Introduction](https://center-for-threat-informed-defense.github.io/attack-flow/introduction/)

ARGUS 应保持现有主路径与分支，但对节点角色做有限区分：

- 攻击行为/TTP：主路径卡片；
- 受影响资产、账号、文件、IOC：挂载在行为节点上下方的小型叶节点；
- 条件或未确认前提：窄菱形节点；
- 多路径汇聚：仅在确有 AND/OR 语义时出现，不为视觉复杂而滥用。

### 5.5 借 TIE：预测节点必须是另一种事实类型

TIE 把 Observed 和 Predicted 分为两个区域，再对预测结果排序和过滤。[TIE 官方 Web 工具](https://center-for-threat-informed-defense.github.io/technique-inference-engine/)

ARGUS 无需新增区域，但应统一现有视觉语法：

| 状态 | 图中表达 | 右栏必须回答 |
|---|---|---|
| 本次观测 | 实线、实色、证据图标 | 在哪一条输入中看到 |
| 公开情报补全 | 蓝色虚线、补全标记 | 补全依据是哪份报告/哪条历史路径 |
| 下一步预测 | 橙色点划线、概率/等级 | 输入了哪些已观测技术、为何排在这里、需查什么才能确认 |
| 已查询未发现 | 灰色、否定标记 | 查过什么数据源、没有看到什么 |

不要只用百分比。概率只能表达模型排序，不能替代事实状态。

### 5.6 借 Timesketch：图负责因果，泳道负责时间和阶段

Timesketch 把 Explore 的原始事件检索和 Story 的调查叙事分开；Attack Flow 也对同一 Flow 提供 Graph、Tactic Table 和 Timeline 等 Lens。[Timesketch Basic Concepts](https://timesketch.org/guides/user/basic-concepts/)、[Attack Flow Visualization](https://center-for-threat-informed-defense.github.io/attack-flow/visualization/)

这支持 ARGUS 当前“上方真实图谱、下方可折叠攻击阶段泳道”的设计。两者不应是互相替代的切换模式：

- 图谱回答“什么导致什么、在哪里分支、哪些实体相互支持”；
- 泳道回答“处于哪个攻击阶段、先后顺序是什么、当前进展到哪里”；
- 点击任一视图，同步高亮另一视图中的同一节点；
- 泳道折叠后保留阶段名称、节点数量、已观测/补全/预测数量。

### 5.7 借 DFIR-IRIS：控制哪些事件进入主图和摘要

DFIR-IRIS 的 Timeline Event 可分别设置是否进入 Graph 与 Summary，并支持父子事件。[DFIR-IRIS Client Case API](https://client.docs.dfir-iris.org/en/latest/case.html)、[DFIR-IRIS Changelog](https://docs.dfir-iris.org/2.4.21/changelog/)

ARGUS 无需给用户暴露编辑开关，但算法输出应有同样的筛选逻辑：

- 只有改变攻击阶段、资产控制权或防守决策的节点进入主路径；
- 解释来源、标签、同源 IOC 等留在分支或右栏；
- 归因证据只在确实支持候选组织时进入末尾归因链路。

## 6. 不适合照搬的部分

### 6.1 不要照搬 OpenCTI 的通用知识库复杂度

OpenCTI 面向长期 CTI 运营，需要大量实体页、关系编辑、权限、Case、Workflow、Dashboard 和 STIX 管理。ARGUS 的核心用户打开页面是为了处理一次攻击线索，不是维护全球威胁知识库。自由力导向全量图、层层 Tab 和关系编辑会破坏当前一页式研判叙事。

### 6.2 不要照搬 Attack Flow Builder 的手工画图模式

Attack Flow Builder 是拖拽编辑器，需要用户创建 Action、填写属性并连线。[Attack Flow Builder](https://center-for-threat-informed-defense.github.io/attack-flow/builder/)

ARGUS 的卖点是自动从报告、告警和 IOC 中得到路径。允许分析员审核或排除算法建议是必要的，但让用户手工画流程会把产品降级成流程图工具。

### 6.3 不要把所有节点强制映射为 ATT&CK

Attack Flow 官方允许自定义行为，不要求所有 Action 都对应 ATT&CK；Condition 和 Asset 也承担 ATT&CK 技术无法表达的上下文。[Attack Flow Introduction](https://center-for-threat-informed-defense.github.io/attack-flow/introduction/)

ARGUS 应保留“具体攻击行为”和“ATT&CK 映射”两个字段。无法可靠映射时显示原行为，不要为了图整齐制造虚假精确。

### 6.4 不要照搬 MISP 的数据密度

MISP 的优势是高密度结构化情报和自动关联，代价是属性表格、标签、对象和图谱容易同时竞争注意力。ARGUS 应让主路径保持稳定，其他 IOC 和来源按需展开，不能默认把全部相关数据摊在画布上。

### 6.5 不要照搬 Timesketch 的完整日志工作台

Timesketch 的搜索、时间过滤和上下文查询建立在受害环境日志时间线上。[Timesketch Search Query Guide](https://timesketch.org/guides/user/search-query-guide/)

ARGUS 当前只有开源威胁情报。可以展示公开报告里的时间、攻击活动顺序和合成告警，但不能用过细的主机事件时间线暗示平台掌握了并不存在的 EDR、SIEM 或 Exchange 日志。

### 6.6 不要照搬 TheHive/IRIS 的案件运营能力

任务分派、负责人、SLA、权限、评论、证据托管和案件状态对真实 IR 团队有价值，但用户已经明确处置建议只需阅读和导出。加入这些能力会稀释路径搜索、还原和处置建议的核心价值。

### 6.7 不要把“规则推断”“共现推荐”和“下一步预测”混成一个词

OpenCTI 的 Inference 是由已有关系得到新关系；TIE 是从已观测 ATT&CK 技术推荐相关技术；Attack Flow 是描述攻击行为的结构。三者都不能自动证明某一步已经发生。[OpenCTI 官方仓库](https://github.com/OpenCTI-Platform/opencti)、[TIE 官方介绍](https://ctid.mitre.org/blog/2024/09/09/know-your-adversarys-next-move-with-tie/)、[Attack Flow Language](https://center-for-threat-informed-defense.github.io/attack-flow/language/)

ARGUS 必须在数据和界面上区分：

- 路径还原：输入中实际出现；
- 历史补全：公开资料中该攻击模式通常包含；
- 下一步预测：基于当前技术组合推测；
- 组织归因：基于多维证据判断候选对手。

## 7. 对 ARGUS 最克制的五项改进

以下建议尽量复用现有主图、泳道、右栏、处置和归因区域，不增加新的大模块。

### P0：统一“观测—补全—预测”视觉语法

在现有图例、节点和边上统一三态，不再让不同区域各自发明状态颜色。点击任一补全或预测节点时，右栏必须出现“依据”和“升级为确认还缺什么”。这是 ARGUS 区别于普通图谱产品的第一核心表达。

### P0：把右栏改成证据验证器

保留节点详情，但信息顺序固定为“行为结论 → 原文/告警证据 → 系统映射理由 → 关联处置”。用户点击节点后应能在数秒内回答“这一步凭什么在图上”，而不只是看到节点属性。

### P0：在现有展开交互中加入“未展开 N”和撤销

不增加新的工具栏。把 OpenCTI 的未展开数量放进节点角标，继续使用右栏的一跳/直接邻居展开，并补一个撤销上次展开。主路径坐标保持锁定，新增分支只在上下区域生长。[OpenCTI Pivot and investigate](https://docs.opencti.io/latest/usage/pivoting/)

### P1：让处置建议反向高亮路径

现有处置响应方案无需扩成任务系统。每条建议只增加一个“关联步骤”入口：

- 点击“阻断外联 SMB”时，高亮利用漏洞、外联 SMB、凭据泄露三个节点；
- 点击“排查异常 EWS”时，高亮预测或补全的 Exchange 分支；
- 导出时保留建议与路径节点的对应关系。

这样图的商业价值从“画出攻击过程”变成“说明为什么现在要做这项动作”。Attack Flow 的 Defensive Posture 指南也把路径用于识别检测缺口、防御瓶颈、关键资产和控制覆盖。[Attack Flow Defensive Posture](https://center-for-threat-informed-defense.github.io/attack-flow/usage_guides/defensive-posture/)

### P1：归因区增加一条反证，不再增加更多卡片

归因仍放在最下方。候选组织卡除支持证据外，只增加一条“主要限制/反证”，例如“漏洞已公开，单一漏洞不能独占归因”或“基础设施可能是被入侵第三方”。点击支持路径继续打开组织知识图谱并高亮匹配路径。这样能提升可信度，又不会让归因重新抢占主展示。

## 8. 建议的产品定位话术

不建议对外说“我们做了一个比 OpenCTI 更简单的图谱”或“自动画 Attack Flow”。更准确的表达是：

> ARGUS 是面向 SOC 二线和应急响应的攻击路径研判产品。它从不完整的公开威胁情报、告警、IOC 或文件出发，区分本次观测、历史补全和下一步预测，还原带分支的攻击路径，并把每个路径判断连接到来源证据与处置建议；组织归因作为末端结论提供可解释证据链。

一句话对标：

> **OpenCTI 负责告诉用户“这些威胁知识如何相关”，Attack Flow 负责告诉用户“攻击行为如何推进”，TIE 负责提示“还可能缺什么、接下来可能发生什么”；ARGUS 应把三者收敛为“现在该如何研判和处置”。**

## 9. 讨论时最值得看的官方页面

1. [OpenCTI Investigation：节点未展开数量、选择性扩展、右栏、撤销与导出](https://docs.opencti.io/latest/usage/pivoting/)
2. [OpenCTI Analyst Workbench：机器识别结果先审后入库](https://docs.opencti.io/latest/usage/workbench/)
3. [Attack Flow Builder：主画布、右侧属性栏、复杂分支和选区导出](https://center-for-threat-informed-defense.github.io/attack-flow/builder/)
4. [Attack Flow 复杂行为语义：Action、Asset、Condition、AND/OR](https://center-for-threat-informed-defense.github.io/attack-flow/introduction/)
5. [TIE Web 工具：Observed 与 Predicted 的清晰分离和排序过滤](https://center-for-threat-informed-defense.github.io/technique-inference-engine/)
6. [Timesketch：Explore、Context Query 与 Story](https://timesketch.org/guides/user/sketch-overview/)
7. [MISP 相关图：上下文面板与大图扩展](https://www.misp-project.org/2017/09/18/MISP.2.4.81.released.html/)
8. [DFIR-IRIS：树状时间线、子事件和报告](https://docs.dfir-iris.org/2.4.21/changelog/)

