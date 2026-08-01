# ARGUS 独立“情报图谱”页面设计研究

> 研究范围：仅讨论 ARGUS 独立“情报图谱”页面，不讨论完整攻击链工作台。  
> 产品边界：数据仅来自开源威胁情报；核心业务仍是攻击路径搜索、路径还原和处置建议。  
> 来源边界：只使用开源项目的官方文档、官方仓库、官方发布说明与源代码。  
> 最后核对：2026-07-27

## 1. 结论先行

ARGUS 的独立情报图谱页不应成为“全库关系的漂亮大图”，也不应复制一套攻击路径工作台。它最应该帮助分析员完成四件事：

1. **从一个线索开始**：输入 IP、域名、Hash、漏洞、工具、组织或报告，明确当前图谱以什么为中心；
2. **发现有价值的关联**：逐跳查看它连接过哪些报告、IOC、工具、TTP、历史活动和组织；
3. **验证关联是否可信**：点击节点或边，查看来源报告、证据摘录、时间范围、证据数量和置信度；
4. **把线索交给路径研判**：将选中的实体或关系带入“攻击路径搜索/还原”，由后者负责主路径、补全、预测和处置建议。

如果只参考一个项目，页面的信息架构最值得借鉴 **OpenCTI Investigation / Report Knowledge Graph**；如果看跨报告 IOC 关联任务，最值得借鉴 **MISP Correlation Graph**；如果看路径分支、因果和时间表达，则借鉴 **MITRE/CTID Attack Flow**，但不能把独立情报图谱改成 Attack Flow Builder。

一句话定位：

> **情报图谱页负责“发现并验证关系”，攻击路径页负责“还原攻击并指导处置”。**

## 2. ARGUS 当前页面审计

当前实现位于 `app/components/LibraryViews.tsx` 的 `FullGraphView`，导航入口和图谱上下文由 `app/ArgusApp.tsx` 生成，画布由 `app/NetworkGraph.tsx` 渲染。

当前页面已有的结构：

- 顶部：返回、标题、节点/关系数量和“真实图谱快照”标签；
- 左栏：节点数、关系数、高置信节点数、实体类型统计；
- 中间：力导向图，支持缩放、重置、节点拖动和节点选择；
- 右栏：选中节点的名称、状态、描述、类型、置信度和所属事件。

当前从侧边导航直接进入时，会选取 `source_count` 最高的三个实体为根，构造最多 48 个节点的子图；从搜索或实体页进入时，则以该实体为根构造最多 42 个节点的子图。

因此目前页面的主要问题不是“图不够复杂”，而是缺少清晰任务：

- 用户不知道三个默认根为什么被选中；
- 左栏只有统计，没有真正控制画布；
- 只能选择节点，不能选择边；
- 右栏说明“它是什么”，但不能说明“为什么相连”；
- 图谱是一次性快照，不能按需展开、撤销和改变调查范围；
- 已有数据中的关系证据、首次/末次出现、证据数量和来源报告没有进入页面；
- 页面与攻击路径搜索之间没有明确交接动作。

好消息是，当前 `Snapshot` 已经包含实现关键交互所需的数据：

- `Relationship` 有关系类型、置信度、证据数量、首次/末次出现和状态；
- `Evidence` 通过 `relationship_id` 关联报告、出处、摘录、发布方和日期；
- `Entity` 有首次/末次出现、来源数、事件和来源引用；
- `NetworkGraph` 已支持隐藏邻居数量、选中/高亮和稳定布局所需的基础能力。

这意味着优先改进主要是信息架构和交互，不需要先引入新的图数据库或大型后端模块。

## 3. 开源项目的图谱页真正帮助分析员完成什么

### 3.1 OpenCTI：围绕实体探索、验证和沉淀知识

OpenCTI 把所有数据组织为知识图谱。Investigation 的核心任务不是展示全库，而是让分析员从实体或关系开始 Pivot，选择关联对象、逐步扩展，并把调查结果导出或沉淀为 Report、Incident Response 等容器。[OpenCTI Pivot and investigate](https://docs.opencti.io/latest/usage/pivoting/)

在 Report 的 Knowledge 页，Graph View 用节点表示 STIX 对象、用边表示关系；直接关系为实线，推断关系为点线。页面提供图形塑形、力参数、选择、筛选、时间范围、创建和编辑工具。[OpenCTI Analysis：Graph View](https://docs.opencti.io/latest/usage/exploring-analysis/)

OpenCTI 还把不同问题拆成不同 Lens：

- Graph：对象之间如何关联；
- Timeline：知识在时间上如何发生；
- Correlation：哪些其他报告通过重要实体与当前报告相关；
- Matrix：报告中的攻击技术落在哪些 ATT&CK 位置。[OpenCTI Analysis](https://docs.opencti.io/latest/usage/exploring-analysis/)

图谱页真正完成的任务：

1. 从一个实体继续探索关联；
2. 验证一个关系是直接关系还是推断关系；
3. 按类型、关系和时间控制调查范围；
4. 找到与当前主题相关的其他报告；
5. 将有价值的调查结果沉淀或导出。

### 3.2 MISP：解释一个事件，并发现跨事件复用的 IOC

MISP 区分两个图谱任务：

- **Event Graph**：展示同一 Event 内对象和属性之间的关系，可编辑对象、属性和关系；它的目标是讲清一次事件内部发生了什么。[MISP Event Graph 发布说明](https://www.misp-project.org/2018/03/23/MISP.2.4.89.released.html/)、[MISP 官方概念速查](https://www.misp-project.org/misp-training/cheatsheet.pdf)
- **Correlation Graph**：把 Event、Attribute、Object、Galaxy、Taxonomy 等跨事件关联起来，帮助分析员发现同一 IOC、工具、组织或上下文曾在哪里出现。[MISP 图谱发布说明](https://www.misp-project.org/2017/09/18/MISP.2.4.81.released.html/)、[MISP 官方功能说明](https://www.misp-project.org/features/)

MISP 为大图加入快捷导航、快速扩展和当前选择/悬停节点的上下文信息面板。[MISP 2.4.81 图谱发布说明](https://www.misp-project.org/2017/09/18/MISP.2.4.81.released.html/)

图谱页真正完成的任务：

1. 查看 IOC、对象、工具和组织是否在其他 Event 中出现；
2. 发现不同报告/事件之间共享的技术线索；
3. 在事件内部组织“谁与谁有什么关系”；
4. 从选中节点快速查看上下文而不离开画布。

MISP 2026 年开始把 Correlation Graph 集成进新的 Insight UI，并尝试用 Pivotick 替换旧 Event Graph，但官方仍将该替换描述为早期概念验证，不能把未完成交互当成熟范式照搬。[MISP 2.5.42 发布说明](https://www.misp-project.org/2026/06/22/misp.2.5.43.released.html/)、[MISP 2.5.43 发布说明](https://www.misp-project.org/2026/06/22/misp.2.5.42.release.html/)

### 3.3 MITRE/CTID Attack Flow：理解攻击行为如何推进和分支

Attack Flow 的核心任务不是发现任意实体关联，而是表达攻击行为的顺序、前置条件、成功/失败分支、汇聚关系和对资产的影响。它用 Action、Asset、Condition 与 AND/OR Operator 构建行为流。[Attack Flow Introduction](https://center-for-threat-informed-defense.github.io/attack-flow/introduction/)、[Attack Flow Language](https://center-for-threat-informed-defense.github.io/attack-flow/language/)

Builder 采用画布加右侧属性栏：选中节点后在右栏显示名称、Technique ID、描述和来源；通过锚点连接行为；校验问题出现在侧栏，点击问题可定位到对应节点；整图或选区可以导出图片。[Attack Flow Builder](https://center-for-threat-informed-defense.github.io/attack-flow/builder/)

Attack Flow 还允许同一数据转成 ATT&CK Navigator、Tactic Table、Matrix、Timeline 和 Treemap，以回答不同问题。[Attack Flow Visualization](https://center-for-threat-informed-defense.github.io/attack-flow/visualization/)

图谱页真正完成的任务：

1. 说明攻击步骤之间的因果和先后；
2. 说明一次攻击为什么出现分支；
3. 表达失败后的替代路径和多条件汇聚；
4. 说明某个行为影响了什么资产；
5. 生成适合报告和沟通的路径视图。

这部分能力属于 ARGUS 的攻击路径页。独立情报图谱只能借用“高亮路径、右栏检查、时间 Lens 和选区导出”，不应承担完整 Attack Flow 编辑。

### 3.4 Yeti：从 IOC 进入威胁实体，再从威胁实体反查证据

Yeti 把 Observables、Entities 和 Indicators 组织为 Threat Graph，允许任意对象建立关系；其目标包括批量搜索 IOC、判断威胁性质，以及从威胁反向列出相关 TTP、恶意软件和 DFIR 证据。[Yeti 官方仓库](https://github.com/yeti-platform/yeti)、[Yeti Key Concepts](https://yeti-platform.io/docs/key-concepts/)

图谱页真正完成的任务：

1. 从 IP、域名、Hash 等技术线索上钻到工具、Campaign 和组织；
2. 从攻击组织反向获得相关 IOC、工具和 TTP；
3. 通过分析插件继续丰富当前 Observable。

Yeti 的前端图谱交互文档不如 OpenCTI 完整，因此它更适合用来确认 ARGUS 的数据探索方向，不宜作为具体视觉模板。

### 3.5 Timesketch：在时间邻域里寻找上下文

Timesketch 不是 CTI 知识图谱，但其 Explore 允许从事件发起 Context Query，寻找该时间点前后发生的其他事件；Story 再把保存的搜索、聚合和原始事件组织为调查叙事。[Timesketch Sketch Overview](https://timesketch.org/guides/user/sketch-overview/)、[Timesketch Basic Concepts](https://timesketch.org/guides/user/basic-concepts/)

对 ARGUS 的价值仅限于时间 Lens：当开源报告确实给出时间时，可按首次出现、末次出现或活动日期查看关系演进。不能模拟受害环境的高精度日志时间线。

## 4. 值得借鉴的图谱交互

### 4.1 画布：稳定的调查空间，不是不断重排的动画

OpenCTI 通过选中节点保留颜色、压暗其他实体来保持调查焦点；当前右栏查看节点和其他多选节点使用不同边框表达。[OpenCTI Pivot and investigate](https://docs.opencti.io/latest/usage/pivoting/)

ARGUS 应采用：

- 选中节点、切换 Inspector Tab、查看来源时不改变任何节点坐标；
- 筛选默认先“压暗”，而不是立刻删除节点并重排；
- 只有明确点击“仅显示筛选结果”或新增节点时才重新布局；
- 根节点固定，用户拖动过的节点保持固定；
- 新展开分支从父节点附近生长，避免整张图洗牌。

这对 ARGUS 尤其重要，因为当前数据量不大，分析连续性比炫目的物理模拟更重要。

### 4.2 筛选：围绕分析问题，而不是暴露所有 STIX 字段

OpenCTI Report Graph 提供类型、关系、时间等筛选；Correlation View 单独用于找相关报告。[OpenCTI Analysis](https://docs.opencti.io/latest/usage/exploring-analysis/)

ARGUS 左栏应从统计栏改成四组默认筛选：

1. **实体类型**：IOC、漏洞、工具、恶意软件、TTP、历史活动、组织、报告；
2. **关系类型**：使用、利用、控制、投递、通信、归属、来源于；
3. **证据强度**：证据数、置信度、直接关系/推断关系；
4. **时间范围**：首次/末次出现或报告日期。

高级 STIX 属性、标签和作者不应默认铺开。来源范围应放在画布顶部作为强语义开关：

- 当前报告内；
- 跨报告知识库。

这对应 MISP 的 Event Graph 与 Correlation Graph 两种任务，但无需真的做成两套页面。

### 4.3 布局：只保留两种语义布局

OpenCTI 提供多种塑形和力参数，适合专家自由分析；Attack Flow Builder 允许手工排布行为节点。[OpenCTI Analysis](https://docs.opencti.io/latest/usage/exploring-analysis/)、[Attack Flow Builder](https://center-for-threat-informed-defense.github.io/attack-flow/builder/)

ARGUS 不应提供大量布局算法和物理参数。建议只保留：

- **中心辐射**：单个根实体的邻域探索，默认布局；
- **关系流向**：以选中实体为左侧起点，按关系方向向右展开，适合查看基础设施、工具、TTP 到组织的关联。

只有从攻击路径页面带入明确路径时，才临时使用“主路径固定、分支上下展开”的路径布局。不要在独立图谱中设置一个与攻击路径页重复的常驻“攻击链模式”。

### 4.4 展开：显示代价、限定范围、可以撤销

OpenCTI 在节点徽标中显示尚未展示的关联数量；双击或按钮展开前，可以选择实体和关系类型；展开过多时支持回退最近十次操作。[OpenCTI Pivot and investigate](https://docs.opencti.io/latest/usage/pivoting/)

MISP 也把快速扩展和上下文面板作为大图导航的核心。[MISP 2.4.81 图谱发布说明](https://www.misp-project.org/2017/09/18/MISP.2.4.81.released.html/)

ARGUS 应采用：

- 节点角标显示 `+N` 个未展开直接邻居；
- 单击只负责选择，避免选择与展开冲突；
- 右栏提供“展开一跳”；
- `展开一跳` 旁的菜单允许限定实体类型和关系类型；
- 明确显示“将增加 8 节点 / 11 关系”；
- 全局只需“撤销上次展开”和“回到初始范围”。

“一键展开整个子树”在当前独立页面不合适。开源情报图谱高度互联，所谓子树通常不是树，容易瞬间制造不可读毛球。

### 4.5 右侧检查器：节点和关系必须同等重要

OpenCTI 点击实体后在右栏查看详情；Attack Flow 右栏随当前选中对象切换属性；MISP 上下文面板快速显示选中和悬停节点。[OpenCTI Pivot and investigate](https://docs.opencti.io/latest/usage/pivoting/)、[Attack Flow Builder](https://center-for-threat-informed-defense.github.io/attack-flow/builder/)、[MISP 2.4.81 图谱发布说明](https://www.misp-project.org/2017/09/18/MISP.2.4.81.released.html/)

ARGUS 当前只检查节点，而真正需要解释的是关系。建议右栏有两种状态：

**选中节点**

- 名称、类型、别名和一句话描述；
- 首次/末次出现、来源数；
- 当前画布内入边/出边数量；
- 相关报告；
- 操作：展开一跳、固定/释放位置、以此重新居中、进入路径研判。

**选中关系**

- `A —[关系类型]→ B`；
- 置信度、证据数量、首次/末次出现；
- 关系状态：直接提取、规则推断或人工确认；
- 来源报告列表；
- 每份报告的证据摘录、位置和发布者；
- 操作：仅看此关系相关节点、把两端实体带入路径研判。

Inspector 建议只有三个 Tab：

- 概览；
- 证据；
- 关联。

不要增加属性、评论、任务、权限、历史修改等企业后台 Tab。

### 4.6 证据：直接关系和推断关系不能只靠颜色

OpenCTI 在 Report Graph 中把直接关系画成实线、推断关系画成点线，并让知识始终可回溯到 Report 或 External Reference。[OpenCTI Analysis](https://docs.opencti.io/latest/usage/exploring-analysis/)

ARGUS 应在边上统一表达：

- 实线：来源报告直接支持；
- 虚线：规则或图约束推断；
- 点划线：算法候选，尚未进入攻击路径结论；
- 选中边后，右栏显示对应原文摘录和报告；
- 不能只显示“置信度 86%”，还要显示“3 份报告 / 4 条证据”。

图谱页不应使用攻击路径页的“已观测/补全/预测”全部语义。独立知识图谱更适合表达“直接、推断、候选”；当关系进入一次具体攻击研判后，再由路径页表达是否本次观测或下一步预测。

### 4.7 时间：作为 Lens，不作为默认主画布

OpenCTI Timeline View 用于报告包含明确时间的攻击或 Campaign；Graph 也可以用时间范围查看报告知识的演进。[OpenCTI Analysis](https://docs.opencti.io/latest/usage/exploring-analysis/)

ARGUS 可在画布顶部提供：

- 关系图；
- 时间线。

时间线只显示有可靠 `first_seen`、`last_seen` 或报告日期的实体与关系；没有日期的对象进入“时间未知”分组。不要推算精确攻击发生时间，也不要模仿 Timesketch 的终端事件粒度。

### 4.8 路径：图谱页只负责选种子和高亮，不负责处置

Attack Flow 的画布非常适合表示 Action、Condition、Asset 和分支，但它的工作是行为流建模。[Attack Flow Introduction](https://center-for-threat-informed-defense.github.io/attack-flow/introduction/)

ARGUS 图谱页应提供：

- 单选节点：`以此为线索研判攻击路径`；
- 多选节点/选中边：`用已选 2 个实体研判路径`；
- 从路径页进入图谱：高亮已有路径，其他知识作为可展开背景。

处置建议、路径补全和下一步预测继续留在攻击路径页。否则两个页面会再次功能重叠。

## 5. 不适合 ARGUS 的交互

### 5.1 OpenCTI 的关系编辑和全量知识运营

OpenCTI Investigation 支持直接创建关系，Report Graph 还支持知识创建与编辑。[OpenCTI Pivot and investigate](https://docs.opencti.io/latest/usage/pivoting/)、[OpenCTI Analysis](https://docs.opencti.io/latest/usage/exploring-analysis/)

ARGUS 当前是比赛展示和只读公开情报分析产品。独立图谱只需探索、验证和导出，不应加入关系创建、多人协作、权限、审核流和知识入库。

### 5.2 OpenCTI 的大量布局和力参数

允许用户调斥力、连线长度、重力和多种布局会增加控制感，但并不提升研判价值。ARGUS 应由产品选择稳定默认值，只给两种有业务含义的布局。

### 5.3 MISP 的默认全量相关图

跨 Event 相关性很容易形成高度互联的大图。ARGUS 应按种子、跳数、实体类型、关系类型和来源范围逐步展开，不能默认加载“全量真实关系”来证明数据很多。

### 5.4 MISP Event Graph 的直接编辑

MISP Event Graph 允许编辑对象、属性和关系，适合情报生产。[MISP Event Graph 发布说明](https://www.misp-project.org/2018/03/23/MISP.2.4.89.released.html/)

ARGUS 的图谱页是消费和研判界面，不应让用户在画布里拖线创建情报事实。

### 5.5 Attack Flow Builder 的空白画布和手工连线

Attack Flow Builder 的目标是编写 Flow，而 ARGUS 的目标是从输入自动得到路径。[Attack Flow Builder](https://center-for-threat-informed-defense.github.io/attack-flow/builder/)

可以借右栏、分支语义和选区导出，但不能把情报图谱变成流程图软件。

### 5.6 过度依赖 Hover 和键盘快捷键

MISP 的快捷键适合高频专家，但比赛演示和低学习成本产品不能把关键展开、检查和返回操作藏在 Hover 或快捷键里。快捷键可以后加，显式按钮必须先存在。

### 5.7 高精度活动时间线

ARGUS 只有开源情报。时间 Lens 应忠实显示报告日期、首次/末次公开出现和历史活动日期，不能表现成受害主机遥测时间线。

## 6. ARGUS 推荐页面结构

### 6.1 页面线框

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ 返回 / 情报图谱   [搜索实体、IOC、报告…]   当前报告内 | 跨报告知识库   导出 │
│ 根实体：CVE-2023-23397 ×   APT28 ×   关系图 | 时间线     42 节点 / 58 关系  │
├───────────────┬───────────────────────────────────────┬─────────────────────┤
│ 筛选          │ 画布                                  │ 节点 / 关系检查器   │
│               │                                       │                     │
│ 实体类型      │ 稳定根节点                            │ 概览 证据 关联      │
│ 关系类型      │ 逐跳展开                              │                     │
│ 证据强度      │ 选中焦点、其他压暗                    │ 来源报告与原文摘录  │
│ 时间范围      │ 实线/虚线/点划线证据状态              │ 一跳展开 / 重新居中 │
│               │                                       │ 进入攻击路径研判    │
│ [仅显示结果]  │  +N 未展开  [撤销展开] [回初始范围]   │                     │
└───────────────┴───────────────────────────────────────┴─────────────────────┘
```

### 6.2 P0：第一阶段必须完成

#### P0-1 明确调查种子和范围

顶部加入图内搜索、根实体 Chip，以及“当前报告内 / 跨报告知识库”范围开关。取消从 `source_count` 最高的三个实体自动制造一个无解释默认图；没有种子时用搜索空状态和最近/典型实体入口。

#### P0-2 把左栏统计改成真正筛选

节点数、关系数、高置信数移到顶部紧凑显示。左栏改为实体类型、关系类型、证据强度和时间范围。默认筛选压暗节点，用户主动选择“仅显示”后才重排。

#### P0-3 支持点击关系并展示证据

这是最高价值改进。把当前 `Evidence.relationship_id` 真正接入 Inspector，显示报告标题、出处、摘录、发布者和日期；关系详情同时显示证据数量和首次/末次出现。

#### P0-4 增加受控展开和撤销

使用 `NetworkGraph` 已有的 `hiddenNeighborCounts` 显示 `+N`，由右栏执行一跳展开；支持实体/关系类型限定，提供“撤销上次展开”和“回到初始范围”。

#### P0-5 打通“进入攻击路径研判”

节点或关系 Inspector 底部提供唯一主操作。把选中实体 ID、关系 ID 和来源范围带入攻击路径页面。图谱不显示完整处置建议。

### 6.3 P1：第二阶段增强

#### P1-1 两种稳定布局

提供“中心辐射 / 关系流向”两种布局；切换时动画短且可预测。选中、打开右栏和筛选压暗都不得重启布局。

#### P1-2 关系图 / 时间线双 Lens

时间线只使用可靠日期。切换 Lens 保留当前选择、筛选和根实体，不另开页面。

#### P1-3 多选并仅高亮连接关系

允许 Shift 多选 2—5 个实体，突出它们之间当前图中已有的连接；主操作变为“用已选实体研判攻击路径”。不在图谱页实现复杂最短路径算法编辑器。

#### P1-4 导出当前视图

导出当前筛选、当前高亮和来源摘要，而不是导出整库图。优先支持 PNG 和一页 PDF；Attack Flow Builder 的选区导出说明这种能力对报告沟通很实用。[Attack Flow Builder](https://center-for-threat-informed-defense.github.io/attack-flow/builder/)

### 6.4 P2：有余力再做

- 保存个人图谱视图；
- 键盘快捷键；
- 迷你地图；
- 框选；
- 关系路径对比；
- ATT&CK Matrix Lens。

这些功能在 OpenCTI、MISP 或 Attack Flow 中各有价值，但对当前 ARGUS“攻击路径搜索/还原/处置”主线不是必需。

## 7. 验收标准

改造后的图谱页应能用一个公开情报案例完成以下演示：

1. 搜索 `CVE-2023-23397`，以其作为唯一根实体；
2. 默认只看当前报告内的漏洞、工具、TTP、基础设施和组织关系；
3. 点击“利用”关系，在右栏看到对应报告和原文摘录；
4. 切换到跨报告知识库，节点角标提示还有若干邻居；
5. 只展开历史活动和组织关系，主图不整体乱跳；
6. 撤销一次错误展开；
7. 多选漏洞与候选组织，点击“进入攻击路径研判”；
8. 攻击路径页接收这些线索并负责还原、补全、预测和处置建议。

若用户只能说“这个图节点很多”，页面仍然失败；若用户能说“我知道这条关系来自哪份报告，也知道下一步该拿哪些线索去做路径研判”，页面才完成了产品任务。

## 8. 优先参考的官方页面

1. [OpenCTI Investigation：选中、右栏、隐藏邻居、选择性扩展和撤销](https://docs.opencti.io/latest/usage/pivoting/)
2. [OpenCTI Report Knowledge：Graph、Timeline、Correlation、Matrix 和时间筛选](https://docs.opencti.io/latest/usage/exploring-analysis/)
3. [MISP Correlation Graph：跨 Event 的 Attribute、Object、Galaxy 关联与上下文面板](https://www.misp-project.org/2017/09/18/MISP.2.4.81.released.html/)
4. [MISP Event Graph：同一事件内的对象、属性和关系](https://www.misp-project.org/2018/03/23/MISP.2.4.89.released.html/)
5. [Attack Flow Builder：画布、Inspector、校验定位和选区导出](https://center-for-threat-informed-defense.github.io/attack-flow/builder/)
6. [Attack Flow Introduction：Action、Asset、Condition 和分支](https://center-for-threat-informed-defense.github.io/attack-flow/introduction/)
7. [Yeti Threat Graph 数据模型](https://yeti-platform.io/docs/key-concepts/)
8. [Timesketch Explore 与 Context Query](https://timesketch.org/guides/user/sketch-overview/)

