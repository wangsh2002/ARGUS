# 开源威胁情报项目的攻击组织画像前端与信息架构研究

> 研究目标：为 ARGUS 新增“攻击组织 / 威胁行为体画像”前端提供可落地的设计依据。  
> 研究范围：OpenCTI、MISP、MITRE ATT&CK、Yeti。  
> 来源边界：只采用项目官方文档、官方仓库、官方数据文件、官方页面和官方培训材料。  
> 核对日期：2026-07-30。

## 1. 结论先行

ARGUS 不适合完整复制任何一个项目，最合适的组合是：

- 用 **OpenCTI** 决定页面骨架：`概览 → 关联知识 → 报告证据 → 历史`，以及从画像进入关系调查的交互；
- 用 **MITRE ATT&CK** 决定内容表达：每个 Campaign、Technique、Software 都必须带“它具体怎么用”和直接来源，而不是只显示标签；
- 用 **MISP** 处理名称重叠和关系不确定性：别名、相似组织、关系类型、估计语言和来源应作为一等信息；
- 用 **Yeti** 提供从组织反查 TTP、恶意软件和 DFIR 线索的快捷入口，但不采用它以自由图谱和自动化为中心的整体页面。

对 ARGUS 来说，攻击组织画像不是一张“组织百科卡”，也不应该是默认铺满全屏的关系图。它应先回答五个问题：

1. 这个名称指的是什么，和哪些别名或活动簇可能重叠？
2. 公开资料如何归因，结论有多确定，存在什么边界？
3. 该组织通常攻击谁、为了什么？
4. 它在不同活动中实际使用过哪些 TTP、工具和基础设施？
5. 每一条判断分别来自哪份报告、哪段证据，是否仍然有效？

因此建议把画像主页面做成“**证据化档案**”，把图谱作为二级核验工具，把 Campaign/历史活动作为组织画像和 ARGUS 现有攻击路径之间的桥梁。

## 2. 项目对比总览

| 项目 | 画像核心 | 字段与关系 | 时间表达 | TTP / 目标 / 基础设施 | 报告证据 | 主要交互 | 对 ARGUS 的价值 |
|---|---|---|---|---|---|---|---|
| OpenCTI | 可运营的威胁知识页 | 属性、别名、Actor / Intrusion Set / Campaign、Victimology、Arsenal、关系 | first/last seen、关系日期、平台修改历史 | 分主题知识页和 Diamond 四象限 | Report/Container、External Reference、来源与置信度 | 卡片筛选、收藏、页签、图谱 Pivot、选择性展开、回退、导出 | 页面骨架和图谱核验最佳参照 |
| MITRE ATT&CK | 公开证据化组织百科 | ID、别名、描述、Campaign、Technique、Software | Campaign 首末时间；页面创建、修改、版本 | TTP 最强；工具充分；基础设施和目标画像较弱 | 每条 Technique 的 Use 说明和原始引用 | 表格浏览、实体跳转、Navigator Layer 查看/下载、版本永久链接 | 证据写法和 Campaign/TTP 展示最佳参照 |
| MISP | 可附着到事件/属性的 Galaxy Cluster | 描述、国家、赞助方、受害者、行业、动机、别名、关系、估计语言 | Sighting 可表达出现；Actor Cluster 本身不是活动时间线 | 可通过 Galaxy、Event、Attribute 和关系拼装 | refs、Event Report、分析员数据 | Cluster 表格/JSON、关系图、附着到 Event/Attribute、相关图 | 名称歧义和关系置信度的最佳参照 |
| Yeti | 从威胁实体反查取证对象 | Actor、Malware、Observable、Indicator、Tag 及任意 Link | 不是画像核心 | 擅长 Actor → Malware → URL/IP 和 TTP/DFIR 反查 | 以对象、标签和自动化结果为主 | Threat Graph、标签图、Link object、批量查询、自动化 | 适合做“开始狩猎/查 IOC”快捷动作，不适合做完整画像骨架 |

## 3. OpenCTI：把画像做成可调查的知识主页

### 3.1 展示哪些字段和关系

OpenCTI 明确区分了三类容易混用的概念：

- `Threat Actor` 是实际的人或攻击者群体；
- `Intrusion Set` 是相对稳定的技术与非技术活动集合，包含 TTP、工具、恶意软件、基础设施和目标特征；
- `Campaign` 是有限时间内、面向一组相似受害者的一系列攻击。

官方文档还提醒，业界数据源经常把攻击者群体建模为 Intrusion Set，说明画像前端必须容纳“不同供应商使用不同聚类口径”，不能把所有别名当成完全相同的组织。[OpenCTI Threats 官方文档](https://docs.opencti.io/latest/usage/exploring-threats/)

Threat Actor 列表以卡片展示，卡片摘要包含：

- 描述；
- 别名；
- 使用的恶意软件；
- 目标国家和行业；
- 标签。

用户可以按通用和 Threat Actor 特有属性搜索、筛选，还可以收藏常用组织。[OpenCTI Threats 官方文档](https://docs.opencti.io/latest/usage/exploring-threats/)

进入单个 Threat Actor 后，官方页面结构是：

- `Overview`：实体属性和近期活动；
- `Knowledge`：Victimology、Arsenal、Techniques 等结构化关联；
- `Content`：面向分析报告、Markdown 等交付内容；
- `Analyses`：包含该对象的分析容器；
- `Data`：数据与文件；
- `History`：实体与关系的修改历史。

典型实体的 Overview 还会显示最新关系、包含该对象的最新 Case/Analysis、外部引用、平台历史和分析员 Notes。[OpenCTI Explore Knowledge Overview](https://docs.opencti.io/latest/usage/overview/)

OpenCTI 的 Knowledge 页会把组织关联的对象继续分主题呈现。官方以 APT29 为例，列出归因关系、受害者、Campaign、TTP 和恶意软件；对 Threat Actor、Intrusion Set、Malware 等对象还会自动生成 Diamond Model，把关系分成：

- Adversary；
- Infrastructure；
- Victimology；
- Capabilities。

四个象限都可点击，进入全部或筛选后的实体列表。[OpenCTI Explore Knowledge Overview](https://docs.opencti.io/latest/usage/overview/)

OpenCTI 的官方仓库还强调，平台同时承载技术与非技术情报，并把关系的 first/last seen、置信度和每条信息的主来源作为数据模型核心。[OpenCTI 官方仓库](https://github.com/OpenCTI-Platform/opencti)

OpenCTI 还明确区分“来源可靠性”和“知识断言置信度”：来源可以整体较可靠，但其中某条归因仍可能只有中等置信；反过来也不能用资料数量替代断言置信度。[OpenCTI Reliability and Confidence 官方文档](https://docs.opencti.io/latest/usage/reliability-confidence/)

### 3.2 时间线、证据和交互

OpenCTI 的时间信息有两种，不能混为一谈：

- 威胁知识时间：对象或关系的 first seen / last seen；
- 平台操作历史：谁在什么时候修改了实体或关系。

后者适合审计，不等于攻击组织活动时间线。ARGUS 应借鉴前者，避免把“报告入库时间”画成“组织活动发生时间”。

证据方面，Overview 直接呈现包含该对象的报告/Case、外部引用和分析员 Notes；Knowledge 中的实体既可能来自直接关系，也可能由推理引擎计算得到，因此 UI 有必要标明关系来源和事实类型。[OpenCTI Explore Knowledge Overview](https://docs.opencti.io/latest/usage/overview/)

OpenCTI 的 Investigation 提供了最值得 ARGUS 借鉴的图谱交互：

- 选择或搜索节点时保留相关节点颜色、压暗无关节点；
- 右侧详情栏区分当前查看节点与其他选中节点；
- 节点角标显示还有多少关联实体未展开；
- 双击或点击扩展后，先选择实体类型和关系类型；
- 图谱过密时可以回退最近 10 次展开；
- 调查可导出 PDF、图片或 STIX，也能转成 Report、Incident Response 等容器。

[OpenCTI Pivot and Investigate 官方文档](https://docs.opencti.io/latest/usage/pivoting/)

### 3.3 适合 ARGUS 的部分

- `Overview / Knowledge / Analyses / History` 的分层非常适合作为画像骨架；
- Diamond Model 适合转化为 ARGUS 的“目标、能力、基础设施、活动”四个摘要区；
- 节点角标、按类型展开、右栏核验和撤销展开适合复用到 ARGUS 现有知识图谱；
- Threat Actor、Intrusion Set、Campaign 的语义区分值得在前端文案中体现；
- External Reference 和包含该对象的 Report 应进入所有关键判断的证据入口。

### 3.4 不适合直接照搬的部分

- OpenCTI 是通用 CTI 操作系统，页签和对象类型非常多；ARGUS 比赛版不需要 Content 编辑、Case 管理、权限、收藏 Dashboard 等完整工作流；
- 现有 ARGUS 数据还不足以稳定拆成 Threat Actor 和 Intrusion Set 两套独立实体，强行照搬会出现同一公开名称两套空页面；
- Diamond 图适合摘要导航，不应成为首屏主体；用户首先需要看到身份、活动和证据结论。

## 4. MITRE ATT&CK：画像的每条 TTP 都要可追溯

### 4.1 展示哪些字段和关系

MITRE ATT&CK 的 Group 页面采用非常克制的线性结构。以 APT28 页面为例，页首展示：

- 名称和简介；
- ATT&CK Group ID；
- Associated Groups；
- Contributors；
- Version；
- Created / Last Modified；
- Version Permalink。

随后依次展示：

- Associated Group Descriptions；
- Campaigns；
- ATT&CK Navigator Layer；
- Techniques Used；
- Software；
- References。

[MITRE ATT&CK APT28 官方页面](https://attack.mitre.org/groups/G0007/)

Campaign 表同时给出 Campaign ID、名称、First Seen、Last Seen、说明/引用和关联 Techniques。Technique 表不是简单的 ID 清单，而是：

- Domain；
- Technique ID / Sub-technique；
- Technique 名称；
- `Use`：该组织在什么场景、用什么方式实际实施该技术；
- 紧跟在 Use 后的原始引用。

Software 表也把软件、引用和该软件使用的 Techniques 放在同一行。[MITRE ATT&CK APT28 官方页面](https://attack.mitre.org/groups/G0007/)

ATT&CK 官方对 Groups 的口径尤其重要：Group 是安全社区以共同名称追踪的活动簇，不同机构的命名可能只部分重叠，Associated Groups 不代表严格等同；Group 和 Technique、Software、Campaign 的映射只覆盖公开报告中能获得的一部分事实。[MITRE ATT&CK Groups 官方说明](https://attack.mitre.org/groups/index.html)

### 4.2 时间线、目标、基础设施和证据

- 时间表达主要落在 Campaign 的 First/Last Seen，而不是做一条连续、自动推断的组织时间线；
- TTP 和 Software 证据非常强，每项都有具体使用叙述和引用；
- 页面中的受害目标更多出现在简介、Campaign 和引用叙述中，没有像 OpenCTI 那样单独形成 Victimology 工作区；
- 基础设施不是 Group 页的主展示对象，无法替代 IOC / Infrastructure 专页；
- References 在页底形成统一来源目录，每条行为叙述又就地引用。

ATT&CK 还提供 Group 对应的 Navigator Layer 查看与下载，适合把组织 Techniques 投射到战术矩阵，但它不是关系图，也不表达攻击步骤顺序。[MITRE ATT&CK APT28 官方页面](https://attack.mitre.org/groups/G0007/)

### 4.3 适合 ARGUS 的部分

- 页首保留稳定 ID、别名、版本和最近更新时间；
- Campaign 作为历史活动时间线的基本单元；
- 每条 TTP 必须显示“公开报告观察到了什么用法”，而不只是 T1059.001；
- TTP 点击后打开证据抽屉，直接看到报告、摘录、时间和映射理由；
- 提供“矩阵视图”，按 ATT&CK Tactic 对 Techniques 分组；
- 来源在结论旁就地出现，同时保留统一证据目录。

### 4.4 不适合直接照搬的部分

- ATT&CK Group 页是一份权威数据目录，不是调查工作台；缺少目标画像、IOC 生命周期、关系图核验和候选归因对比；
- 长表格适合研究检索，不适合直接作为 ARGUS 首屏；
- ATT&CK 不表达技术的必然顺序，不能把 Group 的 Technique 集合自动连成一条攻击链。

## 5. MISP：名称关系和估计语言必须进入画像

### 5.1 展示哪些字段和关系

MISP Galaxy 将高层知识表示为可以附着到 Event 或 Attribute 的 Cluster。官方说明中，Cluster 可以包含任意键值元素，并能应用分发控制；MISP 内置了 Threat Actor、Malware、ATT&CK 等 Galaxy。[MISP Galaxy 官方页面](https://www.misp-project.org/galaxy.html)

MISP 官方 `threat-actor.json` 展示了实际 Actor Cluster 的数据范围。以 APT28 为例，包含：

- value / uuid / description；
- attribution-confidence；
- 国家；
- 疑似国家赞助方；
- 疑似受害者；
- 目标类别和目标行业；
- 事件类型；
- 特定厂商命名来源；
- refs；
- synonyms；
- related 关系；
- 关系上的 estimative-language 标签。

[MISP threat-actor Galaxy 官方数据文件](https://github.com/MISP/misp-galaxy/blob/main/clusters/threat-actor.json)

这比只存“国家、行业、别名”更有价值：MISP 把 `similar` 和 `uses` 等关系分开，还允许给关系附加 “likely” 一类估计语言，说明“两个名称可能相关”不应被前端扁平化成一个无条件别名数组。

官方培训材料的 Cluster 页面示例同时给出关系图和 `Tabular view / JSON view`，表格可见 attribution-confidence、疑似赞助方、疑似受害者等元数据。[MISP Data Model Overview 官方培训材料](https://www.misp-project.org/misp-training/%5Bshort%5D%20MISP%20Data%20model%20overview.pdf)

### 5.2 事件、证据和交互

MISP Event 是情报包装和共享的基本容器，可包含 Attribute、Object、Galaxy Cluster 和 Event Report。Event Report 支持 Markdown，并能交叉引用结构化数据点；Sighting 用于表达某个 Attribute 的观察和误报状态。[MISP Concepts Cheat Sheet](https://www.misp-project.org/misp-training/cheatsheet.pdf)

MISP 官方功能说明还包括：

- 在 Event、Correlation Graph 和 Event Graph 间导航；
- 通过自动关联发现重复或相似指标；
- 把 Threat Actor、Malware 和 ATT&CK Galaxy 关联到事件、报告或属性；
- 通过 Sightings 记录某个指标被观察到。

[MISP Features 官方页面](https://www.misp-project.org/features/)

关系也可以直接附着在 Event Tag 或 Attribute Tag 上，Event Graph 支持实体评论和搜索提示。[MISP 2.4.164 官方发布说明](https://www.misp-project.org/2022/10/10/MISP.2.4.164.released.html/)

### 5.3 适合 ARGUS 的部分

- 别名应拆成“明确同义”和“可能重叠/相似”，不要只用一个 aliases 数组；
- 归因、赞助方、目标和动机字段应允许“不确定”和来源差异；
- 组织之间的关系应显示关系类型、估计语言和来源；
- 报告文字与结构化实体之间应能互相跳转；
- IOC 必须有 Sighting/最后出现时间/失效状态，不能把历史 IOC 永久当作当前基础设施。

### 5.4 不适合直接照搬的部分

- MISP 的核心单位是 Event 和 Attribute，不是精心策展的 Actor Profile；
- Cluster 表格和 JSON 适合录入核验，不适合面向 SOC 阅读的画像首屏；
- Actor 的 TTP、Campaign 和基础设施通常需要从多个 Event/Galaxy 关系拼装，不能直接照抄为单页信息架构；
- 相关图容易变成属性和标签的密集网络，ARGUS 应只按需展开。

## 6. Yeti：从组织快速进入狩猎，而不是复制完整画像

### 6.1 展示哪些对象和关系

Yeti 把数据分为：

- Observables：IP、URL、Hostname、Hash 等技术对象；
- Entities：Campaign、Threat Actor、Malware 等战术对象；
- Indicators：用于匹配 Observables 并与 Entity 建立联系的高层规则。

任意对象都可以通过 Threat Graph 连接。官方示例是：

`Mustang Panda → uses → CobaltStrike → dropped from → URL`，同时 Actor 还可 `controls → IP`。Tag Graph 则通过共同标签把 Actor 和 URL 等对象关联起来。[Yeti Key Concepts 官方文档](https://yeti-platform.io/docs/key-concepts/)

Yeti 官方仓库将典型使用场景定义为：

- 批量搜索 Observables 并判断威胁性质；
- 从某个 Threat 反向列出 TTP、Malware 和相关 DFIR Artifacts；
- 通过 API、Analytics、Feeds 和 Exports 把情报用于取证或第三方系统。

[Yeti 官方仓库](https://github.com/yeti-platform/yeti)

### 6.2 适合 ARGUS 的部分

- 在组织画像页提供“查看相关 IOC”“开始狩猎”“查看历史攻击路径”快捷动作；
- 关联资产不只列名称，还要显示 Actor → Malware → Infrastructure/Observable 的关系链；
- 将 detection/hunting rule 与组织能力关联，便于从画像落到 SOC 动作；
- 可用 Tag 作为快捷过滤，但不可让 Tag 代替有来源的实体关系。

### 6.3 不适合直接照搬的部分

- Yeti 官方明确指出许多能力通过 API 和 Tasks 才能完全发挥，UI 并不是画像展示的主要设计对象；
- 任意 Link 和 Tag Graph 很灵活，但也容易让关系语义变得松散；
- 官方资料没有提供像 OpenCTI/ATT&CK 那样成熟的 Actor 证据页和 Campaign 时间线，因此它适合作为“画像后的狩猎入口”，不适合作为 ARGUS 主页面模板。

## 7. 推荐给 ARGUS 的信息层级

### 7.1 入口：现有知识库中的攻击组织结果

不新增顶层主导航。攻击组织继续作为可查询实体，通过现有综合搜索、攻击链归因候选、报告中的组织实体和知识图谱节点进入同一个专用画像页。综合搜索可增加“攻击组织”结果分组；如后续需要批量浏览，可在现有知识库内部提供组织列表路由。

搜索结果或知识库列表项只展示帮助用户判断“要不要点进去”的信息：

- 主名称；
- 明确别名中的 2—3 个，剩余数量折叠；
- 来源地/公开归因主体；
- 活跃时间范围；
- 主要目标行业；
- 最近一次有证据的活动时间；
- 历史活动数、TTP 数、工具/恶意软件数、来源数；
- 画像状态：已核验 / 部分核验 / 名称存在争议；
- 最近更新时间。

支持按名称与别名、国家/地区、目标行业、动机、活跃状态、ATT&CK Tactic 和来源等级筛选。不要在列表用单一“危险分”给组织排序；风险取决于用户行业、资产和当前活动，而不是组织的固定属性。

### 7.2 二级页面：组织画像

#### A. 固定页首

页首保持一屏内可读：

- 主名称、类型（攻击组织 / 活动簇）；
- 稳定 ID；
- 明确别名；
- “可能重叠名称”单独显示并带关系置信度；
- 国家/组织归因摘要；
- 活跃时间范围；
- 画像状态、来源等级、最后核对时间；
- 一句话分析结论；
- 快捷动作：`查看关系图`、`在报告库中搜索`、`查看攻击路径`。

公开归因必须使用措辞层级，例如“公开确认”“多源高度关联”“供应商命名关联”“仅行为相似”，不能只给一个百分比。

#### B. 主导航

建议只保留五个页签：

1. `概览`
2. `历史活动`
3. `技战术`
4. `关联资产`
5. `来源与证据`

关系图不必成为第六个常驻页签，可通过页首按钮进入全屏/大抽屉；这样能避免用户把“图很大”误认为“画像很完整”。

### 7.3 概览页

概览页按分析员阅读顺序分五块：

1. **身份与归因**
   - 公开归因摘要；
   - 动机；
   - 组织/活动簇边界；
   - 别名关系；
   - 当前证据缺口或争议。

2. **目标画像**
   - 目标行业；
   - 目标国家/地区；
   - 常见受害组织类型；
   - 每个标签可点入支持它的 Campaign/报告。

3. **近期和代表性活动**
   - 最近 3—5 个 Campaign/历史活动卡；
   - 首次/末次出现；
   - 目标；
   - 代表性 TTP；
   - 对应 ARGUS 攻击路径；
   - 来源数与证据状态。

4. **能力摘要**
   - ATT&CK Tactic 覆盖条带；
   - 高频或最具区分度的 Techniques；
   - 常用恶意软件/工具；
   - 当前仍有效与仅历史出现的基础设施数量。

5. **证据健康度**
   - 最近核对时间；
   - 来源总数；
   - 直接证据/交叉印证/推断数量；
   - 存在冲突的判断；
   - 待补字段。

### 7.4 历史活动页

时间线的基本单元应是 Campaign 或经人工审核的历史活动，不是单个 IOC，也不是数据库更新时间。

每个活动条目至少显示：

- 活动名称；
- First Seen / Last Seen / 时间是否精确；
- 活动状态；
- 目标行业和地区；
- 入口方式或关键漏洞；
- 代表性攻击路径；
- 关键 TTP 和工具；
- 与该组织的关系类型及置信度；
- 直接来源。

交互建议：

- 时间范围筛选；
- 按目标行业、Campaign、Tactic、工具筛选；
- “仅显示来源直接确认”开关；
- 列表 / 时间轴切换；
- 点击活动进入 ARGUS 已有攻击路径详情；
- 若两个活动只是共享工具，不自动归为同一 Campaign。

### 7.5 技战术页

默认按 ATT&CK Tactic 分组，支持“矩阵 / 列表”切换。

每条 Technique 不应只显示 ID 和名称，还要显示：

- 组织如何使用；
- 出现在哪些 Campaign；
- First/Last Seen；
- 关联软件或工具；
- 来源数；
- 证据状态；
- 点击后打开原文证据和映射理由。

ARGUS 可以额外显示：

- 已由报告攻击路径验证；
- 仅来自外部公开知识；
- 从现有行为推断但尚未确认。

三种状态必须有不同视觉语法，不能混成同一种“已使用”标签。

### 7.6 关联资产页

分为三个子组即可：

- `恶意软件与工具`
- `基础设施与 IOC`
- `漏洞与利用对象`

每个对象卡片显示关系、所属 Campaign、首次/末次出现、当前状态、来源和是否具有组织专属性。

基础设施需要默认区分：

- 当前活跃；
- 历史使用；
- 已下线/已失效；
- 共享托管或专属性不足；
- 本案观测但不能用于组织归因。

默认不要一次显示全部 IOC，可先按 Campaign 或基础设施簇聚合，再按需展开。

### 7.7 来源与证据页

证据页不只是报告列表，应是“判断—证据”账本：

| 判断对象 | 判断内容 | 证据类型 | 时间 | 来源 | 原文锚点 | 置信/审阅状态 |
|---|---|---|---|---|---|---|
| 组织身份 | 与公开组织/机构的归因关系 | 直接 / 交叉印证 / 推断 | 发布时间 | 报告 | 原文摘录 | 已核验 |
| TTP | 在某 Campaign 使用某技术 | 直接 | 活动时间 | 报告 | 原文摘录 | 已核验 |
| 目标 | 针对某行业/地区 | 多源汇总 | 时间范围 | 多份报告 | 对应段落 | 部分核验 |
| 基础设施 | 控制或使用某 IOC | 直接 / 共享 / 弱关联 | first/last seen | 报告 | 原文摘录 | 需复核 |

同时单列：

- 互相冲突的来源；
- 缺失证据；
- 已过期关系；
- 仅因名称相似产生的候选关系；
- ARGUS 的抽取/映射说明。

### 7.8 关系图

关系图打开时提供四个预设视角：

- `活动`：Actor → Campaign → Attack Path；
- `能力`：Actor → Technique / Malware / Tool；
- `目标`：Actor → Sector / Country / Organization；
- `基础设施`：Actor → Infrastructure / IOC。

图谱交互建议继承 OpenCTI 的成熟做法：

- 节点显示未展开关系数量；
- 展开前选择实体类型、关系类型、时间和证据状态；
- 右栏显示节点、直接关系和支撑来源；
- 支持撤销最近一次展开；
- “本次案件命中”与“组织历史上下文”明确区分；
- 图谱只表达有来源的关系，不根据共同 Tag 自动画成事实边。

## 8. 与 ARGUS 当前数据的衔接

ARGUS 当前 `Actor` 前端类型已经包含：

- description；
- profile_status；
- origin_label；
- active_from / active_to；
- public_attribution；
- motivations；
- target_sectors；
- source_refs / source_urls；
- source_grade；
- updated_at。

现有知识图谱也已经包含攻击组织、历史事件、ATT&CK 技术、工具、IOC/基础设施和来源关系；归因分析页已有候选组织、证据路径、来源抽屉和“组织历史上下文 / 本案命中路径”的区分。

当前主要缺口是前端聚合和路由：完整 `actors` 数据主要用于归因候选，通用搜索和实体详情还没有把组织查询导向专用画像页。

因此前端第一版不需要先重建完整 OpenCTI 模型，可以直接实现：

- 综合搜索中的攻击组织结果和专用详情路由；
- 固定页首；
- 概览；
- 技战术；
- 关联资产；
- 来源入口；
- 从组织页打开已有知识图谱核验。

但以下内容不能仅靠前端推测：

- Campaign 与 Actor 的明确关系类型；
- Campaign 的 First/Last Seen；
- 目标国家/地区；
- IOC 是否仍活跃及组织专属性；
- 每一条 TTP/目标/基础设施关系对应的证据摘录；
- 别名是严格同义还是仅部分重叠。

第一版遇到这些缺失字段时应显示“暂无可核验证据”，不要根据同名、共享工具或共同 Tag 自动补齐。

## 9. 推荐的最小可用版本

建议先实现一个组织详情页，不同时扩展后端模型：

1. 用现有 Actor 数据生成综合搜索中的组织结果；
2. 画像页首展示现有 Actor 字段；
3. 从图谱中按 actor 属性聚合历史事件、TTP、工具和基础设施；
4. 概览页只展示有真实数据的模块；
5. 技术、活动、资产点击后打开现有证据/来源查看器；
6. 关系图复用现有 NetworkGraph，并增加视角筛选；
7. 没有 Campaign 时间或关系级证据时，明确标记“仅组织上下文”。

视觉优先级建议是：

`身份与归因 > 历史活动 > 代表性 TTP > 目标画像 > 关联资产 > 全量图谱`

而不是：

`大图谱 > KPI 数字 > 原始字段表`

## 10. 讨论时需要确定的三个产品选择

### 选择一：页面入口

推荐：不改顶层主导航；让综合搜索、归因候选、报告实体和图谱节点都进入同一个专用画像页。如需浏览全部组织，把列表放在现有知识库内部。

不推荐：只在归因结果页弹出画像。那会让画像无法从报告库、搜索和知识图谱复用。

### 选择二：组织与活动簇是否分开

推荐第一版：前端统一叫“攻击组织画像”，在页首用类型和提示解释它可能是公开组织、供应商活动簇或二者的近似映射。

等数据量和关系证据成熟后，再考虑像 OpenCTI 一样拆成 Threat Actor 与 Intrusion Set。

### 选择三：图谱是否作为主视图

推荐：概览为默认，图谱是全屏二级核验视图。

原因是画像首先服务快速理解，图谱服务关系核验。把图谱置于首屏会掩盖时间、目标和证据缺口，也会放大当前小型样本库的稀疏感。

## 11. 最终建议

ARGUS 的差异化不应是“比 ATT&CK 多一张图”或“做一个缩小版 OpenCTI”，而是把公开画像和现有攻击路径连接起来：

> 从组织看它过去怎样攻击，从历史活动进入可阅读攻击路径，再从每个路径节点回到原始报告证据。

这条链路是当前数据和界面最能支撑的方向。第一版应优先完成组织搜索结果、证据化概览、历史活动、TTP 用法和资产状态；关系图可以复用，但必须保持二级、可筛选、可回退。
