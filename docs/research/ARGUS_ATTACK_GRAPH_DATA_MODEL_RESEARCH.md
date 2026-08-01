# ARGUS 攻击路径图谱数据结构研究

> 研究范围：ARGUS 的“攻击路径研判”图谱，不是全库任意关系探索页。  
> 产品基础：主干从左到右排列；IOC、工具、漏洞、资产和证据从对应步骤树状展开；下方以泳道提供更稳定的阶段阅读；右栏负责逐节点审计。  
> 来源范围：只使用官方规范、官方文档和官方开源仓库。  
> 核对日期：2026-07-30

## 1. 结论

ARGUS 不应把“知识图谱”“攻击路径”和“报告证据”混成一张通用的节点—边表。更适合的结构是五层：

1. **来源证据层**：原始报告、输入告警、证据片段、页码/行号、发布者和哈希；
2. **规范知识层**：规范化 IOC、文件、域名、恶意软件、工具、漏洞、ATT&CK 技术、组织等可复用实体；
3. **活动事实层**：某次攻击活动中实际发生的原子行为，以及行为与 IOC/工具/资产之间带角色的上下文关系；
4. **攻击流层**：行为依赖、分支、条件、AND/OR 汇合、起点和结果；
5. **研判投影层**：主干选择、折叠支线、泳道位置、补全与预测状态。它是可重新计算的展示结果，不是真实事实本身。

核心原则是：

> 主干节点必须是“行为实例”，IOC 必须挂到使用它的具体行为上；报告必须通过证据断言支持节点或边，而不是作为一个“报告标题节点”用“报告提及”连接所有东西。

因此，ARGUS 的完整图不是一棵树，而是一个带来源的有向属性多重图；“左到右主干 + 树状支线 + 泳道”只是从完整图中生成的任务型投影。

---

## 2. 开源项目和规范分别解决什么

### 2.1 STIX 2.1：实体、观测、关系和来源底座

STIX 2.1 把图的节点分成 STIX Domain Objects（SDO）与 Cyber-observable Objects（SCO），边由 Relationship/Sighting 等 STIX Relationship Objects（SRO）和嵌入引用表达。SDO 包括 Malware、Campaign、Intrusion Set、Report、Indicator、Attack Pattern、Vulnerability 等；SCO 包括 File、IPv4 Address、Domain Name、Network Traffic、Process 等。[OASIS STIX 2.1 标准](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)

它对 ARGUS 最重要的区分是：

- **SCO / Observed Data**：实际看见的文件、地址、连接等技术事实；
- **Indicator**：用于检测潜在恶意活动的模式或判定规则，不等于一次具体观测；
- **Sighting**：关于某个 Indicator、Malware、Campaign 等“被看见”的情报断言，可以通过 `observed_data_refs` 指向具体观测；
- **Report / Grouping**：用 `object_refs` 容纳一组对象和关系。Report 表示一份情报产品，Grouping 表示这些对象共享上下文；Bundle 本身不表达共享上下文；
- **Relationship**：具有方向、类型、描述、时间、置信度、来源等属性的一等对象。

STIX 官方特别区分 Sighting 与 Observed Data：前者是“我认为看到了某种威胁”的情报断言，后者只是“我看到了这个文件/连接”的数据事实。[OASIS STIX 2.1 Sighting 与 Observed Data](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070594)

适合 ARGUS：

- 规范实体、IOC 和报告来源的基础字段；
- 区分原始观测、分析判断与关系；
- 使用 `external_references`、`created_by_ref`、`confidence`、marking 保存来源和共享限制；
- STIX 导入/导出兼容。

不适合直接照搬：

- STIX 不定义攻击动作之间的因果顺序；
- Report 的 `object_refs` 只表示“被这份报告收纳”，不能替代“哪个证据支持哪条边”；
- 通用 STIX Relationship 不足以表达条件分支、AND/OR 汇合和主干投影；
- 不能从 STIX 图里找最长路径并称其为攻击主干。

### 2.2 MITRE ATT&CK：统一“这个动作是什么”

MITRE ATT&CK 将概念区分为：

- tactic：攻击者为什么做，即战术目标；
- technique / sub-technique：攻击者如何达成目标；
- procedure：真实攻击者对技术的具体实现。

ATT&CK 官方明确说明 tactics **无序**，并且一次入侵不必出现所有 tactic；procedure 是技术在真实世界中的具体实现。[MITRE ATT&CK FAQ](https://attack.mitre.org/resources/faq/)

ATT&CK 的官方 STIX 数据是其最细粒度的机器可读表示，网站、Navigator 等展示也由 STIX 数据生成；组织/软件到技术的 procedure examples 以关系形式保存并带引用。[MITRE ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/)

适合 ARGUS：

- 给每个攻击行为实例绑定 tactic、technique、sub-technique；
- 作为泳道分类和跨报告语义对齐空间；
- Procedure Examples 可作为动作归一化和补全候选的背景知识。

不适合直接照搬：

- ATT&CK 技术是类型，不是本次活动中的动作实例；
- ATT&CK tactic 的页面列顺序不能当作真实时间或因果顺序；
- “组织 uses 技术”的 ATT&CK 知识关系不能直接变成本次攻击的路径边；
- 单独把技术卡片从左到右排列，仍然回答不了“哪个样本、IOC 和资产参与了哪一步”。

### 2.3 Attack Flow：表达动作依赖、分支与汇合

Attack Flow 是建立在 STIX 2.1 扩展机制上的机器可读语言，主要对象包括：

- `attack-flow`：整个攻击流及其 `scope`、`start_refs`；
- `attack-action`：离散攻击行为，可绑定 tactic/technique、执行时间、命令和资产；
- `attack-asset`：动作依赖或影响的技术/非技术资产；
- `attack-condition`：成功、失败或状态条件，通过 `on_true_refs` / `on_false_refs` 分支；
- `attack-operator`：通过 AND/OR 组合多条路径；
- `effect_refs`：动作、条件或操作符产生的后续效果。

[Attack Flow 语言规范](https://center-for-threat-informed-defense.github.io/attack-flow/language/)  
[Attack Flow 官方 JSON Schema](https://github.com/center-for-threat-informed-defense/attack-flow/blob/main/stix/attack-flow-schema-2.0.0.json)

Attack Flow 最值得 ARGUS 采用的规则是：**相连动作表达的是效果依赖，不只是时间更早。** 后续动作依赖前一动作成功产生的效果；互不依赖的动作应作为并行分支；条件可表达成功/失败；AND/OR 可消除多路汇合的歧义。[Attack Flow Introduction](https://center-for-threat-informed-defense.github.io/attack-flow/introduction/)

适合 ARGUS：

- 攻击主干和分支的内部拓扑；
- 条件、失败回退、并行与汇合；
- 行为级时间、ATT&CK 映射和来源；
- 作为导出格式和复杂图的校验语料。官方提供多种真实案例流。[Attack Flow Example Flows](https://center-for-threat-informed-defense.github.io/attack-flow/example_flows/)

不适合直接照搬：

- Attack Flow 主要是表达规范，不负责从报告抽取；
- 它没有 `main_path` 或“首选分支”字段；
- 它不负责跨报告活动消歧、IOC 归一化和实体合并；
- 官方 Builder 偏人工建模，不应照搬成 ARGUS 的默认查询界面；
- 公开情报若没有资产细节，不应为了填满 `attack-asset` 而虚构资产。

### 2.4 OpenCTI：完整知识图谱、来源容器与受控 Pivot

OpenCTI 的核心模型是知识图谱：节点是带属性的实体，边是带属性的关系，底座基于 STIX 2.1。[OpenCTI Data Model](https://docs.opencti.io/latest/usage/data-model/)

其容器模型把 Report、Grouping、Observed Data、Note、Opinion、Case 等与普通实体区分开。容器通过 `object_refs` 容纳实体和关系；容器是“包含”，不是普通业务关系。[OpenCTI Containers](https://docs.opencti.io/latest/usage/containers/)

Investigation 的密度控制值得直接借鉴：

- 节点角标显示尚未展示的邻居数量；
- 单独选择要扩展的实体类型和关系类型；
- 选中节点时保留焦点并压暗其他节点；
- 可回退最近的展开操作；
- 节点与关系都可以作为调查对象；
- 调查结果可导出或沉淀到 Report/Grouping 等容器。

[OpenCTI Pivot and Investigate](https://docs.opencti.io/latest/usage/pivoting/)

Report/Grouping 等分析容器又提供 Graph、Timeline、Correlation、Matrix 等不同 Lens；时间范围筛选用于查看知识演进，而不是强迫所有内容进入同一张图。[OpenCTI Analysis](https://docs.opencti.io/latest/usage/exploring-analysis/)

OpenCTI 还明确区分来源可靠性与信息置信度，并可表达 Told、Induced、Deduced、Witnessed 等不同信息形成方式。[OpenCTI Reliability and Confidence](https://docs.opencti.io/latest/usage/reliability-confidence/)

适合 ARGUS：

- 报告是证据容器，不是攻击行为节点；
- 关系也是一等对象，必须能被选择和审计；
- 默认只显示有限范围，按类型逐跳展开，并可撤销；
- 来源可靠性与断言置信度分开；
- 关系图、时间图和矩阵/泳道是不同投影。

不适合直接照搬：

- OpenCTI 的全局关系图适合探索，不能自动给出攻击主干；
- `related-to`、`uses`、`targets` 等知识关系不是动作依赖；
- OpenCTI 的企业级对象、权限、任务和大量 Tab 会让比赛型 ARGUS 过重；
- 不能把整个 OpenCTI STIX 本体原样暴露给前端。

### 2.5 MISP：事件、IOC 对象、对象关系与时间窗

MISP 以 Event 作为共享和分析上下文；Attribute 是基本情报单元，Object 根据模板把文件、网络连接等多个属性组合为语义对象，Object Reference 表达对象间关系。Event Report 用文本描述事件，并可引用事件中的 Attribute/Object。[MISP Concepts Cheat Sheet](https://www.misp-project.org/misp-training/cheatsheet.pdf)

MISP Object 的价值在于：文件不只是一个 hash 节点，而是由文件名、大小、多个 hash 等属性共同描述的复合对象；Object 可以和其他 Object/Attribute 建立关系。[MISP Objects 发布说明](https://www.misp-project.org/2017/09/18/misp.2.4.80.released.html/)

MISP 将 Event Graph 与 Event Timeline 分开：前者显示事件中实体关系，后者基于 Attribute/Object 的时间信息展示攻击步骤。其数据模型后来在 Attribute/Object 层加入 `first_seen` 和 `last_seen`。[MISP Timeline 发布说明](https://www.misp-project.org/2020/01/21/misp.2.4.120.released.html/)

适合 ARGUS：

- 一份报告可包含多个活动片段或 IOC 集，不强制一报告一链；
- 文件、邮件、网络连接等应是带属性的复合对象；
- `first_seen` / `last_seen` 应进入实体与关系，但时间视图单独生成；
- Event Report 的自然语言与结构化对象相互引用；
- IOC 跨事件关联适合作为调查支线。

不适合直接照搬：

- MISP Event 是共享容器，不等于严格的一次攻击活动；
- Event Graph 的对象关系不保证因果；
- 时间相邻不代表动作依赖；
- MISP 强 IOC/共享的模型不能代替 ARGUS 的行为流。

### 2.6 Timesketch：只借鉴时间 Lens 与调查叙事

Timesketch 用 Sketch 组织一个案件中的多条 Timeline；Explore 支持时间过滤、事件搜索、Context Query、星标和保存视图；Story 将保存的搜索、聚合、原始事件与说明文字组织为调查叙事。[Timesketch Sketch Overview](https://timesketch.org/guides/user/sketch-overview/) [Timesketch Basic Concepts](https://timesketch.org/guides/user/basic-concepts/)

适合 ARGUS：

- 点击行为后查看前后时间邻域；
- 将已确认动作和证据收录到研判故事；
- 时间过滤不改变底层关系事实。

不适合直接照搬：

- Timesketch 面向取证日志事件，不是 CTI 知识图谱；
- 公开报告通常没有日志级时间精度；
- 不能用报告段落顺序或发布日期模拟精确执行时间。

### 2.7 为什么不以 Maltego CE 为核心

Maltego 的产品交互可以作为通用 Pivot 工具的视觉参考，但 Community Edition 不是可直接审计和复用的数据模型规范或核心开源实现。本研究不以其作为 ARGUS 本体设计依据。

---

## 3. ARGUS 需要明确的三个“图”

### 3.1 完整知识图 `KnowledgeGraph`

保存规范实体和可复用知识关系，例如：

```text
APT28 ──uses──> HeadLace
HeadLace ──communicates-with──> cdn-meeting-update.com
cdn-meeting-update.com ──resolves-to──> 185.225.72.44
CVE-2017-6742 ──affects──> Cisco IOS
```

它适合情报关系探索和跨报告 Pivot，不直接等于一条攻击链。

### 3.2 活动事实图 `ActivityGraph`

保存某个攻击活动范围内的行为实例和具体上下文：

```text
[发送 NATO 主题钓鱼邮件]
    └─ delivers ─> [invitation.zip]

[用户打开 LNK]
    ├─ executes ─> [powershell.exe]
    ├─ mapped-to ─> [T1204.002]
    └─ produces-effect ─> [取得用户态代码执行]

[HeadLace 建立 C2]
    ├─ uses ─> [HeadLace]
    ├─ connects-to ─> [cdn-meeting-update.com]
    └─ on-asset ─> [受害终端]
```

这是 ARGUS 攻击路径页面的事实底座。

### 3.3 研判投影 `AnalysisProjection`

从活动事实图中计算：

- 哪些行为构成默认主干；
- 哪些真实分支折叠为 `+N`；
- 哪些是本次输入观测、跨报告补充、算法补全和预测；
- 每个行为放在哪个泳道；
- 初始展示哪些关键 IOC；
- 哪些节点可继续展开。

投影只保存选择与解释，不复制实体和事实。更换主干算法或前端布局时，事实图不需要重抽。

---

## 4. 推荐的详细数据结构

### 4.1 `source_document`：来源文档

| 字段 | 含义 |
|---|---|
| `id` | 稳定 ID |
| `title` | 报告标题 |
| `publisher_ref` | 发布机构 Identity |
| `published_at` / `collected_at` | 发布时间 / 采集时间 |
| `original_url` | 原始 URL |
| `sha256` / `mime_type` | 原文文件校验与类型 |
| `tlp` / `license` | 使用和共享限制 |
| `parser_version` | 解析器版本 |
| `document_kind` | report / alert / user-input / dataset-document |
| `review_status` | unreviewed / reviewed / rejected |

报告不作为默认画布节点。它是证据容器，只在右栏“来源”或报告视图出现。

### 4.2 `evidence_span`：最小可审计证据

| 字段 | 含义 |
|---|---|
| `id` | 证据 ID |
| `source_document_ref` | 来源报告 |
| `locator` | 页码、段落、行号、表格单元格或 JSON Path |
| `quote` | 短原文摘录 |
| `context_before` / `context_after` | 必要上下文 |
| `extraction_method` | model / rule / manual |
| `extractor_version` | 模型/规则版本 |
| `language` | 原文语言 |

每个行为、上下文关系、依赖边和实体别名都可以引用不同证据。禁止只在活动根节点上挂一个报告 URL。

### 4.3 `canonical_entity`：规范知识实体

建议实体类别：

| 大类 | 子类示例 |
|---|---|
| `observable` | ipv4, ipv6, domain, url, email, file, hash, process, registry-key, mutex, certificate, network-traffic |
| `threat` | malware, tool, vulnerability, infrastructure, intrusion-set, threat-actor, campaign |
| `knowledge` | attack-technique, attack-tactic, course-of-action |
| `asset` | host, account, application, device, service, data, organization |

核心字段：

```yaml
id:
entity_type:
name:
canonical_value:
aliases: []
stix_id:
external_ids: []
first_seen:
last_seen:
attributes: {}
normalization:
  rule_version:
  merge_key:
review_status:
```

规范化要求：

- IP、域名、URL、hash 使用确定性规范化值；
- 文件实体保存 filename、hashes、size、mime 等属性，不把每个属性都画成独立主节点；
- Malware/Tool/Actor 保留别名，但只显示规范名称；
- ATT&CK 技术实体保存 `Txxxx(.xxx)` 和 ATT&CK 版本；
- 同值 Observable 可以跨报告复用，但每次出现仍通过 Observation 记录。

### 4.4 `observation`：某次来源中的具体出现

`canonical_entity` 回答“它是什么”，`observation` 回答“它在何时、何处被哪份输入看见”。

```yaml
id:
entity_ref:
activity_ref:
source_document_ref:
evidence_refs: []
first_observed:
last_observed:
count:
sensor_or_report_context:
observation_basis: input-telemetry | input-alert | source-report
```

这样同一个域名跨三份报告出现时，只有一个规范实体，但有三次独立 Observation。不能因为规范实体被合并，就丢掉来源和时间差异。

### 4.5 `activity`：攻击活动边界

```yaml
id:
name:
scope: incident | campaign | activity-cluster | report-fragment
description:
start_time:
end_time:
source_document_refs: []
actor_hypotheses: []
cluster_method:
cluster_confidence:
review_status:
```

一份报告可以产生：

- 0 个活动：只有 IOC/组织画像；
- 1 个活动；
- 多个互不连通的活动；
- 多个待定片段，暂不强制合并。

多份报告也可以支持同一 Activity，但必须保留各自 Observation 与证据断言。

### 4.6 `behavior_action`：攻击主干和分支的唯一节点类型

这是最重要的节点。

```yaml
id:
activity_ref:
label: "创建计划任务"
description: "Zebrocy 创建名为 ... 的计划任务以实现持久化。"
actor_ref:
verb: create
object_refs: []
asset_refs: []
tool_refs: []
malware_refs: []
technique_refs: ["T1053.005"]
tactic_refs: ["TA0003"]
command_ref:
execution_start:
execution_end:
action_status: succeeded | failed | attempted | unknown
evidence_state: input-observed | report-asserted | corroborated | reconstructed | predicted
confidence:
evidence_refs: []
review_status:
```

#### 行为标签规则

- 标签是“动词 + 关键对象”，不是完整句子；
- 中文建议 4–14 字，最长不超过约 20 字；
- 不出现报告作者、研究者和“报告指出”等叙述；
- 工具、文件、IOC 是关联实体，不应替代行为；
- 同一原句可以产生一个行为和多个上下文实体；
- 描述、命令、证据摘录放在字段里，不塞进节点标题。

好例子：

- `打开恶意 LNK`
- `执行 PowerShell`
- `创建计划任务`
- `收集系统信息`
- `向 C2 回传数据`

坏例子：

- `APT28 Delivers Zebrocy Malware Campaign using NATO Theme as Lure`
- `攻击者可能使用恶意文件在受害者设备上执行命令并收集信息`
- `194.32.78.245`
- `Zebrocy`

后两者是实体，不是行为。

### 4.7 `action_context_link`：行为与 IOC/工具/资产的角色关系

每个 IOC 必须连接到使用它的具体动作，而不是统一挂到 Activity 根节点。

推荐的受控关系词：

| 关系族 | 关系类型 |
|---|---|
| 投递/获取 | `delivers`, `downloads-from`, `retrieves`, `extracts`, `contains` |
| 执行/落地 | `executes`, `loads`, `drops`, `writes`, `copies-as`, `invokes` |
| 持久化/修改 | `creates`, `modifies`, `registers`, `schedules`, `installs` |
| 网络 | `connects-to`, `resolves-to`, `redirects-to`, `receives-from`, `exfiltrates-to` |
| 利用/身份 | `exploits`, `authenticates-as`, `impersonates` |
| 目标/资产 | `targets`, `runs-on`, `affects`, `reads-from`, `collects-from` |
| 语义 | `uses-malware`, `uses-tool`, `mapped-to-technique` |
| 产物 | `produces`, `creates-file`, `captures`, `collects` |

字段：

```yaml
id:
activity_ref:
action_ref:
entity_ref:
role:
direction: action-to-entity | entity-to-action
first_seen:
last_seen:
confidence:
evidence_state:
evidence_refs: []
review_status:
```

“报告提及”不属于这个关系表。报告对关系的支持由 `evidence_refs` 表达。

### 4.8 `action_dependency`：攻击动作之间的过程边

只有行为到行为、行为到条件/操作符的边进入攻击流。

推荐类型：

| 类型 | 语义 |
|---|---|
| `enables` | 前一步效果是后一步的执行条件 |
| `causes` | 前一步直接造成后一步 |
| `reported-before` | 报告明确给出先后，但依赖关系不确定 |
| `on-success` / `on-failure` | 成功或失败分支 |
| `alternative` | 互斥或可替代分支 |
| `parallel` | 同范围并行且无依赖；更推荐使用共同父节点/分支组表达 |
| `join-and` / `join-or` | 多路汇合条件 |

字段：

```yaml
id:
activity_ref:
source_action_ref:
target_action_ref:
dependency_type:
required_effect:
condition_ref:
operator_ref:
sequence_index:
confidence:
evidence_state:
evidence_refs: []
review_status:
```

约束：

- 不允许用 `攻击行为推进` 作为正式关系类型；
- 若只能确认文本先后，保存为 `reported-before`，不能冒充 `enables`；
- 若报告只列出两种行为但没有连接依据，不创建路径边；
- 每条 `reconstructed` 或 `predicted` 边必须保存生成理由和支持候选；
- 图允许 DAG 和多分支，不强制单链；若真实活动存在循环，可用重复的行为实例表达不同执行轮次，不直接让展示主干形成难读循环。

### 4.9 `flow_condition` 与 `flow_operator`

与 Attack Flow 对齐：

```yaml
flow_condition:
  id:
  description:
  pattern:
  on_true_refs: []
  on_false_refs: []
  evidence_refs: []

flow_operator:
  id:
  operator: AND | OR
  input_refs: []
  effect_refs: []
```

只有在来源或研判确实需要表达条件/汇合时创建，不为简单顺序链增加空节点。

### 4.10 `assertion`：事实与证据之间的审计桥梁

为了让节点与边都可审计，建议将所有事实统一视为断言：

```yaml
id:
subject_ref:
predicate:
object_ref:
activity_ref:
assertion_kind: entity-property | context-link | action-dependency | identity-resolution
basis: source-report | input-alert | cross-source | algorithm | analyst
evidence_refs: []
source_reliability:
confidence:
model_or_rule_version:
review_status:
supersedes_ref:
```

这解决四个问题：

1. 同一关系可以由多份报告独立支持；
2. 冲突断言并存，不相互覆盖；
3. 后端重跑时可以追踪由哪个模型/规则生成；
4. 前端点击节点或边能展示“为什么这样画”。

### 4.11 `analysis_projection`：主干、折叠和泳道

```yaml
id:
activity_ref:
projection_kind: soc-triage | incident-response
root_action_refs: []
mainline_action_refs: []
mainline_dependency_refs: []
branch_groups:
  - parent_action_ref:
    action_refs: []
    collapsed_by_default: true
key_context_by_action:
  action-id: [entity-id-1, entity-id-2]
lane_assignment:
  action-id:
    tactic_ref:
    lane_order:
node_state:
  action-id: input-observed | report-asserted | corroborated | reconstructed | predicted
selection_reason:
algorithm_version:
generated_at:
```

投影层不保存新的“事实边”。例如主干选择只是引用现有 `action_dependency`，不能再创建一套 `攻击行为推进` 关系。

---

## 5. 从数据结构到默认展示

### 5.1 初始画布

默认只显示：

- 5–9 个主干行为；
- 每个行为最多 1–2 个高价值上下文实体；
- 真实分支只显示入口节点或 `+N` 聚合；
- 每个行为显示 `IOC n / 证据 n / 技术 n`；
- 分支、补全、预测采用不同线型和状态标记。

示例：

```text
钓鱼邮件投递 → 打开恶意 LNK → 执行 PowerShell → 创建计划任务 → 收集信息 → 向 C2 回传
                    │                │                 │               │
              invitation.lnk      HeadLace       T1053.005     cdn-meeting-update.com
              文件 IOC +2         样本 +2         证据 +1       IP/URL +3
```

这里 `invitation.lnk`、HeadLace、T1053.005 和域名来自 `action_context_link`，不是路径行为节点。

### 5.2 节点展开

借鉴 OpenCTI：

- 单击只选择，不触发布局；
- 右栏显示将展开的邻居数量和类型；
- “展开一跳”只增加该行为直接关联的 IOC/工具/资产；
- “展开行为分支”只增加该行为后续真实行为；
- 可按 IOC、文件、基础设施、工具、技术、证据筛选；
- 展开从父节点附近放射生长，已有节点位置固定；
- 支持撤销最近一次展开。

不提供默认“一键铺满全图”。若提供“展开全部直接关联”，也必须只针对当前节点的一跳，并在执行前显示预计增加数量。

### 5.3 右侧检查器

选中行为：

- 行为标题、描述、ATT&CK 映射和阶段；
- 输入观测 / 报告断言 / 补全 / 预测状态；
- 使用的工具、恶意软件、IOC 和影响资产；
- 前置效果和后续依赖；
- 报告原文证据；
- 处置与检测建议。

选中 IOC/实体：

- 规范值、别名、首次/末次出现；
- 当前行为中的角色；
- 同活动内其他使用位置；
- 跨报告/跨活动出现；
- 来源证据。

选中过程边：

- `A —[enables]→ B`；
- 前一步产生的效果；
- 来源是否明确表达依赖；
- 证据片段、置信度和审核状态；
- 若为补全/预测，显示支持的历史路径或技术依据。

### 5.4 泳道

泳道是同一 `ActivityGraph` 的第二种投影：

- 以 ATT&CK tactic 或产品自定义高层阶段分组；
- 行为实例仍是同一 ID；
- 点击泳道卡片同步选中上方图谱节点；
- 泳道顺序只服务阅读，不改写依赖边；
- 多分支在同一泳道内并排，汇合后重新合并；
- 可折叠未发生或仅有预测的阶段。

不能把 ATT&CK tactic 顺序当作后端补边规则。

### 5.5 时间视图

时间必须分三种：

- `execution_start/end`：攻击实际执行时间；
- `first_observed/last_observed`：IOC 或事实被观察的时间；
- `published_at`：报告发布时间。

三者不能混排。公开报告没有执行时间时显示“报告顺序未知”或时间窗，不使用报告发布日期伪造执行时间。Timesketch 式时间邻域适合做可选 Lens，不应替代主干图。

---

## 6. 一个完整案例应该怎样入图

假设报告证据描述：

> 用户打开 ZIP 中的 LNK。LNK 启动 PowerShell 下载 HeadLace。HeadLace 连接 cdn-meeting-update.com，并向解析地址 185.225.72.44 回传系统信息。

### 6.1 规范实体

```text
file: invitation.zip
file: invitation.lnk
process/tool: powershell.exe
malware: HeadLace
domain: cdn-meeting-update.com
ipv4: 185.225.72.44
attack-technique: T1204.002
attack-technique: T1059.001
attack-technique: T1082
```

### 6.2 行为实例

```text
A1 打开恶意 LNK
A2 执行 PowerShell
A3 下载 HeadLace
A4 收集系统信息
A5 向 C2 回传
```

### 6.3 行为依赖

```text
A1 --enables(code execution)--> A2
A2 --enables(payload retrieval)--> A3
A3 --enables(implant execution)--> A4
A4 --enables(collected data available)--> A5
```

### 6.4 上下文关系

```text
A1 --opens--> invitation.lnk
A1 --mapped-to-technique--> T1204.002
A2 --executes--> powershell.exe
A2 --mapped-to-technique--> T1059.001
A3 --downloads--> HeadLace
A4 --uses-malware--> HeadLace
A4 --mapped-to-technique--> T1082
A5 --uses-malware--> HeadLace
A5 --connects-to--> cdn-meeting-update.com
cdn-meeting-update.com --resolves-to--> 185.225.72.44
```

注意最后一条 `resolves-to` 是知识实体关系，不是攻击步骤边。前端可以在 A5 展开域名后继续展开 IP，但不能把“域名 → IP”插进主干。

### 6.5 证据

每个 A 节点和每条 dependency/context link 都引用原文片段。若证据只支持“PowerShell 和 HeadLace 同时被提及”，则不能自动创建 `A2 → A3 enables`；可以先保存两个行为和 `reported-before` 候选，进入复核。

---

## 7. 最小可用关系词表

比赛阶段不需要无限扩展本体。建议先控制在：

### 行为过程边

```text
enables
causes
reported-before
on-success
on-failure
alternative
join-and
join-or
```

### 行为—实体边

```text
delivers
opens
extracts
downloads-from
executes
loads
drops
creates
modifies
copies-as
invokes
connects-to
exfiltrates-to
exploits
targets
runs-on
collects-from
uses-malware
uses-tool
mapped-to-technique
produces
```

### 实体知识边

```text
resolves-to
communicates-with
contains
signed-by
affects
variant-of
alias-of
uses
attributed-to
```

前端必须按三类分开展示。实体知识边不能进入攻击主干，活动归因边不能冒充本次攻击事实。

---

## 8. 必须避免的结构

### 8.1 活动根节点挂满所有内容

```text
攻击活动
  ├─ IOC
  ├─ 工具
  ├─ 技术
  └─ 一条纯行为链
```

这种结构无法回答 IOC 对应哪一步，也无法生成逐步处置建议。

### 8.2 报告标题成为中心节点

```text
报告标题 --报告提及--> 组织/工具/IOC/技术/句子
```

这只是文档共现图。报告应作为证据容器，关系事实应有自己的来源引用。

### 8.3 完整句子成为节点

完整句子会造成重复、不可合并和视觉过载。原句属于 `evidence_span.quote` 或 `behavior_action.description`，不是 `label`。

### 8.4 所有顺序边都叫“攻击行为推进”

它隐藏了真正重要的差异：因果依赖、明确时间先后、条件分支、模型补全和预测。至少要区分 `enables`、`reported-before`、条件和候选状态。

### 8.5 IOC 强行塞进主干

IOC 不是攻击动作。主干应保持为行为；IOC 挂在其实际参与的行为上，并允许展开到更多实体知识关系。

### 8.6 把 ATT&CK 矩阵当成流程

ATT&CK tactics 无序。泳道可按战术稳定排布，但真实依赖边必须来自报告证据或明确标记的研判结果。

---

## 9. 对 ARGUS 当前目标最重要的落地顺序

这不是代码实施计划，而是数据结构的优先级：

1. 先把 `behavior_action` 与 `canonical_entity` 分开；
2. 把 IOC/工具/技术重新连接到具体行为；
3. 将过程边拆成明确类型，移除正式数据中的“攻击行为推进”；
4. 每个节点和边都绑定 `evidence_span`；
5. 引入 Activity 边界，允许一报告零/一/多活动；
6. 单独保存 `analysis_projection`，主干不再污染事实图；
7. 最后再补 Condition、AND/OR 和时间 Lens。

如果只做前三项，图谱的展示意义就会比当前结构明显提升：安全人员可以沿主干理解攻击过程，又能从每一步直接拿到 IOC、证据和处置锚点。

## 10. 最终定义

ARGUS 的攻击路径图谱应定义为：

> 在一个明确攻击活动范围内，以带证据的原子攻击行为为流程节点，以效果依赖、明确先后、条件和汇合为过程边，以规范化 IOC、工具、漏洞、技术和资产为行为上下文，并从完整事实图上生成面向 SOC 与应急响应的可审计主干投影。

对应的展示不是“把所有知识画出来”，而是：

```text
可读主干
  + 与具体步骤绑定的关键 IOC
  + 按需展开的完整事实支线
  + 同源同步的阶段泳道
  + 点击即可回到原文的节点/边证据
```

这套结构保留了 STIX/OpenCTI/MISP 的来源和实体治理能力，采用 ATT&CK 统一动作语义，采用 Attack Flow 表达真实分支与依赖，同时避免把通用知识图谱、时间线和攻击流错误地合并为一张图。
