# 开源攻击路径项目对比与 ARGUS 技术定位

## 研究问题

ARGUS 计划将报告中的自然语言行为映射到统一的 ATT&CK 语义空间，允许阶段缺失、分支和汇合，再进行跨报告对齐、路径补全、后续行为预测和逐边证据审计。本说明对照现有开源项目，判断这一组合是否有实际差异，并确定应直接借鉴的设计。

## 总结

单独来看，ARGUS 计划中的每一项能力都有开源先例：

- TRAM：报告文本到 ATT&CK 技术映射；
- RAF-AG：报告图、ATT&CK Procedure 对齐和路径解码；
- Attack Flow：分支、条件、汇合、资产和行为依赖的标准表达；
- TIE：根据已观测 ATT&CK 技术推断关联技术；
- OpenCTI/MISP：情报容器、实体关系、来源和分析员工作流。

ARGUS 的潜在差异不在于重新实现其中某一项，而在于将它们连接成一个以证据为中心的闭环：

```text
原文证据
  → 行为断言
  → ATT&CK/自定义动作规范化
  → 稀疏报告观察图
  → 跨报告活动对齐
  → 可解释路径重建
  → 有依据的后续行为预测
  → 处置建议
```

这个优势只有在系统严格区分“观测、跨报告补充、算法补全和预测”时成立。如果只是把 ATT&CK 节点按战术泳道排列，优越性并不存在。

## 项目对比

### TRAM

TRAM 是 MITRE Center for Threat-Informed Defense 的开源报告映射平台。它从人类可读 CTI 文本中识别 ATT&CK 技术，开箱支持常见技术，并提供数据标注和模型定制流程。当前公开说明强调 SciBERT 单标签/多标签模型和人工标注闭环。

来源：

- <https://github.com/center-for-threat-informed-defense/tram>

优势：

- 成熟的报告到 ATT&CK 映射任务定义；
- 句子级标注和分析员修正；
- 支持使用组织自己的数据重新训练；
- 可直接作为 ARGUS 映射评测基线。

局限于 ARGUS 目标：

- 输出重点是技术标签，不是行为实例；
- 不负责建立技术之间的时序、因果或条件边；
- 不负责跨报告判断是否属于同一攻击活动；
- 不负责路径补全和证据链展示。

ARGUS 应借鉴：

- 保留句子级标注任务；
- 保存分析员接受、拒绝和改标结果；
- 将低置信度映射进入待审队列；
- 用 TRAM 结果作为候选召回，而不是直接作为最终节点。

### RAF-AG

RAF-AG 是直接从 CTI 报告生成攻击路径的研究型开源实现。它先将报告转换成图，再与 ATT&CK Procedure 图进行对齐，最后进行路径解码。项目公开 30 份 CTI 报告及专家生成的 ground truth。

来源：

- <https://github.com/cyb3rlab/RAF-AG>

优势：

- 将报告图、Procedure 对齐结果和最终路径分层保存；
- 不把文本分类和路径解码混成一个模型；
- 使用 ATT&CK Procedure Examples，而不只使用技术标题；
- 提供可用于路径生成评测的专家标注数据。

局限于 ARGUS 目标：

- 研究流程以单份报告路径生成为中心；
- 公开设计没有解决生产级跨报告活动消歧；
- 路径证据、来源独立性和分析员审计不是其主要产品目标；
- 对复杂跨报告冲突和不同粒度表达的处理有限。

ARGUS 应借鉴：

- 严格分开 `report_graph`、`procedure_alignment` 和 `path_decoding`；
- 将 Procedure Examples 建成候选语义库；
- 用 RAF-AG 数据集做外部基线测试；
- 不让大模型从全文一步生成最终路径。

### Attack Flow

Attack Flow 是 MITRE CTID 建立的 STIX 2.1 扩展。`attack-action` 可以引用 ATT&CK tactic/technique，包含行为描述、执行时间、命令和资产；`effect_refs`、Condition 和 Operator 用于表达依赖、分支与汇合。官方特别说明，动作连接表达依赖关系，不只是“发生时间更早”。

来源：

- <https://center-for-threat-informed-defense.github.io/attack-flow/language/>
- <https://center-for-threat-informed-defense.github.io/attack-flow/introduction/>
- <https://github.com/center-for-threat-informed-defense/attack-flow>

优势：

- 已有公开 JSON Schema、校验器和示例语料；
- 原生支持分支、失败条件、AND/OR 聚合和资产；
- 与 STIX 生态兼容；
- 节点可带外部来源与置信度。

局限于 ARGUS 目标：

- 主要解决表达和编辑，不负责从自然语言自动抽取；
- 不负责跨报告实体/活动合并；
- 不定义“观测、重建、预测”的产品状态；
- 官方 Builder 更偏人工建模。

ARGUS 应借鉴：

- 内部图模型兼容 Attack Flow 的 Action、Condition、Operator、Asset；
- 导出 Attack Flow/STIX，而不是创造不可交换的私有格式；
- 将边理解为行为依赖或效果传递，不把段落顺序当作边；
- 复用其置信度术语和 Schema 验证；
- 用官方复杂示例作为分支渲染和导出测试集。

### Technique Inference Engine

TIE 根据已观测 ATT&CK 技术预测相关技术。公开数据包含 6,236 份 CTI 报告和 43,899 个技术观察，覆盖 ATT&CK Enterprise v15 的 96%。

来源：

- <https://github.com/center-for-threat-informed-defense/technique-inference-engine>
- <https://center-for-threat-informed-defense.github.io/technique-inference-engine/>

优势：

- 大规模公开“报告—技术”共现数据；
- 能为缺失技术和后续调查范围提供先验排序；
- 有可运行的基线和训练数据。

局限于 ARGUS 目标：

- “相关技术”不等于本次攻击的下一步；
- 报告级共现通常缺少真实顺序；
- 不能单独证明缺失边或因果关系；
- 输出更适合作为调查提示，而不是历史事实。

ARGUS 应借鉴：

- 将 TIE 作为候选生成器和先验概率；
- 结合当前节点、资产平台、活动簇和历史路径重新排序；
- 所有 TIE 结果保持为 `predicted`，直到出现独立证据；
- 评测时分开“候选召回率”和“真实后续步骤准确率”。

### OpenCTI

OpenCTI 将 Report、Grouping 和 Case 作为 Container，容纳实体和关系；关系本身是一等对象。其工作台允许导入、验证和人工修正后再写入知识库。

来源：

- <https://docs.opencti.io/latest/usage/manual-creation/>
- <https://docs.opencti.io/latest/usage/pivoting/>
- <https://github.com/OpenCTI-Platform/opencti>

优势：

- 成熟的来源、置信度、标记和知识图谱模型；
- 支持分析员调查、关系创建和增量扩展；
- 适合保存“谁声称了什么”。

局限于 ARGUS 目标：

- 通用情报图谱没有把攻击行为序列作为核心分析对象；
- 关系图不自动等于可解释攻击路径；
- 路径缺口与下一步预测不是主线能力。

ARGUS 应借鉴：

- 报告作为证据容器，而不是路径本身；
- 断言与规范实体分离；
- 关系保存来源、置信度、创建者和时间；
- 在写入历史知识库前设置分析工作台和审核状态。

### MISP

MISP 强于 IOC、对象、事件、自动关联和共享控制。Event Report 可以同时包含文本、属性、对象和可选关系。

来源：

- <https://www.misp-project.org/features/>
- <https://github.com/MISP/MISP>

优势：

- IOC 解析、去重、关联和 Warning Lists 成熟；
- Event/Object 模型适合接收多种情报；
- TLP、共享组和分析员协作能力成熟。

局限于 ARGUS 目标：

- IOC 相关性不是攻击步骤依赖；
- Event Graph 不保证表达真实行为顺序；
- 不负责自动构建跨报告 Attack Flow。

ARGUS 应借鉴：

- IOC 解析优先使用确定性规则；
- 引入误报/保留地址/公共基础设施 Warning Lists；
- 将 TLP、许可和共享范围贯穿报告、证据与导出；
- 不把“共享 IOC”直接解释成“同一攻击活动”。

## ARGUS 真正可能形成的优势

### 1. 稀疏语义对齐

报告行为映射到：

```text
ATT&CK tactic
  + technique/sub-technique
  + canonical action signature
  + subject/object/asset
```

相比只输出技术标签，Action Signature 能区分同一技术在不同上下文中的行为实例。中间阶段允许为空，同一阶段允许重复和分支。

### 2. 跨报告的路径级融合

OpenCTI/MISP 处理实体和一般关系，RAF-AG 处理单报告路径。ARGUS 可以把跨报告活动消歧、节点图对齐和证据补充作为主任务：

- 同一事件才合并；
- 相似行为只标记为 variant/related；
- 一条路径可引用多份独立报告；
- 冲突不覆盖，作为并列断言保留。

### 3. 观测、补全和预测严格分层

这是产品可信度的核心：

- `source-observed`
- `cross-source-corroborated`
- `algorithm-reconstructed`
- `algorithm-predicted`
- `curator-confirmed`

同一张图中可以联动展示，但数据库和导出不能混淆。

### 4. 逐节点、逐边解释

Attack Flow 支持外部引用，OpenCTI 支持来源关系；ARGUS 可以进一步把原文行号、引用哈希、映射候选、合并理由和预测依据统一放进节点/边审计面板。

### 5. 从图到行动

多数项目停留在标签、图谱或预测。ARGUS 的产品目标是让 SOC 二线和应急响应人员从路径直接得到：

- 已观测行为对应检测覆盖；
- 缺口节点的排查建议；
- 预测步骤的重点监控；
- IOC、资产和证据导出；
- 可解释处置方案。

## 必须避免的伪优势

- “使用 ATT&CK”不是优势，已经是行业常规。
- 把节点放进战术泳道不是路径重建。
- TIE 的共现预测不能包装成“下一步一定发生”。
- 大模型生成一条通顺路径不代表事实正确。
- 两份报告使用相同 PowerShell 技术不代表同一活动。
- 节点越多不代表分析能力越强。

## 推荐落地顺序

1. 兼容 Attack Flow 内部图模型与导出格式。
2. 建立 TRAM 风格的句子级 ATT&CK 候选和人工修正记录。
3. 按 RAF-AG 分层保存报告图、Procedure 对齐和路径解码。
4. 实现稀疏阶段对齐与不同粒度 Action Signature。
5. 实现跨报告活动候选召回和图对齐，先不自动合并。
6. 接入 TIE 作为补全/预测候选先验。
7. 将预测映射到检测与处置建议。
8. 用 Attack Flow 示例、RAF-AG ground truth 和 ARGUS 金标准案例分别评测结构、抽取和实战效果。

## 建议评测指标

- 行为节点抽取 Precision / Recall / F1
- ATT&CK Technique Top-1 / Top-3 Accuracy
- 显式关系抽取 F1
- 路径节点和边 F1
- 分支/汇合结构准确率
- 跨报告同活动 Pairwise F1
- 节点对齐准确率
- 路径补全 Recall@K
- 下一步预测 Hit@K / MRR
- 有证据节点比例
- 有证据边比例
- 分析员平均修正次数

## 最终判断

该方案有明确的组合优势，但目前应表述为“技术路线优势”，不能宣称已经超过现有项目。只有完成跨报告活动对齐、证据分层和面向处置的闭环，并用外部数据集验证后，才能形成可信的比赛亮点。
