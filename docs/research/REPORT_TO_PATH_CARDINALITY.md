# 威胁报告与攻击路径的基数关系

## 结论

威胁报告与攻击路径不应建模为一对一，也不应要求每份报告至少生成一条路径。更合理的关系是：

- 一份报告可以支持零条、一条或多条攻击路径；
- 一条攻击路径可以引用一份或多份报告；
- 报告中的实体、行为和关系可以在尚未组成路径时独立保存；
- “没有形成路径”是合法分析结果，但必须记录原因、处理状态和已提取内容。

因此，ARGUS 应采用 `Report 0..N <-> 1..N ActivityPath` 的多对多关系，并在报告侧单独保存分析运行记录。

## 开源项目与标准的做法

### STIX 2.1

OASIS STIX 2.1 将 Report 定义为引用若干 STIX 对象的情报容器。`object_refs` 可以包含实体或关系，但 Report 与攻击序列之间没有强制关系。STIX 的图由对象和关系逐步组成，并不要求一个 Report 构成连通路径。

- STIX 2.1 规范：<https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html>

### OpenCTI

OpenCTI 将 Report、Grouping 和 Case 明确视为 Container。报告“包含”实体和关系，而不是自身等同于调查图或攻击路径。导入文档后，提取内容进入工作台，经验证后才写入知识库；关系也可以由分析员另行创建。

- OpenCTI 手工创建与关系模型：<https://docs.opencti.io/latest/usage/manual-creation/>
- OpenCTI 文件导入：<https://docs.opencti.io/6.4.X/usage/import-files/>
- OpenCTI 调查图：<https://docs.opencti.io/latest/usage/pivoting/>

### MISP

MISP Event/Event Report 可以保存属性、对象、文本和可选关系。其图谱能力用于浏览已存在的关联，而不是要求每个 Event Report 都构成顺序攻击链。对象之间的引用和分析员关系是可选的增量知识。

- MISP 功能与数据模型：<https://www.misp-project.org/features/>
- MISP Objects：<https://www.misp-project.org/2017/09/18/misp.2.4.80.released.html>

### MITRE ATT&CK 与 TRAM

ATT&CK 用于标准化行为与技术映射，TRAM 从报告文本中识别 ATT&CK 技术；识别出若干技术并不代表获得了这些技术之间的时序或因果边。因此“已完成技术抽取”和“已形成路径”必须是两个状态。

- CTID/TRAM：<https://github.com/center-for-threat-informed-defense/tram>
- MITRE ATT&CK：<https://attack.mitre.org/resources/>

### Attack Flow

Attack Flow 是独立于 Report 的行为序列对象。一个有效 Attack Flow 自身必须有起点，但其外部证据可以引用多份报告；规范没有要求每份被引用报告单独对应一条 Flow。官方示例也以事件、活动、恶意软件或攻击树为建模范围，而不是按文档数量建模。

- Attack Flow 语言规范：<https://center-for-threat-informed-defense.github.io/attack-flow/language/>
- Attack Flow 示例集：<https://center-for-threat-informed-defense.github.io/attack-flow/example_flows/>

### RAF-AG

RAF-AG 是少数直接从 CTI 报告自动生成攻击路径的开源研究实现。它仍然将报告图、过程对齐结果和最终解码路径分成不同输出层，说明“报告图存在”不等于“成功解码出路径”。

- RAF-AG：<https://github.com/cyb3rlab/RAF-AG>

## ARGUS 建议模型

### 1. 报告分析运行

每份已处理报告必须有一条 `report_analysis_run`，而不是必须有一条路径：

- `status`: pending / extracting / reviewed / failed
- `extracted_entity_count`
- `extracted_behavior_count`
- `supported_relation_count`
- `activity_cluster_count`
- `path_count`
- `no_path_reason`
- `parser_version`
- `review_state`

`path_count = 0` 是允许的，但 `no_path_reason` 必须明确，例如：

- `ioc-only`
- `strategic-context-only`
- `malware-capability-only`
- `insufficient-sequence-evidence`
- `disconnected-observations`
- `duplicate-evidence`
- `parser-failed`

### 2. 报告观察图

所有带原文证据的实体、行为与关系先进入 `report_observation_graph`。它允许：

- 多个不连通分量；
- 只有节点、没有顺序边；
- 同一行为存在多个候选规范化名称；
- 关系方向或时序尚未确定。

### 3. 攻击活动簇

从观察图中识别零个或多个 `activity_cluster`。一个活动簇可以跨报告合并，也可以将一份汇总报告拆成多个独立活动。簇只是分析边界，不保证已形成路径。

### 4. 攻击路径

只有在存在可解释的时序、因果、条件或数据流关系时才生成 `activity_path`。路径应标记：

- `observed-fragment`
- `reconstructed`
- `predicted-extension`
- `curator-confirmed`

每个节点和边继续保留来源、推理依据、置信度和生成方式。

## 对当前六份报告的处理

当前六份均是技术型活动报告，按正文内容判断，大概率都能形成至少一条观察路径。但这是这批样本的内容特征，不应上升为全库约束。

正确做法是补齐尚未整理的 Mustang Panda、NetWire 和 APT28 报告路径，同时修改校验逻辑：

- 删除“报告已分析则必须存在路径”的设想；
- 改为“报告已分析则必须存在分析运行结果”；
- 当路径为零时要求填写可审计原因；
- 仅对明确标记为 `path-bearing` 且复核完成的报告检查路径覆盖率。
