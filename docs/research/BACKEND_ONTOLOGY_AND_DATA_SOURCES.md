# ARGUS 后端算法、本体与公开数据源研究

> 范围：面向 SOC 二线分析员和应急响应人员，只使用公开威胁情报。来源仅采用官方规范、官方文档与官方仓库。最后核对：2026-07-28。

## 1. 架构结论

STIX、ATT&CK、Attack Flow、CACAO 不是四选一，而是不同层：

| 层级 | 采用方案 | ARGUS 中的作用 |
|---|---|---|
| 通用 CTI 与交换 | **STIX 2.1** | 组织、Campaign、恶意软件、工具、漏洞、IOC、报告、关系、来源引用、版本和置信度 |
| 行为知识骨架 | **MITRE ATT&CK** | Tactic、Technique/Sub-technique、Group、Software、Mitigation、Data Component 的标准词表 |
| 一次事件的路径 | **MITRE/CTID Attack Flow** | Action、Asset、Condition、AND/OR、Effect 组成的有向分支图 |
| 处置模型 | **OASIS CACAO 2.0 子集** | Investigation、Detection、Mitigation、Remediation 的可读/可导出 Playbook |
| 标签与生态兼容 | **MISP** | Event 导入导出、TLP/估计语言/来源标签和社区 Feed |

STIX 2.1 官方定义自己是表达网络威胁与可观测信息的语言，包含 SDO、SCO、Relationship、Sighting、外部引用和版本机制；它适合作为交换语义，但不是数据库物理模型。[OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)

ATT&CK 是基于真实观察的对手行为知识库，官方以 STIX 2.1 Collection 发布 Enterprise、Mobile 和 ICS 数据。[ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/)、[ATT&CK STIX Data](https://github.com/mitre-attack/attack-stix-data)

Attack Flow 是 STIX 2.1 扩展，能表达顺序、条件、成功/失败分支和汇聚，最适合 ARGUS 的“主路径 + 分支 + 补全 + 预测”；Action 也允许不映射 ATT&CK，因而能保留报告中的事件粒度行为。[Attack Flow Language](https://center-for-threat-informed-defense.github.io/attack-flow/language/)、[Introduction](https://center-for-threat-informed-defense.github.io/attack-flow/introduction/)

CACAO 2.0 定义 Playbook、Workflow Step、Command、Agent、Target 和条件控制。比赛版只实现阅读、Markdown/PDF/CACAO JSON 导出，不做自动封禁或隔离。[OASIS CACAO 2.0](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html)

因此推荐：

> **STIX 2.1 作通用语义和交换外壳，ATT&CK 作行为词表，Attack Flow 作事件路径，CACAO 子集作处置；另建 ARGUS 证据断言与算法运行层。**

## 2. ARGUS 领域模型

不建议另造一套大而全 OWL 本体。基础对象直接映射：

- APT 组织档案 → `intrusion-set`；未确认活动簇 → `campaign` 或内部 `activity-cluster`；
- 恶意软件、合法双用途工具、漏洞、ATT&CK 技术 → `malware`、`tool`、`vulnerability`、`attack-pattern`；
- IOC 检测模式 → `indicator`；IP、域名、Hash、文件、进程 → SCO；
- 原始报告 → `report`；处置 → `course-of-action` + CACAO Playbook；
- 本次具体行为 → `attack-action`，引用 ATT&CK `attack-pattern`。

Observable 是事实数据，Indicator 是检测模式，不能混用；OpenCTI 也明确区分两者。[OpenCTI Observations](https://docs.opencti.io/latest/usage/exploring-observations/)

STIX 的 `confidence` 不足以表达前端已有的四种事实状态，应增加内部模型：

- `SourceDocument`、`SourceSpan`：URL、内容哈希、页码/段落/offset；
- `AnalysisRun`：输入、算法配置、模型版本、Prompt 版本、知识快照；
- `Assertion`：对实体、边或路径步骤的一条判断；
- `AssertionState`：`observed`、`reconstructed`、`predicted`、`candidate`、`refuted`；
- `EvidenceLink`：Assertion 指向 SourceSpan，区分支持、反证和上下文；
- `ScoreComponent`：实体、路径、时间、来源、反证等分项贡献；
- `ReviewDecision`：分析员确认、修改、拒绝及理由。

硬约束：

1. 高置信预测仍不是观测事实；
2. 每条边必须有自己的证据，不能用两个节点各自的来源证明边；
3. Flow Action 是事件实例，ATT&CK Technique 是行为类型，两者分开；
4. 补全、预测和归因必须能按知识快照复算；
5. LLM 输出只进入 Draft，确认后才写主图谱。OpenCTI Analyst Workbench 也是“连接器识别 → 草稿审核 → 验证入库”。[OpenCTI Workbench](https://docs.opencti.io/latest/usage/workbench/)

存储上，比赛版建议 **PostgreSQL + pgvector + 对象存储 + NetworkX/igraph**：PostgreSQL 作唯一事实源，pgvector 做候选召回，图算法库完成路径和聚类。数据量证明在线多跳成为瓶颈后，再增加 Neo4j 图投影；不要一开始双写两套主库。

## 3. 传统算法与 AI 的边界

原则是：**LLM 负责读、提议和解释；确定性代码、统计模型和图算法负责校验、排序、约束和留痕。**

| 任务 | 传统算法/确定性职责 | LLM 职责 |
|---|---|---|
| 文档与 IOC | PDF/HTML/OCR、哈希、页码定位；IP/域名/URL/Hash/CVE/ATT&CK ID 正则、refang、校验 | 修复破碎文本，识别不规则提及 |
| 实体抽取/消歧 | ID、别名、时间、平台、邻域；BM25/向量召回与阈值拒识 | 受 Schema 约束提出候选，解释 Top-K |
| 关系抽取 | 类型白名单、方向、否定、时间约束，要求 SourceSpan | 抽取主谓宾和模态候选 |
| 活动聚类 | 时间窗、共享资产/身份/工具、图社区发现、相似度 | 簇命名，解释候选缺边 |
| 路径补全 | 子图检索、K 最短路/Beam Search、资产连续性、平台、时间和 ATT&CK 阶段弱序 | 为候选步骤生成解释和验证缺口 |
| 下一步预测 | Technique 共现/转移矩阵、Markov/序列模型、校准和平台过滤 | 将统计依据写成研判说明 |
| 组织归因 | 多证据加权、时间衰减、路径相似、来源可靠性、反证扣分 | 汇总支持与反证，不决定候选排名 |
| 处置建议 | CVE/Technique/资产/阶段规则映射 CACAO 模板 | 去重、改写成当前案例语言 |
| 证据溯源 | 哈希、页码/offset、边—证据、模型版本和快照 | 只做摘要，不能生成来源 |

实体消歧应先用 external ID/别名生成候选，再结合名称、向量、邻域、时间和来源打分；只有名称相似时不得自动合并。OpenCTI 也把 canonical 属性去重、合并、置信度和规则推断作为独立数据质量能力。[OpenCTI Data Processing](https://docs.opencti.io/latest/reference/data-processing/)

“两个簇其实是一条链”必须显式处理：先以同章节、时间、资产和明确因果形成高精度初始簇，再根据共享资产、工具、漏洞、连续阶段和历史路径生成 `candidate` 缺边。高分也先进入“建议合并”，不能让 LLM 因为叙事通顺就造边。

路径补全不是 LLM 续写：从历史 Attack Flow、Technique 共现/转移、工具与资产前置条件生成候选，再以时间、平台、资产连续性和来源过滤、重排。MITRE/CTID Technique Inference Engine 从已观察 Technique 预测相关 Technique，其公开训练数据有 6,236 份 CTI 报告和 43,899 条观测，可作为下一步预测基线；但它产生的是关联预测，不是事件事实。[TIE 官方仓库](https://github.com/center-for-threat-informed-defense/technique-inference-engine)

归因建议拆分为工具重合、Technique 重合、有序路径相似、带时间衰减的基础设施、目标/时间兼容、来源可靠性和反证。IOC 权重应低于稳定工具和 TTP 组合；输出“候选 + 支持/反证”，不要伪装成统计概率。

处置由规则先生成：CVE 关联厂商公告/KEV，Technique 关联 ATT&CK Detection/Data Component/Mitigation，Observable 关联日志与检索范围，预测 Action 关联待验证信号。LLM 只能改写已检索模板，不能发明修复版本、命令、IOC 或执行破坏性动作。

## 4. 数据来源

第一优先级是结构化权威基线：

| 来源 | 用途 | 边界 |
|---|---|---|
| ATT&CK STIX 2.1 | 标准 ID、别名、组织、软件、TTP、缓解 | 锁定 release，保留 deprecated/revoked |
| CISA KEV | 已确认在野利用、要求动作 | 证明在野利用，不证明本事件已利用 |
| NVD API 2.0 | CVE、CVSS、CPE、CWE、引用 | 修复结论优先厂商公告 |
| FIRST EPSS | 未来 30 天利用概率与 percentile | 不是完整风险分 |
| CWE / CAPEC | 弱点根因、攻击模式和前置条件 | 不能替代 ATT&CK 或机械一一映射 |

CISA 提供 KEV JSON/CSV；NVD API 支持按修改时间增量同步；FIRST 每日发布 EPSS；CWE/CAPEC 提供官方 XML/CSV。[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)、[NVD API](https://nvd.nist.gov/developers/vulnerabilities)、[FIRST EPSS](https://www.first.org/epss/)、[CWE Downloads](https://cwe.mitre.org/data/downloads.html)、[CAPEC Downloads](https://capec.mitre.org/data/archive.html)

第二优先级是 CISA/NCSC/CERT、Microsoft、Cisco Talos、Mandiant、Unit 42、ESET 等发布方的一手报告和厂商公告。这些文本是 Attack Flow、组织画像和处置证据的主来源。必须保存原 URL、发布者、时间、内容哈希和页码/段落；`confirmed`、`assessed`、`likely`、`associated with` 不得归一成同一强度。CISA 官方说明其 Cybersecurity Advisory 通常包含 TTP、IOC 和缓解措施。[CISA Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)

第三优先级是 abuse.ch：

- ThreatFox：IOC、威胁类型、恶意软件标签；旧 IOC 会过期，关系必须有时间范围；
- MalwareBazaar：样本 Hash 与元数据；Web 服务默认不下载/解压恶意样本；
- URLhaus：恶意 URL 和 Payload 关联。

[ThreatFox API](https://threatfox.abuse.ch/api/)、[MalwareBazaar API](https://bazaar.abuse.ch/api/)、[URLhaus API](https://urlhaus.abuse.ch/api/)

MISP 作为 Connector 和标签兼容层：导入 Event/Attribute/Object/Galaxy/Event Report，保留 UUID、Org、时间和源 URL。MISP 自动 Correlation 包含相同属性、模糊 Hash、CIDR 等，只能生成候选 `related-to`，不能直接成为 Attack Flow 因果边。[MISP Data Models](https://www.misp-project.org/datamodels/)、[MISP Features](https://www.misp-project.org/features/)

## 5. 开源项目实现对照

| 项目 | 后端与表达 | 借鉴 | 不照搬 |
|---|---|---|---|
| OpenCTI | STIX 2.1 知识图谱；External Import、Analysis、Enrichment、File、Stream Connector；Report、关系来源和推断 | Connector 生命周期、Draft 审核、来源/关系证据、规范化 | 全量实体、消息队列和通用推理复杂度 |
| MISP | Event/Attribute/Object/Galaxy/Taxonomy、Feed、Sync、Correlation | 批量 IOC、分享标签、社区生态 | 把相关图当因果路径或归因证据 |
| Attack Flow Builder | STIX 扩展、Schema 校验、Action/Asset/Condition/Operator、可编辑分支 | 事件路径语义、人工修边、导出和官方 Corpus | 从空白画布手工作为主流程 |
| ATT&CK Workbench | STIX 2.1 Object、Collection/Index、REST API、MongoDB、可选 TAXII | ATT&CK 版本锁定、官方与本地扩展分离 | 它是知识维护工具，不是事件调查后端 |
| IntelOwl | Analyzer、Connector、Pivot、Ingestor、Playbook、Investigation Job | 分析器输入类型、状态、重试、原始结果隔离 | Analyzer JSON/Job 分支不是统一本体或攻击路径 |
| Yeti | Observable、Entity、Indicator、Link；Feed/Analytics；ArangoDB | Observable 校验、双向 Pivot、轻量插件 | 任意 Link/共享 Tag 不能直接成为路径边 |

官方资料：[OpenCTI Data Model](https://docs.opencti.io/latest/usage/data-model/)、[OpenCTI Connectors](https://docs.opencti.io/latest/deployment/connectors/)、[MISP 官方仓库](https://github.com/MISP/MISP)、[Attack Flow Builder](https://center-for-threat-informed-defense.github.io/attack-flow/builder/)、[ATT&CK Workbench](https://github.com/mitre-attack/attack-workbench-frontend)、[IntelOwl Usage](https://intelowlproject.github.io/docs/IntelOwl/usage/)、[Yeti Concepts](https://yeti-platform.io/docs/key-concepts/)

## 6. 实施顺序

1. 先建立 SourceDocument、SourceSpan、Assertion、AnalysisRun 和固定版本 ATT&CK；
2. 接入 KEV、NVD、EPSS，完成 IOC/ID 确定性提取；
3. 用 JSON Schema 约束 LLM 抽取，进入活动簇 Draft 审核；
4. 生成 STIX 图谱和 Attack Flow，完成受约束路径补全；
5. 建 Technique 转移预测、多证据归因、反证和 CACAO 处置模板；
6. 再扩展官方报告、abuse.ch、MISP、CAPEC/CWE Connector。

必须评测实体/关系 F1、实体链接 Accuracy@1/Recall@K、活动聚类 B-cubed、补全/预测 Hit@K/MRR/校准、归因 NDCG 与证据覆盖率。**所有 Assertion 100% 可回到 SourceSpan；无源结论必须为零。**

最终决策应记录为 ADR：STIX 兼容但不直接以 Bundle 作数据库；ATT&CK 是行为基线；每个活动簇采用 Attack Flow；处置采用只读 CACAO 子集；MISP 是交换层；LLM 不拥有最终裁决权；PostgreSQL 先做唯一事实源。
