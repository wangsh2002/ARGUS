# ARGUS 公开威胁报告采集与语料治理策略

> 结论：ARGUS 不应在“自己爬取”和“直接使用已有报告库”之间二选一。最可靠的方案是：**已有权威结构化语料作为骨架，官方原始报告作为证据，白名单定向采集负责持续更新，MISP/abuse.ch 等 Feed 只负责发现线索和补充 IOC**。系统不做全网通用爬虫，也不把聚合平台中的二手关系直接当作攻击路径事实。

## 一、为什么不能只选一种来源

只依赖现成 Feed，接入快、格式整齐，但大多数 Feed 面向 IOC 交换，往往只有“IP/域名/样本—恶意软件—标签”，缺少攻击动作的先后关系、资产上下文和原文证据，无法支撑 ARGUS 的核心能力——可解释路径补全。反过来，全网爬取虽然量大，却会引入来源混杂、重复转载、页面改版、反爬限制、许可不明和抽取错误；“爬到了网页”并不等于获得可信情报。

真实性也不由格式是否统一决定。可信数据可以来自 PDF、HTML、JSON 或 STIX，关键是每个结论都能回到：发布机构、原始 URL、发布时间、原始文件哈希、页码/段落、采集时间和解析版本。**格式统一应发生在内部规范化层，原始材料必须原样保存。**

因此建议把采集过程拆成“发现、归档、解析、规范化、审核”五步。Feed 和索引用于发现候选报告；采集器只访问登记过的官方域名；原件进入不可变证据库；不同解析器生成统一的文档块；算法再从文档块产生待审核的实体、关系和路径断言。

## 二、推荐的四层来源体系

### L0：标准本体与标识符基线

这层不是报告语料，而是所有报告映射到的共同词表。

- 以 [MITRE ATT&CK STIX 2.1 官方仓库](https://github.com/mitre-attack/attack-stix-data)为组织、软件、Technique、Tactic 和外部引用的基线。官方说明 STIX 是 ATT&CK 最细粒度的机器可读表示，并提供官方 TAXII 服务；历史版本也按 Collection 保留，适合固定比赛数据快照。[ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/)
- ATT&CK 中 Group/Software 到 Technique 的 procedure relationship 可作为“某主体曾如何使用某技术”的高可信行为证据；其中的 `external_references` 和 citation URL 用来发现原始报告，但不能据此自动推断事件内的先后顺序。
- STIX 2.1 用作交换模型而非物理数据库。OASIS 将 Report、Indicator、Observed Data、Attack Pattern、Malware、Relationship、Sighting 等定义为标准对象；TAXII 2.1 是通过 HTTPS 交换 CTI 的 REST 协议。[STIX 2.1 介绍](https://oasis-open.github.io/cti-documentation/stix/intro.html)、[TAXII 2.1 介绍](https://oasis-open.github.io/cti-documentation/taxii/intro.html)

建议每月同步一次 ATT&CK，演示数据固定到明确版本；新版本先进入 staging，完成 ID 迁移、撤销对象处理和回归测试后再切换。

### L1：已人工整理的真实攻击路径“金标准”

这层最适合直接作为路径算法的训练、验证和经典案例库。

- [MITRE CTID Attack Flow 示例库](https://center-for-threat-informed-defense.github.io/attack-flow/example_flows/)提供公开事件的 Attack Flow、STIX、Mermaid 和图片下载，支持分支、条件和动作序列；官方仓库包含 corpus、JSON Schema，采用 Apache-2.0 许可。[Attack Flow 仓库](https://github.com/center-for-threat-informed-defense/attack-flow)
- [CTID Technique Inference Engine（TIE）](https://github.com/center-for-threat-informed-defense/technique-inference-engine)公开了 6,236 份 CTI Report 对应的 43,899 条 Technique 观测，覆盖 ATT&CK Enterprise v15 的 96%，数据位于仓库 `data` 目录，整体为 Apache-2.0。它非常适合做“报告—Technique 共现”和预测基线。

但 TIE 公开的主要是**报告引用与 Technique 标注数据，不等于把 6,236 份原始报告正文全部再发布**。其官方数据收集说明也表明，一部分标注来自 OpenCTI 中的 Report/TTP 关系。因此 ARGUS 应导入 TIE 的映射、URL、活动/组织标签和频次，再根据 URL 到原发布方归档可访问的原文；失效链接仍保留引用记录，不能伪造正文。[TIE 数据收集说明](https://github.com/center-for-threat-informed-defense/technique-inference-engine/tree/main/data/data%20collection)

比赛版先精选 30—50 个有清晰原文、多个分支和足够 TTP 的事件进行双人复核，比未经审核地导入数千份报告更有价值。Attack Flow corpus 可直接作为测试集；TIE 可作为大规模弱监督训练集，二者不能混成同一质量等级。

### L2：权威原始报告与安全公告

这一层采用“来源注册表 + 定向采集器”，而不是搜索引擎式全网爬虫。

优先来源包括：

1. [CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)：官方定义说明 Cybersecurity Advisory 通常包含威胁行为、TTP、IOC 和缓解措施，适合构建完整事件；分析报告和联合公告也可进入语料库。
2. [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)：官方提供 CSV、JSON 和 JSON Schema，是“已在野利用”及处置动作的权威结构化来源。官方 [kev-data 仓库](https://github.com/cisagov/kev-data)会在 canonical 网站更新后的数分钟内同步，适合每日增量。
3. 国家级 NCSC/CERT 官方发布页，例如 [英国 NCSC Reports & Advisories](https://www.ncsc.gov.uk/section/keep-up-to-date/reports-advisories)和 [CERT-EU Security Advisories](https://cert.europa.eu/publications/security-advisories/)。
4. 厂商原站的研究报告与博客，如 [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/security-insider/threat-intelligence-reports)、[Cisco Talos](https://blog.talosintelligence.com/)、[Google Threat Intelligence/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence)、[ESET Research](https://www.welivesecurity.com/en/)和 [Unit 42](https://unit42.paloaltonetworks.com/)。

对这些网站只做白名单适配器：RSS/API 优先，其次抓列表页和详情页；遵守 robots、限速、站点条款与撤稿状态。发布方网页只作为 canonical source，转载、新闻摘要和搜索结果只能用于发现，不进入证据层。

更新建议：CISA/KEV 每日；NCSC/CERT 每日或每周；厂商报告每周；经典案例人工触发重抓。发现正文发生变化时保存新版本，绝不覆盖旧版本。

### L3：聚合 Feed 与 IOC 丰富化

- [MISP Default Feeds](https://www.misp-project.org/feeds/)可快速导入公开 OSINT Event/Attribute；但不同 Feed 的采集方式、置信度和许可不同，必须按 feed 单独配置来源权重。MISP 事件关系可产生候选关联，不能直接成为因果边。
- OpenCTI 的 external-import connector 会从外部服务拉取信息、转换为 STIX 2.1 bundle；其 import-document 能处理 PDF、HTML、Markdown、Text，另有 STIX、MISP 和 CSV 导入机制。ARGUS 可借鉴 connector 状态、增量游标和原始结果隔离，不必为了比赛部署完整 OpenCTI。[OpenCTI Connectors](https://docs.opencti.io/latest/deployment/connectors/)、[OpenCTI 文件导入](https://docs.opencti.io/latest/usage/import-files/)
- [ThreatFox API](https://threatfox.abuse.ch/api/)提供带首次/末次发现、恶意软件、置信度和引用的 IOC；官方自 2025 年起会使超过六个月的 IOC 过期，正好说明 IOC 必须具有时间有效性。[URLhaus API](https://urlhaus.abuse.ch/api/)适合恶意 URL，[MalwareBazaar API](https://bazaar.abuse.ch/api/)适合样本哈希与元数据。

abuse.ch 数据只用于节点丰富化、IOC 时间线和报告候选发现，不用于证明“动作 A 导致动作 B”。社区 API受 fair-use 和商业用途条款约束，比赛可用，但产品化前必须重新核查授权；平台也明确没有为所有 abuse.ch 项目统一提供 STIX/TAXII。[ThreatFox FAQ](https://threatfox.abuse.ch/faq/)

## 三、多格式统一解析，而不是统一保存格式

每次采集先创建 `SourceArtifact`，字段至少包含：canonical URL、来源机构、标题、发布时间、采集时间、MIME、HTTP ETag/Last-Modified、SHA-256、许可/使用条款、TLP/数据标记、父页面和采集器版本。原件写入只读对象目录，解析产物与原件分离。

- **STIX/Attack Flow/MISP/JSON**：先用官方 schema 验证；保留原始对象 ID 和版本，转为内部实体、边、证据断言。校验失败进入隔离区，不“尽力修正”后悄悄入库。
- **CSV**：每个来源维护显式列映射、编码和日期规则；保存源行号。KEV 等结构化源按主键和版本增量更新。
- **HTML**：同时保存原始 HTML 和抽取后的正文；保留 DOM/CSS selector、标题层级、表格和字符区间，使证据能跳回原段落。脚本渲染页面必要时保存渲染快照。
- **PDF**：保存原 PDF；先做版面感知文本抽取并记录页码、块坐标，扫描版再 OCR；表格和图片说明单独成为块。页面文本不可只拼成一长串，否则引用页码和路径顺序都会失真。
- **图片/附件**：OCR 结果必须标记为机器识别；压缩包和恶意样本进入隔离存储，比赛版只保存哈希和公开分析元数据，不执行样本。

LLM 只能读取确定性解析后的文档块，输出带 `source_artifact_id + page/block/span` 的候选断言。它不得改写原文，也不得在没有证据位置时创建“已观测”关系。OCR/LLM 的模型、提示词、温度和输出 JSON 都纳入 `AnalysisRun`，保证可重放。

## 四、去重、可信度与人工审核

去重分三层：

1. SHA-256 相同：同一二进制原件，只增加新的获取 URL。
2. canonical URL、发布方、标题、发布日期相同：视为同一逻辑文档的不同版本。
3. 文本 MinHash/SimHash 高相似：标记转载或近重复，但不自动合并；官方原站优先，版本差异保留。

每个断言的可信度拆开记录，不输出一个不可解释的总分：来源等级、原文是否直接陈述、抽取方式、独立来源数、时间一致性、平台/资产兼容性和人工审核状态。建议审核状态为 `raw → parsed → machine-proposed → analyst-reviewed → published`。

人工审核聚焦高价值对象：所有进入经典演示的路径、所有系统补全的边、所有路径分叉/汇合、所有组织归因关系。IOC 和标准标识符可以规则自动通过；LLM 新建的行为边必须至少一名分析员确认。训练集、验证集按“事件/报告族”切分，避免同一报告的转载版本同时出现在训练和测试中。

## 五、比赛版最小落地方案

第一阶段不写通用爬虫，先完成：

1. 导入固定版本的 ATT&CK STIX、Attack Flow corpus、TIE 映射和 CISA KEV。
2. 从 Attack Flow 与 TIE 引用中选 30—50 份官方原始报告，归档 PDF/HTML，建立页码/段落级证据。
3. 为 CISA、NCSC/CERT 和 3—5 个厂商原站编写白名单适配器；所有解析结果先进待审区。
4. 接入 MISP Default Feeds 与 ThreatFox/URLhaus 作为 IOC 丰富化层，并设置有效期和来源权重。
5. 精修 5—10 个可分支的金标准案例，构造“遮蔽节点、删除边、截断后半段”的可复算评测集。

最终数据库中应同时存在三种明确区分的数据：**原始报告证据、人工确认的真实路径、算法生成的补全/预测假设**。这样既保留真实世界报告的复杂与异构，又能在前端用统一结构展示；评委点击任何节点或边，都能看到它来自哪份原报告、哪一页、谁确认过、算法为什么补全，以及还缺什么证据。

