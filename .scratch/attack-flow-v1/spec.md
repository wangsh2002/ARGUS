---
type: spec
status: ready-for-agent
feature: attack-flow-v1
created: 2026-08-01
revision: 2
---

# ARGUS AttackFlow V1 数据标准与运行链路改造规格

## Problem Statement

ARGUS 已经具备较完整的综合查询、攻击路径研判、攻击组织、情报入库、路径复核、历史报告和全景图谱页面，也已经存在来源归档、实体规范化、历史路径、行为关系、行为上下文和证据等数据库结构。然而，当前产品并没有一个贯穿抽取、审核、存储、查询和前端展示的稳定攻击流契约。

同一个攻击过程目前分别以通用实体关系、`activity_path` 记录、报告事件图、路径分析响应和前端 `Snapshot`/候选卡片等不同形状出现。主干有时依靠顺序字段或前端规则推断，历史事实与查询时的补全、预测状态也存在混用风险。在线匹配主要在通用“攻击步骤”实体上工作，不能稳定利用行为旁的 IOC、工具、恶意软件和漏洞，且一次只选择一个活动候选。前端启动时仍主要读取构建期导出的静态快照，因此数据库中的更新不能自然成为所有页面的实时数据来源。

此前的报告抽取实验进一步放大了这一问题：模型输出结构复杂、质量门和前端展示结构相互耦合，结果即使抽取成功，也难以稳定发布为前端真正需要的“清晰主干 + 行为旁关联内容”。如果继续先调抽取提示词、再临时适配前端，系统会不断增加转换层，模型能力和产品效果都难以可靠评估。

本次工作需要先确定一个简单、证据优先的 AttackFlow V1 标准，再让持久化、运行时 API 和现有前端围绕该标准收敛，最后重写抽取链路。V1 必须复用现有数据库和产品页面中已经正确的部分，不能为了追求理想化图谱推倒重建，也不能在替代链路完成前删除仍被运行时使用的代码。

## Solution

ARGUS V1 只引入两个长期稳定的外部领域契约：

- **AttackFlow**：保存一项攻击活动中有来源支持的行为过程。它包含来源、报告声称的攻击组织、行为 Action、行为间关系、显式主干、行为旁 Context 和证据。它是攻击链页面与全景图谱共享的事实基础，不包含任何特定查询的补全或预测状态。
- **FlowMatchResult**：描述一次输入与一条 AttackFlow 的匹配结果。它包含候选得分、具体命中、未解释输入、主干进度点以及本次查询下的输入命中、路径补全和后续预测状态。它是分析运行结果，不会反向修改历史 AttackFlow。

抽取暂存结果复用 AttackFlow 的核心形状，但使用临时局部标识和未解析 Context 名称；它不是第三套长期数据模型。发布阶段由系统验证原文引用、解析规范实体、确认主干和关系约束，再以事务写入正式 AttackFlow。模型不生成全局实体身份、不计算匹配得分、不决定查询状态，也不需要理解数据库表或前端组件。

数据库继续使用现有 SQLite 规范化结构并做增量演进。AttackFlow 是领域接口而不是单一 JSON 存储格式；Repository 负责在规范化的 Flow、Action、Relation、Context Link、Source、Actor Claim 和 Evidence 记录之间组装与拆解。历史基线只迁移 APT28 Zebrocy、APT29 DNC 和 Lazarus Redbanc 三条人工精选路径；后续模型实验路径不进入正式接口，其缓存、批次输出和专用金标在依赖核验后删除。查询结果继续作为带算法版本和知识快照的分析运行保存。

前端保留当前页面、导航、布局和“横向主干 + 附近关联内容”的展示方式，但攻击链、查询匹配和图谱数据改为运行时读取后端。主干严格使用 AttackFlow 提供的顺序；IOC、工具、漏洞、资产等只作为 Action 的 Context 展示；FlowMatchResult 再对同一主干叠加“输入命中 / 路径补全 / 后续预测”。构建期快照仅作为迁移期间的兼容入口，最终不再是正式运行数据源。

## User Stories

1. As a threat intelligence analyst, I want one stable AttackFlow shape across extraction, review, storage and display, so that the meaning of the data does not change between product stages.
2. As a threat intelligence analyst, I want one AttackFlow to describe one attack activity rather than one source document, so that report boundaries do not create false process boundaries.
3. As a threat intelligence analyst, I want one report to yield zero, one or multiple AttackFlows, so that IOC-only reports and multi-activity reports are represented honestly.
4. As a threat intelligence analyst, I want multiple sources to support the same AttackFlow, so that corroborating reports strengthen one activity instead of duplicating it.
5. As a threat intelligence analyst, I want behavior occurrences to be the process nodes, so that the graph describes what happened rather than a list of indicators and software names.
6. As a threat intelligence analyst, I want each Action to have a concise verb-object name and a separate description, so that the mainline remains readable without losing detail.
7. As a threat intelligence analyst, I want source sentences stored as evidence rather than node titles, so that long report prose does not become unreadable graph labels.
8. As a threat intelligence analyst, I want IOC, tools, malware, vulnerabilities, accounts, files and assets attached to the relevant Action, so that context remains visible without pretending to be process progression.
9. As a threat intelligence analyst, I want Action Context to use controlled types and roles, so that extraction output and frontend labels remain consistent.
10. As a threat intelligence analyst, I want every published Action to have verified source evidence, so that unsupported model output cannot enter the historical graph.
11. As a threat intelligence analyst, I want every published Action Relation to have verified source evidence, so that the system does not fabricate a complete-looking chain.
12. As a threat intelligence analyst, I want Context links and reported actor claims to retain their own evidence, so that supporting details remain independently auditable.
13. As a threat intelligence analyst, I want uncertain relationships omitted rather than saved at low confidence, so that uncertainty is not disguised as graph structure.
14. As a threat intelligence analyst, I want temporal order, progression, enablement, causation and explicit success or failure transitions distinguished, so that relations communicate more than a generic next step.
15. As a threat intelligence analyst, I want branch and merge structure represented by ordinary Action Relations, so that V1 does not require special branch nodes or nested workflow syntax.
16. As a threat intelligence analyst, I want one explicit representative mainline stored for each AttackFlow, so that the product can render a stable chain without guessing.
17. As a threat intelligence analyst, I want alternate actions to remain connected outside the mainline, so that a readable representative path does not erase real branches.
18. As a threat intelligence analyst, I want ATT&CK technique identifiers to be optional annotations, so that valid behavior is not rejected because technique mapping is uncertain.
19. As a threat intelligence analyst, I want ATT&CK names and tactics resolved by the system, so that the model does not duplicate or contradict the reference catalog.
20. As a threat intelligence analyst, I want report-provided actor attribution preserved as a sourced claim, so that the report's statement is visible without becoming an ARGUS-confirmed conclusion.
21. As a threat intelligence analyst, I want conflicting actor claims to coexist, so that disagreements between sources are not hidden by premature merging.
22. As a SOC analyst, I want a partial set of clues to match known AttackFlows, so that an incident can be recognized before every step is observed.
23. As a SOC analyst, I want one query to return multiple ranked flow candidates, so that the system does not hide plausible alternatives behind one forced selection.
24. As a SOC analyst, I want behavior text and attached Context values to match Actions, so that an IOC or tool can locate the stage where it was used.
25. As a SOC analyst, I want every hit to explain whether it matched behavior, Context or an optional ATT&CK annotation, so that the reason for the candidate is visible.
26. As a SOC analyst, I want unmatched inputs preserved in each candidate result, so that I can see what the historical flow does not explain.
27. As a SOC analyst, I want the furthest matched mainline Action to define current progress, so that reconstruction and prediction follow a simple deterministic rule.
28. As a SOC analyst, I want unmatched mainline Actions at or before current progress shown as path reconstruction, so that gaps in supplied evidence are visible.
29. As a SOC analyst, I want unmatched mainline Actions after current progress shown as subsequent prediction, so that the remaining historical continuation is clearly separated from observed input.
30. As a SOC analyst, I want Context matches labeled as input hits rather than direct behavior observations, so that the UI does not overstate what the query proves.
31. As a SOC analyst, I want directly matched alternate Action branches highlighted without automatically predicting every unmatched branch, so that side paths are not presented as inevitable.
32. As a SOC analyst, I want candidate scores calculated by the system and accompanied by match details, so that model self-confidence does not determine ranking.
33. As a SOC analyst, I want matching results frozen with algorithm and knowledge versions, so that a past analysis can be replayed and audited after the knowledge base changes.
34. As a SOC analyst, I want candidate cards to summarize hits, unexplained clues, progress and confidence, so that I can select a path before opening its full detail.
35. As a frontend user, I want the current horizontal mainline and attached-content layout retained, so that the data migration does not force a product redesign.
36. As a frontend user, I want relation labels and conditions visible between Actions, so that the process can be understood without opening every detail panel.
37. As a frontend user, I want evidence available from existing node and relation detail interactions, so that every displayed fact can be traced to a source.
38. As a frontend user, I want all current product pages and navigation retained, so that the migration does not remove working capabilities.
39. As a frontend user, I want newly published knowledge to become visible without rebuilding a static data file, so that the interface reflects the current database.
40. As a graph investigator, I want AttackFlows, Actions, Entities, Actors and Sources to use stable identities, so that they can participate in one panoramic graph.
41. As a graph investigator, I want to begin from an IOC and reach related Actions, AttackFlows, Sources and reported Actors, so that investigations can move from a clue to its context.
42. As a graph investigator, I want to begin from an Actor, Source, AttackFlow or Action and traverse the same evidence-backed graph, so that navigation works in either direction.
43. As a graph investigator, I want cross-level shortcut edges generated dynamically, so that the overview is readable without storing duplicate facts.
44. As a graph investigator, I want every aggregated shortcut to expose its underlying path, so that graph convenience does not reduce explainability.
45. As a knowledge curator, I want extraction candidates isolated from published AttackFlows, so that review and correction occur before permanent graph changes.
46. As a knowledge curator, I want exact evidence quotes verified against archived source text, so that hallucinated or altered quotations are rejected.
47. As a knowledge curator, I want system-owned Context identity resolution at publication time, so that spelling variants can reuse one canonical Entity.
48. As a knowledge curator, I want the model prevented from assigning global Entity or Actor identities, so that temporary extraction choices cannot corrupt identity resolution.
49. As a knowledge curator, I want equivalent strong indicators merged deterministically while ambiguous names remain reviewable, so that automation is used only where safe.
50. As a knowledge curator, I want publication to be atomic and rollback-compatible, so that a failed validation cannot partially modify the graph.
51. As a knowledge curator, I want an IOC-only or context-only report to publish useful entity evidence without creating an AttackFlow, so that the system does not force every report into a chain.
52. As a developer, I want AttackFlow assembled behind one application and repository seam, so that routes, scripts and UI components do not each invent their own conversion rules.
53. As a developer, I want the existing normalized SQLite corpus evolved rather than replaced, so that current curated evidence and identities remain usable.
54. As a developer, I want the attack path matcher to operate on AttackFlow and Action Context rather than generic entity labels, so that matching follows the new domain standard.
55. As a developer, I want frontend migration to use an explicit compatibility adapter, so that old and new reads can coexist while each workflow is converted.
56. As a developer, I want external behavior tests to protect existing user workflows, so that internal refactoring does not silently change the product.
57. As a maintainer, I want legacy runtime modules removed only after no production caller remains, so that cleanup cannot break ingestion or review.
58. As a maintainer, I want obsolete experiment outputs and caches removed once the retained baseline is fixed and dependency checks pass, so that abandoned research artifacts no longer obscure the production system.

## Implementation Decisions

- AttackFlow is the single canonical interface for a published historical attack activity. It is an aggregate over normalized records, not an opaque database blob and not a frontend-only view model.
- FlowMatchResult is the canonical interface for one query candidate. It references an immutable AttackFlow identity and carries only query-relative information.
- Extraction staging reuses the AttackFlow core shape with local temporary identifiers and unresolved Context names. It does not introduce a third permanent domain contract.
- An AttackFlow contains a schema version, stable identity, title, optional summary, supporting Source references, reported Actor claims, Actions, Action Relations and an explicitly ordered mainline of Action identities.
- One AttackFlow represents one attack activity. A Source may support zero, one or multiple AttackFlows, and an AttackFlow may have evidence from multiple Sources.
- Cross-report flow merging is system- and curator-owned. Shared Actor names or ATT&CK techniques alone are insufficient; strong anchors and compatible behavior structure are required before proposing a merge.
- An Action is an occurrence inside one AttackFlow, not a globally canonical behavior entity. Actions with similar labels in different flows remain separate occurrences unless a later ontology feature explicitly relates them.
- An Action contains a stable flow-scoped identity, concise name, optional description, qualitative confidence, optional ATT&CK technique identifiers, Context links and Evidence references.
- Action names follow a concise verb-object convention suitable for the mainline. Full report sentences belong in descriptions and Evidence.
- Model-facing Context contains type, name and role. Published Context additionally contains a system-resolved canonical Entity identity.
- Context types are controlled and cover malware, tool, asset, vulnerability, file, process, account, infrastructure, IP address, domain, URL, hash and other.
- Context roles are controlled and cover uses, targets, communicates-with, exploits, downloads-from, drops-on, runs-on, modifies, creates and other.
- Context describes participants and objects around an Action. It never determines mainline order and is never converted into a process Action merely to make it visible.
- Action Relation types are restricted to `precedes`, `leads_to`, `enables`, `causes`, `on_success` and `on_failure`. Optional human-readable condition text may further explain an outcome edge.
- `precedes` means evidence-backed temporal order only. It does not imply dependency or causation.
- Branch and merge are graph topology, not relation types. Multiple outgoing relations form a branch and multiple incoming relations form a merge.
- Every published Action and Action Relation requires at least one verified Evidence reference. Context links and reported Actor claims also retain evidence appropriate to their own assertion.
- Evidence references an archived Source and exact quote. The system verifies the quote and computes its span or locator; model-provided offsets are never trusted.
- Unsupported Action Relations are omitted. Low confidence is not a substitute for missing evidence.
- Extraction confidence for published facts uses `high`, `medium` or `low`. Numeric values from legacy data may be mapped during migration, but the extraction model is not asked for false percentage precision.
- ATT&CK identifiers are optional and secondary. The system resolves technique names and tactics from its catalog, and ATT&CK-only similarity has lower matching influence than concrete behavior or Context.
- Reported Actor claims are Flow-level sourced assertions with reported name, optional resolved Actor identity, Source, confidence and Evidence. They are not platform-confirmed attribution.
- The mainline is stored explicitly as a unique ordered list of Action identities. Every identity must belong to the Flow, and every adjacent pair must be connected by a published Action Relation.
- Mainline order is not inferred by the frontend, ATT&CK tactic order, Action array order or a topological sort at read time.
- Non-mainline Actions remain ordinary Actions connected by ordinary relations. V1 does not add Condition, AND, OR, retry or branch container nodes.
- FlowMatchResult contains Flow identity, numeric candidate score, detailed matches, unmatched inputs, mainline frontier and query-relative Action states.
- A detailed match retains the original input value and type, target Action identity, match kind, matched behavior or Context value and numeric match confidence.
- Supported match kinds are behavior, Context and ATT&CK annotation. Context and behavior are primary; ATT&CK annotation is optional supporting evidence rather than the main selection key.
- Candidate matching returns multiple results above a defined threshold and uses deterministic tie-breaking. A lack of sufficient match returns no candidate rather than selecting an unrelated Flow.
- The mainline frontier is the furthest mainline Action matched by behavior or attached Context. If only a non-mainline Action matches, it may support the candidate but does not move the frontier without an evidence-backed connection to a mainline position.
- In a candidate with a mainline frontier, matched mainline Actions are input hits, unmatched mainline Actions at or before the frontier are reconstructed, and unmatched mainline Actions after the frontier are predicted.
- A directly matched non-mainline Action is marked as an input hit. Other non-mainline Actions retain reference styling unless a later, separately specified branch-projection rule can classify them without overstating certainty.
- Query-relative states are never persisted on AttackFlow Actions or Relations. Relation styling is derived from endpoint states at presentation time.
- A Flow match run stores its normalized inputs, candidate results, algorithm version and knowledge snapshot so the exact historical analysis can be replayed.
- The backend evolves the existing normalized activity-path, Action Context, Source, Entity and Evidence structures rather than creating a parallel graph store.
- Persistence gains first-class support for explicit mainline position, many-to-many Flow Sources and sourced reported Actor claims where current structures do not already represent them.
- Legacy assertion states that mix reconstructed or predicted content into historical path facts are not carried into published AttackFlow. Such states belong in analysis runs; migration must report unsupported legacy facts rather than silently promote them.
- Repository operations expose publish, read, list and migration behavior in AttackFlow terms. Callers do not read or write individual persistence rows to assemble a Flow.
- Application operations expose Source archiving, ingestion staging, reviewed publication, AttackFlow retrieval, Flow matching, analysis replay and graph-neighborhood expansion through one service boundary.
- Existing source archive, knowledge-ingestion publication, rollback and review workflows are extended rather than replaced with an unaudited direct browser write endpoint.
- AttackFlow list and detail reads are runtime backend operations. The browser accesses them through the existing same-origin server route boundary.
- The panoramic graph reads normalized atomic facts shared with AttackFlow. Stored relationships include Flow membership, Flow Source support, Action Context, reported Actor claims and Evidence references.
- Actor-to-IOC, Flow-to-IOC and similar cross-level shortcuts are dynamically aggregated graph projections. They are never persisted as independent facts and must expose their underlying path.
- The current generic entity/relationship graph remains available during migration, but attack-process matching moves to AttackFlow Actions and Action Context rather than generic labels and event metadata.
- The current build-time Snapshot remains only as an expand-contract compatibility source while workflows migrate. The final runtime path no longer requires regenerating a static JSON file to see newly published knowledge.
- Frontend adapters isolate AttackFlow and FlowMatchResult from legacy `Snapshot`, investigation-case and candidate-card shapes. UI components do not depend on database rows, extraction payloads or report-event-graph internals.
- Existing page names, navigation, major interactions, horizontal mainline, side Context, evidence panels, review workflow and visual design remain unchanged unless a data field no longer has truthful support.
- User-facing query labels are “输入命中”, “路径补全” and “后续预测”. A Context hit must not be described as direct observation of the behavior.
- The new extraction pipeline outputs zero to many staged Flow candidates per Source and targets the simplified AttackFlow core fields directly.
- The extraction model proposes local Actions, allowed Relations, Context names, reported Actor names, mainline and exact Evidence quotes. System code performs quote verification, identity resolution, ATT&CK enrichment, validation and publication.
- Existing extraction and report-event-graph modules remain behind the compatibility path until the new pipeline passes source-to-review-to-publication tests. Cleanup is a final contract step, not part of initial schema work.
- Generated experiment outputs, caches and obsolete commands are removed only after dependency search proves they are not used by the runtime, tests or retained evaluation workflow.

## Testing Decisions

- Tests assert behavior through the highest stable seam. Backend product behavior is tested through FastAPI HTTP requests; frontend behavior is tested through rendered user workflows; database internals are tested only where migration or transaction guarantees cannot be observed more safely at a higher seam.
- Existing backend API tests are the primary prior art for Source archiving, path analysis, staging, publication, rollback and report graph retrieval. They should be extended around AttackFlow operations rather than replaced with repository-mocking tests.
- Existing frontend interaction tests are the acceptance seam for navigation, path candidates, path detail, ingestion, review, actor views and graph exploration. Tests should assert visible user behavior rather than component state or adapter implementation.
- Migration tests run on a disposable copy of the current SQLite snapshot. They verify that current curated paths, Action order, relations, Context links, identities, Sources and Evidence remain available after migration.
- Contract round-trip tests publish a representative AttackFlow through the application or HTTP boundary and read it back without losing mainline order, branch topology, relation semantics, Context identities, Actor claims or Evidence.
- Validation tests reject missing Action Evidence, missing Relation Evidence, unverified quotes, unknown relation types, repeated or unknown mainline Actions and adjacent mainline Actions without a connecting relation.
- Atomicity tests prove that any validation or identity-resolution failure leaves the published knowledge graph unchanged and that successful publication remains rollback-compatible.
- Source-cardinality tests cover a Source producing no Flow, one Flow and multiple Flows, plus multiple Sources supporting one existing Flow.
- Flow-merging tests prove that matching Actor or ATT&CK values alone does not merge activities, while curator-approved strong anchors can attach new Source evidence to an existing Flow.
- Entity-resolution tests reuse existing deterministic canonicalization prior art and cover refanged IOC values, exact indicator equivalence, alias reuse and ambiguous software names requiring review.
- Matcher tests cover behavior hits, Context hits, lower-weight ATT&CK hits, unmatched inputs, no candidate, multiple ranked candidates and deterministic ties.
- Progress tests use an incomplete five-step mainline with matches at the beginning, middle and end to verify the exact frontier, reconstruction and prediction rules.
- Branch tests prove that a directly matched alternate Action can support a candidate without flattening branches into false adjacent mainline edges or predicting every side branch.
- Replay tests verify that saved match runs retain normalized inputs, algorithm version, knowledge snapshot and candidate details after the underlying knowledge base changes.
- Graph tests start independently from IOC, Actor, Source, AttackFlow and Action identities, then verify bidirectional traversal through normalized atomic relationships.
- Graph aggregation tests prove that shortcut edges are generated with explainable underlying paths and never appear as stored atomic relationships.
- Frontend tests verify that mainline order comes from AttackFlow, Context remains attached to the correct Action, relation labels remain visible and the three query states come only from FlowMatchResult.
- Runtime-data tests verify that a newly published Flow can appear in attack-chain and graph views without regenerating a build-time snapshot.
- No-path ingestion tests preserve existing behavior: trustworthy IOC-only or context-only Sources may publish Entity evidence without inventing an AttackFlow.
- Extraction acceptance tests use fixed archived report fixtures and verify zero-flow, multi-flow, branch, conflicting attribution, unsupported relation and quote-verification cases through the staging boundary.
- Cleanup is accepted only after backend tests, frontend interaction tests, build, dependency search and retained extraction evaluation all pass without the removed modules or generated artifacts.

## Out of Scope

- Redesigning the existing frontend information architecture, navigation or visual language.
- Removing the existing intelligence-ingestion, path-review, actor, report, panoramic-graph or GPT pages.
- Replacing SQLite with Neo4j or another graph database.
- Making STIX Attack Flow import or export a V1 requirement.
- Creating a global ontology that merges equivalent Action occurrences across different AttackFlows.
- Adding explicit Condition, AND, OR, retry, fallback or branch container nodes before real source cases require them.
- Allowing arbitrary model-defined Action or Relation types.
- Requiring every Action to map to ATT&CK.
- Asking the model to assign canonical Entity, Actor, Source or Flow identities.
- Treating report-provided Actor attribution as an ARGUS-confirmed conclusion.
- Fully automatic cross-report activity merging without curator review.
- Automatically publishing model extraction output without evidence verification and existing review controls.
- Defining a machine-learned ranking model or promising a fixed scoring formula in V1.
- Persisting matched, reconstructed or predicted state on historical AttackFlow facts.
- Persisting dynamically aggregated Actor-to-IOC or Flow-to-IOC shortcuts as facts.
- Deleting legacy runtime code before replacement workflows pass the agreed external tests.
- Cleaning unrelated repository files or removing current product content that is still used.

## Further Notes

- This design intentionally distinguishes the **saved historical flow** from the **query interpretation of that flow**. “后续预测” means continuation along a known historical reference Flow; it is not a claim that the attacker will certainly perform the action in the current incident.
- The existing database already contains most required normalized concepts. The preferred implementation is an expand-contract migration: add missing invariants and interfaces beside current behavior, migrate one workflow at a time, then remove obsolete representations only after full cutover.
- The most important storage correction is not a table rename. It is enforcing that published AttackFlow contains only sourced historical facts, while reconstructed and predicted states live exclusively in versioned analysis runs.
- The most important frontend correction is not a visual rewrite. It is making the saved mainline authoritative and applying FlowMatchResult as a separate overlay instead of deriving semantics from static card data.
- The most important extraction correction is reducing model responsibility. Model quality should be judged on evidence-backed Actions, Relations and Context within one activity; identity resolution, scoring, publication and graph aggregation remain deterministic system responsibilities.
- The implementation should prefer one deep AttackFlow application module over many format converters spread across routes, scripts and components.
- The superseded ticket draft has been removed. After this replacement spec is accepted, `/to-tickets` must derive a new ticket set from this document rather than restoring the previous breakdown.
