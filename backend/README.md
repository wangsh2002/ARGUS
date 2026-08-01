# ARGUS 可解释路径后端

这一服务暴露两组边界清晰的能力。

在线研判接口（只读历史图谱，不产生图谱写入）：

- `POST /v1/sources`：按原文 SHA-256 归档来源，并生成可审计的段落锚点。
- `GET /v1/attack-flows`：列出当前保留的人工精选 AttackFlow V1。
- `GET /v1/attack-flows/{flow_id}`：读取带显式主干、行为上下文和证据的 AttackFlow V1。
- `POST /v1/flow-matches`：用行为、IOC、工具、恶意软件、漏洞或 ATT&CK 线索匹配多个 AttackFlow 候选。
- `GET /v1/flow-matches/{id}`：重放冻结的输入、候选、算法版本和知识快照。
- `GET /v1/runtime/catalog`：读取当前知识版本的搜索目录。
- `GET /v1/runtime/entities/{id}`：读取实体的证据、来源和关联 AttackFlow。
- `GET /v1/graph/nodes` 与 `GET /v1/graph/neighborhoods/{id}`：读取证据化全景图谱。

高保真入库接口（暂存、显式发布、可回滚）：

- `POST /v1/knowledge-ingestions`：生成实体消歧、关系证据、质量门和图谱增量预览；提交 `attack_flow_candidate` 时暂存一条复核候选，默认不写图。
- `GET /v1/knowledge-ingestions?status=staged`：读取待复核 AttackFlow 队列。
- `GET /v1/knowledge-ingestions/{id}`：读取冻结的入库预览。
- `PUT /v1/knowledge-ingestions/{id}`：修订待复核的 AttackFlow 候选并重新执行证据、关系、主干和 Context 校验。
- `POST /v1/knowledge-ingestions/{id}/reject`：拒绝单条暂存候选，不影响同一来源的其他候选。
- `POST /v1/knowledge-ingestions/{id}/publish`：全部硬性质量门通过后，事务发布一个知识版本。
- `POST /v1/knowledge-versions/{id}/rollback`：撤销该版本新增的证据、实体或 AttackFlow，保留审计记录。

AttackFlow 候选只提交局部 Action、Relation、Context、reported Actor 和精确
quote。后端重新在归档原文中定位 quote、解析规范实体并生成全局身份；未知关系、
断裂主干、Flow 外引用、缺证据或模糊 Context 都会阻塞发布。成功发布后可直接通过
`GET /v1/attack-flows/{id}` 读取，不依赖重新导出前端静态快照。

一个来源可以提交 `attack_flow_candidates` 数组。空数组形成明确的 no-flow 结果并
继续保留可发布的实体证据；多个元素会各自生成独立入库任务，分别修订、拒绝或
发布。单条候选预览会显示建议新建或建议合并及原因。合并必须提交已确认的
`merge_review` 和完整 Action 映射，并同时满足强 Context 身份锚点、兼容行为名称、
关系及主干顺序；共享 Actor 或 ATT&CK 技术本身不足以合并。发布合并只向现有 Flow
补充新 Source 的证据、Context 和 reported Actor claim，不复制 Action 或 Flow。
`flow_source_supports` 保证同一来源与 Flow 的支持关系及同一来源候选重复发布幂等。

未命中历史本体的行为和模糊命名实体会留在暂存区，避免未经消歧就污染历史图谱。
IP、域名、URL、哈希、CVE 和 ATT&CK 编号等强类型实体使用确定性规则规范化，
可以在保留原文写法与证据锚点的同时创建或复用全局实体。

来源文档不必包含攻击过程。纯 IOC 或仅有上下文的可信来源可以正常入库，
并以 `path_outcome.status = no-path` 和明确的 `no_path_reason` 保存；系统不会为了
得到攻击链而调用路径抽取或补写不存在的攻击步骤。

本地启动：

```bash
PYTHONPATH=backend uvicorn argus_backend.main:app --reload --port 8000
```

接口文档位于 `http://127.0.0.1:8000/docs`。

运行测试：

```bash
PYTHONPATH=backend pytest backend/tests -q
```

模型抽取只输出 AttackFlow V1 暂存候选。系统验证原文 quote、
解析 Context 身份、检查显式 mainline，然后交给待审队列。候选数为 0
时只使用确定性规则保留 IOC/CVE 实体证据。

## 历史攻击流基线

运行时只保留 APT28 Zebrocy、APT29 DNC 和 Lazarus Redbanc 三条人工精选
AttackFlow。旧分块抽取实验的缓存、批次输出和路径金标不再作为生产数据或回归
基线；后续抽取流程直接发布经过证据校验的 AttackFlow V1。

## 不完整线索匹配

`FlowMatchResult` 不修改历史 AttackFlow。它只为本次查询保存每条输入的命中原因、
未解释输入、候选分数、主干进度点，以及“输入命中 / 路径补全 / 后续预测”状态。
具体行为和 Context 是主要匹配依据；ATT&CK 只提供低权重辅助，不能单独选出候选。
没有候选达到阈值时返回空数组，不强行选择最相似的历史 Flow。

`query_text` 可以用换行、分号或 `→` 分隔多条线索；调用方也可以直接提交带
`value` 和 `kind` 的 `inputs` 数组。
