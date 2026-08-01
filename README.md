# ARGUS 可追溯攻击链研判前端

ARGUS 是一个以查询为入口的威胁情报工作台。它把 IOC 详情、可编辑攻击链、历史报告总结、参考处置建议、关系图谱和 GPT 辅助组织在同一条研判流程中。归因只作为辅助假设，不是产品的唯一目标。

产品范围和验收标准见 [`docs/ARGUS_FRONTEND_SPEC.md`](docs/ARGUS_FRONTEND_SPEC.md)。

## 本地运行

前端运行时通过后端 API 读取当前知识版本，开发和构建不依赖静态数据导出。
`lib/argus-data.json` 只是前端交互测试显式注入的固定 fixture，不存在生产更新命令。

## 原始报告语料

论文数据集只作为原文获取渠道，不导入其实体、标签或关系。当前首批使用
AnnoCTR 的 6 份完整报告文本；每份文本都固定 SHA-256，并核验原发布方页面。
重新导入时需要提供官方 AnnoCTR 仓库根目录：

```bash
sqlite3 data/argus_cti.db < data/migrations/011_evidence_first_corpus.sql
python3 scripts/import_report_corpus.py \
  --source-root /path/to/anno-ctr-lrec-coling-2024
npm run data:corpus:verify
```

`source_artifacts/source_spans` 保存原件与证据位置；
导入原始语料不会自动生成实体、关系或攻击流；
`activity_paths/activity_path_nodes/activity_path_edges` 只保存通过现行抽取和审核流程发布的历史路径；
算法补全和预测仍保存在研判运行中，不会混入历史路径。首批来源选择与审核记录见
[`docs/research/CTI_RAW_CORPUS_INITIAL_BATCH.md`](docs/research/CTI_RAW_CORPUS_INITIAL_BATCH.md)。

本地开发与构建：

```bash
npm run dev
npm run build
npm test
```

`npm run dev` 会同时启动桌面前端（`3001`）和算法后端（`8000`），并在其中
一项异常退出时停止另一项，避免页面仍可访问但提交时显示连接中断。需要单独调试时：

```bash
npm run dev:frontend
npm run dev:backend
PYTHONPATH=backend pytest backend/tests -q
```

桌面演示只需运行 `npm run dev`。前端通过同源
`/api/flow-matches` 使用当前 AttackFlow 与 Action Context 对输入进行多候选匹配。

在线研判与历史知识图谱严格分开：在线查询只生成可审计的分析快照，不写入
历史图谱；顶部“情报入库”页面会先生成 AttackFlow 或实体证据预览，
只有全部硬性质量门通过并由用户确认后，才发布一个可回滚的知识版本。

后端把来源原文、证据锚点、研判快照和知识版本记录保存在同一份 SQLite 中。经典
Jaguar Tooth 请求样例和接口说明见
[`backend/README.md`](backend/README.md)。

调查草稿保存在浏览器 `localStorage`。打印视图可导出 PDF，工作台也支持 Markdown 和 JSON。

## ARGUS GPT

复制 `.env.example` 后配置 DeepSeek 的 OpenAI-compatible `chat/completions` 服务：

```bash
ARGUS_LLM_BASE_URL=https://api.deepseek.com
ARGUS_LLM_API_KEY=replace-me
ARGUS_LLM_MODEL=deepseek-v4-pro
```

GPT 会接收当前案件节点和来源上下文。它建议的新节点必须由用户确认后才会加入草稿；模型未配置时页面会明确显示离线状态，不返回模拟答案。

当前历史攻击链只保留 APT28 Zebrocy、APT29 DNC 和 Lazarus Redbanc 三条
人工精选路径。旧模型抽取实验及其缓存、批次输出和路径金标已移除；后续抽取直接
以 AttackFlow V1 为目标，不再迁移这些实验结果。

## 数据边界

- 页面只展示当前 SQLite 运行时知识版本支持的实体和属性。
- 公开报告仅保存元数据、ARGUS 结构化摘要与原文链接，不复制完整文章。
- 所有建议仅供分析参考，不直接执行封禁、隔离或配置变更。
