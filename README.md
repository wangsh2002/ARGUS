# ARGUS 可追溯攻击链研判前端

ARGUS 是一个以查询为入口的威胁情报工作台。它把 IOC 详情、可编辑攻击链、历史报告总结、参考处置建议、关系图谱和 GPT 辅助组织在同一条研判流程中。归因只作为辅助假设，不是产品的唯一目标。

产品范围和验收标准见 [`docs/ARGUS_FRONTEND_SPEC.md`](docs/ARGUS_FRONTEND_SPEC.md)。

## 本地运行

当前数据由 `data/argus_cti.db` 同源导出：

```bash
npm run data:sync
```

本地开发与构建：

```bash
npm run dev
npm run build
npm test
```

调查草稿保存在浏览器 `localStorage`。打印视图可导出 PDF，工作台也支持 Markdown 和 JSON。

## ARGUS GPT

复制 `.env.example` 后配置任意 OpenAI-compatible `chat/completions` 服务：

```bash
ARGUS_LLM_BASE_URL=https://your-provider.example/v1
ARGUS_LLM_API_KEY=replace-me
ARGUS_LLM_MODEL=your-model
```

GPT 会接收当前案件节点和来源上下文。它建议的新节点必须由用户确认后才会加入草稿；模型未配置时页面会明确显示离线状态，不返回模拟答案。

## 数据边界

- 页面只展示当前 SQLite 快照支持的实体和属性。
- 公开报告仅保存元数据、ARGUS 结构化摘要与原文链接，不复制完整文章。
- 所有建议仅供分析参考，不直接执行封禁、隔离或配置变更。
