# ARGUS CTI 前端

ARGUS 是面向威胁情报检索、攻击链匹配、报告综合分析与可解释归因的前端工作台。

当前数据由 `data/argus_cti.db` 同源导出。启动或构建前可执行：

```bash
npm run data:sync
```

本地开发与构建：

```bash
npm run dev
npm run build
npm test
```

当前 GPT 页面只实现交互界面；模型服务尚未接入，因此不会返回模拟答案。文件分析支持 TXT、JSON 与 Markdown，并只匹配数据库中已有事实。
