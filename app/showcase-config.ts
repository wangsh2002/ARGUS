export const curatedIntelLabels = [
  "95.179.131.29",
  "ReconHellcat",
  "PowerRatankba",
  "FlawedGrace",
  "Cobalt Strike",
];

export const curatedHomeReports = [
  {
    title: "ReconHellcat Uses NIST Theme as Lure To Deliver New BlackSoul Malware",
    note: "投递、C2、下载、浏览器数据收集与回传形成完整闭环",
  },
  {
    title: "Whatta TA: TA505 Ramps Up Activity, Delivers New FlawedGrace Variant",
    note: "完整展示邮件投递、宏执行、加载器与 FlawedGrace 落地",
  },
  {
    title: "APT28 Delivers Zebrocy Malware Campaign using NATO Theme as Lure",
    note: "适合演示输入命中、缺失步骤补全与后续行为预测",
  },
  {
    title: "As Delta Variant Spreads, COVID-19 Themes Make Resurgence In Email Threats",
    note: "一份报告关联四条独立攻击流，适合多链对比",
  },
  {
    title: "New Evidence Might Link Lazarus Tool Found in Chile RedBanc Intrusion to Previous Attacks in Pakistan",
    note: "四步紧凑链路连接 PowerShell、C2 与关键 IOC",
  },
  {
    title: "Cobalt Strike: Favorite Tool from APT to Crimeware",
    note: "三步聚焦 BazaLoader、Cobalt Strike 与后续载荷",
  },
];

export const curatedIntelReportTitles = curatedHomeReports
  .slice(0, 5)
  .map((report) => report.title);

export const curatedPathReportTitles = [
  curatedHomeReports[0].title,
  curatedHomeReports[1].title,
];

export const curatedPathExamples = [
  {
    label: "APT28 部分链路补全",
    query:
      "Drop Zebrocy malware executable → Create scheduled task for persistence",
    note: "2 个命中·1 个补全·1 个后续预测",
    requiredActions: [
      "Drop Zebrocy malware executable",
      "Create scheduled task for persistence",
    ],
  },
  {
    label: "ReconHellcat 后续行为预测",
    query:
      "Deliver NIST-themed CAB by spearphishing → Connect loader to Cloudflare-hosted C2",
    note: "2 个命中·1 个补全·3 个后续预测",
    requiredActions: [
      "Deliver NIST-themed CAB by spearphishing",
      "Connect loader to Cloudflare-hosted C2",
    ],
  },
  {
    label: "两条 EDR 告警·双攻击流分流",
    query:
      "EDR alert A: Create scheduled task for persistence; EDR alert B: Drop and detonate FlawedGrace",
    note: "同一批输入分别命中 APT28 与 TA505，保留未解释线索",
    requiredActions: [
      "Create scheduled task for persistence",
      "Drop and detonate FlawedGrace",
    ],
  },
];

export const curatedGptExamples = [
  {
    label: "总结 APT28 与 Zebrocy 攻击路径",
    query: "根据公开报告总结 APT28 使用 Zebrocy 的攻击路径与关键 IOC",
    note: "组织、恶意软件、IOC 与历史行为联合分析",
    requiredLabels: ["APT28", "Zebrocy"],
  },
  {
    label: "梳理 PowerRatankba 攻击过程",
    query: "梳理 Lazarus 使用 PowerRatankba 的攻击过程和处置重点",
    note: "结合历史报告与关联实体",
    requiredLabels: ["PowerRatankba"],
  },
];

export const curatedGraphRoots = [
  {
    label: "95.179.131.29",
    title: "从 C2 验证漏洞利用链",
    description: "沿 443/8080 通信回溯 CVE-2018-0798、PoisonIvy 与原文证据。",
  },
  {
    label: "ReconHellcat",
    title: "从组织跨活动追踪",
    description: "连接 BlackSoul、BlackWater、投递行为、C2 与两份来源报告。",
  },
  {
    label: "CVE-2017-0199",
    title: "从漏洞反查多条攻击链",
    description: "核验漏洞在 TA800 与 Leviathan 历史活动中的不同用法。",
  },
  {
    label: "FlawedGrace",
    title: "从恶意软件追溯投递链",
    description: "查看 TA505 投递、加载器、关联 IOC 与原始报告。",
  },
  {
    label: "Cobalt Strike",
    title: "从工具横向查看历史活动",
    description: "跨报告查看工具与攻击步骤、IOC 和组织的关联。",
  },
];
