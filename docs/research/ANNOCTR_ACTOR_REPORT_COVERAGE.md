# AnnoCTR 攻击组织报告覆盖与扩充策略

更新日期：2026-07-30  
目标：将每个去重后的真实攻击组织或独立活动簇扩充到约 3 篇高质量报告；不足时明确保留缺口，不用背景提及或低质量转载凑数。

## 结论

AnnoCTR 本地副本共包含 400 篇报告原文，但只有 train、dev、test 三个精标 split 提供实体链接金标；其余 280 篇 `ext` 原文不能当成已确认的组织归属。按照 `GROUP` 金标统计：

- 716 条组织提及；
- 60 篇带 `GROUP` 标注的报告；
- 70 个不同的 `label_link`；
- 其中 38 个直接链接到 MITRE ATT&CK Group，31 个是 Bosch 私有节点，另有 1 个错误链接到 ATT&CK Software；
- 经别名归并和非组织项清理后，得到 **65 个可用真实组织或独立活动簇**；
- **14 个组织已有至少 3 篇严格金标报告**；
- **9 个组织有 2 篇，还差 1 篇**；
- **42 个组织只有 1 篇，还差 2 篇**；
- 要把全部 65 个组织补到 3 篇，严格口径下还缺 **93 个“组织—报告”关联**。

因此，不应将“70 个 GROUP 实体”直接显示成 70 个攻击组织。平台当前更合理的目标是：

1. 以 MITRE ATT&CK Group ID 作为优先规范键；
2. Bosch 私有节点保留为独立活动簇，只有证据明确时才并入 ATT&CK 组织；
3. 先复核 AnnoCTR 的 280 篇扩展原文，再从 ATT&CK 引用和一线厂商原始报告补齐；
4. 没有三篇可信报告的长尾组织允许显示“覆盖不足”，不强行补满。

## 当前实施进度

在上述严格金标基线之上，已对 AnnoCTR `ext` 原文完成第一批人工复核：

- 接纳 9 篇报告，形成 12 条有精确行级证据的“组织—报告”关系；
- 明确拒绝 1 条背景命中：`Baza Valentine's Day` 原文说明该活动不属于 TA800；
- 达到至少 3 篇的组织从 14 个增至 17 个；
- 2 篇覆盖组织为 14 个，1 篇覆盖组织为 34 个；
- 距离全部 65 个组织达到 3 篇仍缺 82 条有效“组织—报告”关系。

本批次使 Golden Chickens、mummy-spider / TA542、TA800 达到或超过
3 篇，并为 Patchwork、Magic Hound / TA453、Mustang Panda / TA416、
TA551、TA544、TA574 各补充了一篇可信报告。人工决策、证据行与拒绝原因
保存在 `data/corpus/annoctr_ext_actor_review.json`。

## 数据范围和可信边界

AnnoCTR 论文说明，该数据集以完整威胁报告为单位进行细粒度标注，实体和安全概念会链接到 Wikipedia 与 MITRE ATT&CK；论文与数据集采用 CC-BY-SA 许可。[AnnoCTR 论文](https://aclanthology.org/2024.lrec-main.103/)、[Bosch Research 官方仓库](https://github.com/boschresearch/anno-ctr-lrec-coling-2024)

本次统计固定在本地上游提交：

```text
d510b6949e1938d47c93a43eedd562dc538439dc
```

关键文件如下：

```text
AnnoCTR/all/splits.tsv
AnnoCTR/all/text/<document>.txt
AnnoCTR/linking/train.jsonl
AnnoCTR/linking/dev.jsonl
AnnoCTR/linking/test.jsonl
AnnoCTR/entities/mitre_entity.jsonl
```

split 分布为：

| Split | 报告数 | 是否有人工实体链接金标 |
|---|---:|---|
| train | 70 | 是 |
| dev | 16 | 是 |
| test | 34 | 是 |
| ext | 280 | 否，只能作为待复核原文 |
| 合计 | 400 | — |

`all/text` 中的内容是数据集保存的 plaintext/Markdown 版本，不一定是发布机构最初的 PDF；文件名通常能恢复发布方、日期和标题片段，但数据集没有完整、独立的原始 URL 清单。因此后续入库时仍需反查原始页面，并记录 URL、发布时间、SHA-256、MIME、许可/TLP 和证据位置。

## 统计与归并方法

### 1. 严格金标统计

仅遍历以下三个文件：

```text
AnnoCTR/linking/train.jsonl
AnnoCTR/linking/dev.jsonl
AnnoCTR/linking/test.jsonl
```

过滤条件：

```text
entity_type == "GROUP"
```

分组键必须使用 `label_link`，不能使用 `mention` 或 `label_title`。报告数按去重后的 `document` 计算，别名按 `mention` 汇总。

可复核的 `jq` 命令：

```bash
jq -s '
  [.[] | select(.entity_type == "GROUP")]
  | sort_by(.label_link)
  | group_by(.label_link)
  | map({
      label_link: .[0].label_link,
      label_title: .[0].label_title,
      reports: (map(.document) | unique),
      aliases: (map(.mention) | unique)
    })
' AnnoCTR/linking/{train,dev,test}.jsonl
```

不要使用 `_w_neg.json`、`_w_con.json` 或 `_w_con_w_neg.json` 变体统计组织证据；这些文件是实体链接实验样本，会加入上下文或负例。

### 2. 规范化决策

| 原始实体 | 处理 | 依据 |
|---|---|---|
| Bosch `APT40` | 并入 `G0065 Leviathan / APT40` | ATT&CK 将 APT40、Leviathan、TEMP.Periscope 和 TEMP.Jumper列为同一组织的关联名称。[G0065](https://attack.mitre.org/groups/G0065/) |
| Bosch `Cozy Bear` | 并入 `G0016 APT29` | ATT&CK 将 Cozy Bear 列为 APT29 的关联名称。[G0016](https://attack.mitre.org/groups/G0016/) |
| Bosch `Emissary Panda` | 规范为 `G0027` | ATT&CK 将 Emissary Panda、APT27、LuckyMouse 等列为同一组织的关联名称。[G0027](https://attack.mitre.org/groups/G0027/) |
| Bosch `Fancy Bear` 私有节点 | 并入 `Fancy Lazarus` 活动簇，不并入 APT28 | 该节点只出现在 Fancy Lazarus 勒索 DDoS 报告中，标注的 mention 是该活动簇冒用的 “Armada Collective / Lazarus Group”；若按标题并入 APT28 会制造错误归因 |
| Bosch 标题 `TA453` 私有节点 | 按原文更正为 `TA543` | 对应报告正文持续描述 TA543/JSSLoader；原标题与 mention 不一致 |
| `Orz` → ATT&CK `S0229` | 排除 | S0229 是 Software，不是 Group。[S0229](https://attack.mitre.org/software/S0229/) |
| `Magecart-type` | 排除出“具体组织”统计 | 只有泛型描述，不能证明是一个可独立归因的具体组织 |
| `CloudFall` 与 `CloudAtlas` | 暂不合并 | 原报告仅给出 moderate-confidence overlap；重叠不等于同一主体 |

这一步把 70 个链接实体归并为 65 个可用组织或独立活动簇。这里的“真实组织”是产品实体口径，不代表法律意义上的唯一现实主体；厂商命名可能存在同组异名、子集、共享工具和重叠活动。

## 覆盖矩阵

“报告数”只统计严格 `GROUP` 金标报告。缺口按目标 3 篇计算。

### 已达到目标：14 个

| 规范组织 | 规范键 | 报告数 | 金标中出现的代表别名 |
|---|---|---:|---|
| APT28 | G0007 | 8 | APT28、Sednit、Sofacy、STRONTIUM |
| DarkSide | Bosch 私有节点 | 7 | DarkSide |
| ReconHellcat | Bosch 私有节点 | 5 | ReconHell、ReconHellcat |
| APT29 | G0016 | 4 | APT29、Cozy Bear |
| APT41 | G0096 | 4 | APT41、Barium、TA415 |
| Lazarus Group | G0032 | 4 | HIDDEN COBRA、Lazarus Group |
| menuPass | G0045 | 4 | APT10、menuPass |
| APT-C-36 | G0099 | 3 | APT-C-36、Blind Eagle |
| Emissary Panda | G0027 | 3 | APT27、Emissary Panda |
| Leviathan / APT40 | G0065 | 3 | APT40、Leviathan、Periscope、TA423 |
| TA505 | G0092 | 3 | TA505 |
| TA575 | Bosch 私有节点 | 3 | TA575 |
| Turla | G0010 | 3 | Turla |
| Winnti Group | G0044 | 3 | BARIUM、Blackfly、Winnti Group |

### 还差 1 篇：9 个

| 规范组织 | 规范键 | 当前报告数 | 数据集内扩展原文线索 |
|---|---|---:|---|
| APT1 | G0006 | 2 | 无保守字面候选，需外部 |
| APT33 | G0064 | 2 | 有 1 篇候选，需检查是否只是伊朗威胁背景 |
| Cobalt Group | G0080 | 2 | Golden Chickens 相关报告有候选，需确认是否提供实质行为 |
| Dragonfly | G0035 | 2 | 无保守字面候选，需外部 |
| FIN7 | G0046 | 2 | 无保守字面候选，需外部 |
| Golden Chickens | Bosch 私有节点 | 2 | 有 2 篇标题直接相关的扩展原文，优先复核 |
| Gorgon Group | G0078 | 2 | 无保守字面候选，需外部 |
| Ke3chang | G0004 | 2 | 无保守字面候选，需外部 |
| Sandworm Team | G0034 | 2 | 有 1 篇供应链主题候选，需检查主体性 |

### 还差 2 篇：42 个

| 规范组织 | 规范键 | 当前报告数 | 补齐入口 |
|---|---|---:|---|
| APT17 | G0025 | 1 | 外部原始报告 |
| APT18 | G0026 | 1 | 外部原始报告 |
| APT32 | G0050 | 1 | 外部原始报告 |
| BabukGang | Bosch 私有节点 | 1 | 外部原始报告 |
| Berserk Bear | Bosch 私有节点 | 1 | 外部原始报告 |
| BlackMatter | Bosch 私有节点 | 1 | 外部原始报告 |
| Chimera | G0114 | 1 | 外部原始报告 |
| Cleaver | G0003 | 1 | 1 篇扩展候选，仍需至少 1 篇外部 |
| CloudAtlas APT | Bosch 私有节点 | 1 | 外部原始报告 |
| CloudFall | Bosch 私有节点 | 1 | 外部报告稀缺，允许维持独立待定簇 |
| Dharma | Bosch 私有节点 | 1 | 外部原始报告 |
| E.K.P | Bosch 私有节点 | 1 | 先确认该私有节点身份，再决定是否扩充 |
| Evilnum | G0120 | 1 | 外部原始报告 |
| Fancy Lazarus | Bosch 私有节点 | 1 | 1 篇扩展候选可能只是历史背景，需谨慎 |
| FIN6 | G0037 | 1 | 2 篇 Golden Chickens 扩展候选，需确认主体性 |
| Gamaredon Group | G0047 | 1 | 1 篇扩展候选，仍需至少 1 篇外部 |
| GrooveGang | Bosch 私有节点 | 1 | 外部原始报告 |
| HydroJiin | Bosch 私有节点 | 1 | 1 篇扩展候选，仍需至少 1 篇外部 |
| Kimsuky | G0094 | 1 | 外部原始报告 |
| Magic Hound | G0059 | 1 | BadBlood/TA453 扩展原文可优先复核 |
| mummy-spider | Bosch 私有节点 | 1 | 4 篇 Emotet/TA542 候选，优先复核 |
| Mustang Panda | G0129 | 1 | TA416 扩展原文可优先复核 |
| Naikon | G0019 | 1 | 外部原始报告 |
| OilRig | G0049 | 1 | 1 篇扩展候选，仍需至少 1 篇外部 |
| Patchwork | G0040 | 1 | 4 篇字面候选，但只有 1 篇标题直接相关 |
| ShinyHunters | Bosch 私有节点 | 1 | 外部原始报告 |
| SilverTerrier | G0083 | 1 | 外部原始报告 |
| TA2722 | Bosch 私有节点 | 1 | 外部原始报告 |
| TA428 | Bosch 私有节点 | 1 | 外部原始报告 |
| TA459 | G0062 | 1 | 外部原始报告 |
| TA543 | Bosch 私有节点 | 1 | 外部原始报告 |
| TA544 | Bosch 私有节点 | 1 | 2 篇 Proofpoint 扩展候选，优先复核 |
| TA547 | Bosch 私有节点 | 1 | 1 篇扩展候选，仍需至少 1 篇外部 |
| TA551 | G0127 | 1 | 2 篇扩展候选，优先复核 |
| TA574 | Bosch 私有节点 | 1 | 2 篇 Proofpoint 扩展候选，优先复核 |
| TA800 | Bosch 私有节点 | 1 | 4 篇扩展候选，其中有直接主题报告 |
| The White Company | G0089 | 1 | 外部原始报告 |
| Transparent Tribe | G0134 | 1 | 1 篇扩展候选，仍需至少 1 篇外部 |
| TrickbotGang | Bosch 私有节点 | 1 | 外部原始报告 |
| vicious-panda | Bosch 私有节点 | 1 | 外部原始报告 |
| WIRTE | G0090 | 1 | 外部原始报告 |
| Xenotime | Bosch 私有节点 | 1 | 外部原始报告 |

## AnnoCTR 扩展原文能补多少

对全部 400 篇 `all/text` 使用经过清理的组织名和别名做大小写不敏感、单词边界匹配，排除当前金标报告后：

- 22 个未达标组织至少有 1 篇扩展原文候选；
- 11 个未达标组织在“所有候选都有效”的理想情况下可达到 3 篇；
- 候选报告并集为 37 篇；
- 即使把所有候选都接受，仍有 40 个组织不足 3 篇，剩余缺口至少 66 个“组织—报告”关联。

这只是候选召回，不是归属结论。字符串命中常见的错误包括：

- 报告只把某组织作为历史背景或对比对象；
- 恶意软件服务被多个组织使用，报告主体并不是该组织；
- 勒索活动冒用知名 APT 名称；
- 名称本身歧义，例如 Cobalt、Winnti、Magecart；
- 报告汇总多个组织，但没有给目标组织足够的行为证据。

优先复核的扩展原文包括：

| 组织 | 候选报告 ID | 预判 |
|---|---|---|
| Golden Chickens | `quoteintelligence_2020-01-27_the-chicken-keeps-laying-new` | 标题直接相关，强候选 |
| Golden Chickens | `quoteintelligence_2020-07-20_golden-chickens-evolution-of-the` | 标题直接相关，强候选 |
| mummy-spider / TA542 | `proofpoint_2020-08-28_comprehensive-look-emotets-summer-2020` | Emotet 活动主题，强候选 |
| mummy-spider / TA542 | `proofpoint_2020-10-01_emotet-makes-timely-adoption-political` | Emotet 活动主题，强候选 |
| Patchwork | `lab52_2019-10-22_new-patchwork-campaign-against-pakistan` | 标题直接相关，强候选 |
| Magic Hound / TA453 | `proofpoint_2021-03-30_badblood-ta453-targets-us-and` | 标题直接相关，强候选 |
| Mustang Panda / TA416 | `proofpoint_2020-11-23_ta416-goes-ground-and-returns` | 需用 ATT&CK/厂商别名表确认后入库 |
| TA800 | `proofpoint_2021-02-11_baza-valentines-day` | 需确认 TA800 是主体 |
| TA800 | `proofpoint_2021-03-10_nimzaloader-ta800s-new-initial-access` | 标题直接相关，强候选 |
| TA544、TA551、TA574 | `proofpoint_2021-06-16_first-step-initial-access-leads` | 多组织汇总，需逐组织核验行为证据 |

需要明确拒绝的典型误命中：

- `proofpoint_2021-06-10_ransom-ddos-extortion-actor-fancy` 不能作为 Lazarus Group 报告；文中描述的是冒用 Lazarus 名称的 Fancy Lazarus 勒索活动。
- 只出现 “Cobalt Strike” 的报告不能自动算作 Cobalt Group。
- 只出现 “Winnti malware” 的报告不能自动算作 Winnti Group。

## 外部补齐策略

### 第一优先级：从 ATT&CK Group 页面反向选择原始引用

MITRE 官方维护的 ATT&CK STIX 数据和 Group 页面提供规范 ID、关联名称、技术关系及引用来源。[ATT&CK STIX Data](https://github.com/mitre-attack/attack-stix-data)、[ATT&CK Groups](https://attack.mitre.org/groups/)

正确做法不是把 ATT&CK 页面本身当作第三篇报告，而是：

1. 以 Group ID 查询该组织；
2. 从 Techniques Used、Campaigns 和 References 中挑选原始来源；
3. 优先选包含完整攻击过程、工具、基础设施或 IOC 的一线报告；
4. 避免选择只复述其他厂商结论的新闻稿。

### 第二优先级：AnnoCTR 原始供稿方的一线报告

AnnoCTR 官方仓库列出的供稿方包括 Intel 471、Lab52、S2 Grupo、Proofpoint、QuoIntelligence 和 Zscaler。对数据集中已有组织，优先继续从同一厂商追踪系列报告，可以降低命名体系变化带来的消歧成本。

### 第三优先级：政府和大型厂商原始报告

不足组织按以下顺序补充：

1. CISA、FBI、NCSC、CERT 等政府联合通告；
2. Microsoft、Google/Mandiant、ESET、Cisco Talos、Palo Alto Unit 42、Secureworks、Trend Micro、Kaspersky 等一线研究团队；
3. 仅在找不到原始页面时使用可信归档，并保存归档 URL 和原始发布方。

### 报告准入标准

一篇报告只有同时满足以下条件，才计入某个组织的 3 篇覆盖：

- 来源是原始发布机构或可核验的官方归档；
- 组织是报告主体或主要分析对象之一，不是背景列表中的一次提及；
- 至少存在一条可定位到原文的组织—行为证据，如工具、TTP、漏洞、基础设施、攻击步骤或受害目标；
- 能区分“厂商明确归因”“报告转述归因”“平台推断关联”；
- 与已有报告不是同文转载或只改标题的重复版本；
- 入库时保存发布机构、原始 URL、发布时间、采集时间、SHA-256、MIME、许可/TLP、解析器版本和证据位置。

## 实施优先级

不建议一次性为 65 个组织并行抓取。最稳妥的顺序是：

### P0：零外部成本完成

先复核 280 篇扩展原文中的强候选，优先处理：

- Golden Chickens
- mummy-spider / TA542
- Magic Hound / TA453
- Mustang Panda / TA416
- Patchwork
- TA544
- TA551
- TA574
- TA800

### P1：每个只差 1 篇

补齐 9 个两篇覆盖组织。对 APT1、Dragonfly、FIN7、Gorgon Group 和 Ke3chang，直接从 ATT&CK 引用反查一篇高质量原始报告；对 APT33、Cobalt Group、Golden Chickens 和 Sandworm 先复核扩展原文。

### P2：比赛展示优先组织

从只覆盖 1 篇的组织中，优先补有较强知名度或行为差异的组织：

- Kimsuky
- Magic Hound / TA453
- Mustang Panda
- OilRig
- Patchwork
- Transparent Tribe
- TA551
- TA800
- BlackMatter
- ShinyHunters

### P3：长尾私有活动簇

CloudFall、E.K.P、HydroJiin、TA2722、TA428 等私有节点先做身份确认。若公开材料不足，可保留为“待归并活动簇”，展示一篇高保真报告和明确的覆盖不足状态，不为达到 3 篇而错误合并。

## 建议的完成判定

对比赛项目，“全”不应定义为每个名字机械拥有三条记录，而应定义为：

- 65 个组织/活动簇都能在目录中检索；
- ATT&CK 组织完成 ID 和别名归一；
- 14 个现有充分覆盖组织保持完整；
- P0、P1 组织优先达到 3 篇；
- 每篇报告都能回到原文证据；
- 所有补全、预测和归因路径区分原始证据与算法生成；
- 长尾组织明确显示报告覆盖度和待复核状态。

按这个口径，系统的可信度会高于“每个组织硬凑三篇”，同时仍能在比赛现场展示较完整的组织目录和可解释攻击路径。

## 来源

- [AnnoCTR 论文（ACL Anthology）](https://aclanthology.org/2024.lrec-main.103/)
- [Bosch Research AnnoCTR 官方仓库](https://github.com/boschresearch/anno-ctr-lrec-coling-2024)
- [本次固定的 AnnoCTR 上游提交](https://github.com/boschresearch/anno-ctr-lrec-coling-2024/tree/d510b6949e1938d47c93a43eedd562dc538439dc)
- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [MITRE ATT&CK STIX Data 官方仓库](https://github.com/mitre-attack/attack-stix-data)
- [MITRE G0016 APT29](https://attack.mitre.org/groups/G0016/)
- [MITRE G0027 Emissary Panda / APT27](https://attack.mitre.org/groups/G0027/)
- [MITRE G0065 Leviathan / APT40](https://attack.mitre.org/groups/G0065/)
- [MITRE S0229 Orz](https://attack.mitre.org/software/S0229/)
