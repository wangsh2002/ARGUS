from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
from time import perf_counter
from typing import Any, Protocol

import httpx

from .models import (
    AttackFlowDraft,
    AttackFlowDraftAction,
    AttackFlowDraftActorClaim,
    AttackFlowDraftContext,
    AttackFlowDraftEvidence,
    AttackFlowDraftRelation,
)


PROMPT_VERSION = "attack-flow-extraction/1.2"
SEGMENTATION_PROMPT_VERSION = "attack-flow-activity-segmentation/1.1"
CONSOLIDATION_PROMPT_VERSION = "attack-flow-activity-consolidation/1.0"
VARIANT_PROMPT_VERSION = "attack-flow-variant-inventory/1.0"
RELATION_PROMPT_VERSION = "attack-flow-relation-extraction/1.0"
ALLOWED_RELATIONS = {
    "precedes",
    "leads_to",
    "enables",
    "causes",
    "on_success",
    "on_failure",
}
CONTEXT_TYPES = {
    "malware",
    "tool",
    "asset",
    "vulnerability",
    "file",
    "process",
    "account",
    "infrastructure",
    "ip",
    "domain",
    "url",
    "hash",
    "other",
}
CONTEXT_ROLES = {
    "uses",
    "targets",
    "communicates-with",
    "exploits",
    "downloads-from",
    "drops-on",
    "runs-on",
    "modifies",
    "creates",
    "other",
}
CONFIDENCE_LEVELS = {"high", "medium", "low"}
ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
ENTITY_NAME_PATTERN = re.compile(
    r"^(?:https?://|hxxps?://|CVE-\d{4}-\d+|"
    r"(?:\d{1,3}\.){3}\d{1,3}|[a-f0-9]{32,64}|"
    r"\S+\.(?:exe|dll|docx?|xlsx?|js|vbs|ps1|hta|bin|dat))$",
    re.IGNORECASE,
)
ENGLISH_ACTION_PATTERN = re.compile(
    r"^(?:send|deliver|open|enable|execute|run|launch|load|download|drop|"
    r"write|create|modify|inject|decode|decrypt|collect|steal|capture|query|"
    r"discover|connect|communicate|exfiltrate|persist|install|exploit|invoke|"
    r"copy|move|delete|enumerate|retrieve|stage|redirect|unpack|extract|"
    r"deploy|distribute|use|leverage|compromise|obtain)\b",
    re.IGNORECASE,
)
CHINESE_ACTION_PATTERN = re.compile(
    r"(?:投递|发送|打开|启用|执行|启动|加载|下载|释放|写入|"
    r"创建|修改|注入|解码|解密|收集|窃取|截图|查询|发现|"
    r"连接|通信|回传|外传|持久化|安装|利用|调用|复制|"
    r"移动|删除|枚举|获取|触发|跳转|解压|传递)"
)
ENGLISH_ACTION_VERBS = {
    "send",
    "deliver",
    "open",
    "enable",
    "execute",
    "run",
    "launch",
    "load",
    "download",
    "drop",
    "write",
    "create",
    "modify",
    "inject",
    "decode",
    "decrypt",
    "collect",
    "steal",
    "capture",
    "query",
    "discover",
    "connect",
    "communicate",
    "exfiltrate",
    "persist",
    "install",
    "exploit",
    "invoke",
    "copy",
    "move",
    "delete",
    "enumerate",
    "retrieve",
    "stage",
    "redirect",
    "unpack",
    "extract",
    "deploy",
    "distribute",
    "use",
    "leverage",
    "compromise",
    "obtain",
    "perform",
}


class AttackFlowLanguageModel(Protocol):
    model: str

    def extract_attack_flows(
        self,
        report: dict[str, Any],
        source_text: str,
    ) -> dict[str, Any]:
        ...


@dataclass(frozen=True)
class AttackFlowExtractionResult:
    candidates: list[AttackFlowDraft]
    audit: dict[str, Any]


@dataclass(frozen=True)
class DeepSeekAttackFlowExtractor:
    base_url: str
    api_key: str
    model: str
    timeout_seconds: float = 180.0

    def extract_attack_flows(
        self,
        report: dict[str, Any],
        source_text: str,
    ) -> dict[str, Any]:
        segmentation = self._request_json(
            {
                "task": (
                    "先把威胁情报原文划分为零到多个彼此独立的"
                    "具体攻击活动范围。本步不抽取节点或关系。"
                ),
                "report": report,
                "numbered_source": _numbered_source(source_text),
                "rules": [
                    (
                        "每个活动使用 line_ranges；同一活动的投递、载荷、"
                        "持久化和 C2 分散在不同章节时，放入同一活动的"
                        "多个不连续范围。"
                    ),
                    (
                        "同一攻击主体、时间窗口或案例中的入口变体、"
                        "条件路径和共享后继属于同一活动。"
                    ),
                    (
                        "不同攻击者、不同时间波次、不同案例或互不相关的"
                        "感染链分成不同活动。"
                    ),
                    (
                        "纯 IOC 表、检测规则、产品能力、生态概述、假设示例、"
                        "未来预测和纯归因讨论不形成攻击活动。"
                    ),
                    "不同活动的 line_ranges 不得重叠；没有具体攻击活动时输出空列表。",
                    "只输出 JSON。",
                ],
                "output_schema": {
                    "activities": [
                        {
                            "title": "来源内可区分的活动名称",
                            "line_ranges": [
                                {"start_line": 1, "end_line": 20},
                                {"start_line": 40, "end_line": 60},
                            ],
                            "reason": "主体、时间、入口或载荷边界",
                        }
                    ]
                },
            },
            max_tokens=5000,
            system_message=(
                "你是保守的威胁情报活动分段器。"
                "不抽取攻击图，不补造活动，只输出 JSON。"
            ),
        )
        activity_slices = _validated_activity_slices(segmentation, source_text)
        consolidation: dict[str, Any] = {"groups": []}
        if len(activity_slices) > 1:
            consolidation = self._request_json(
                _activity_consolidation_prompt(
                    report,
                    activity_slices,
                ),
                max_tokens=5000,
                system_message=(
                    "你是保守的威胁情报活动边界复核器。"
                    "只归并有原文明确支持的同一活动变体，只输出 JSON。"
                ),
            )
        activity_groups = _validated_activity_groups(
            consolidation,
            activity_slices,
            source_text,
        )
        consolidated_activities = _consolidated_activity_slices(
            activity_slices,
            activity_groups,
        )
        if len(consolidated_activities) == 1:
            consolidated_activities = [
                _expand_single_activity_span(
                    consolidated_activities[0],
                    source_text,
                )
            ]
        aggregate: dict[str, Any] = {
            "candidates": [],
            "unassigned_evidence": [],
            "_segmentation": {
                "prompt_version": SEGMENTATION_PROMPT_VERSION,
                "initial_segments": [
                    {
                        "id": activity["id"],
                        "title": activity["title"],
                        "line_ranges": activity["line_ranges"],
                    }
                    for activity in activity_slices
                ],
                "consolidation_prompt_version": CONSOLIDATION_PROMPT_VERSION,
                "activities": [
                    {
                        "title": activity["title"],
                        "line_ranges": activity["line_ranges"],
                        "consolidation_method": activity[
                            "consolidation_method"
                        ],
                    }
                    for activity in consolidated_activities
                ],
            },
        }
        for activity_index, activity in enumerate(consolidated_activities):
            raw_variant_plan = self._request_json(
                _activity_variant_prompt(
                    report,
                    activity["title"],
                    activity["numbered_source"],
                ),
                max_tokens=5000,
                system_message=(
                    "你是保守的威胁情报路径变体识别器。"
                    "只识别原文明确存在的并行或条件路径，只输出 JSON。"
                ),
            )
            variant_plan = _validated_variant_plan(
                raw_variant_plan,
                activity,
                source_text,
            )
            aggregate["_segmentation"]["activities"][activity_index][
                "variant_prompt_version"
            ] = VARIANT_PROMPT_VERSION
            aggregate["_segmentation"]["activities"][activity_index][
                "variants"
            ] = variant_plan["variants"]
            raw = self._request_json(
                _activity_extraction_prompt(
                    report,
                    activity["title"],
                    activity["numbered_source"],
                    variant_plan,
                ),
                max_tokens=12000,
                system_message=(
                    "你是保守的 AttackFlow 抽取器。"
                    "证据不足就不输出，只输出 JSON。"
                ),
            )
            raw_candidates = raw.get("candidates", [])
            if not isinstance(raw_candidates, list):
                raw_candidates = []
            raw_candidates, coverage = self._retry_incomplete_variant_coverage(
                report,
                activity,
                variant_plan,
                raw_candidates,
                source_text,
            )
            aggregate["_segmentation"]["activities"][activity_index][
                "variant_coverage"
            ] = coverage
            for candidate in raw_candidates:
                if not isinstance(candidate, dict):
                    aggregate["candidates"].append(candidate)
                    continue
                candidate_actions = candidate.get("actions", [])
                if (
                    isinstance(candidate_actions, list)
                    and len(candidate_actions) >= 2
                ):
                    raw_relations = self._request_json(
                        _relation_extraction_prompt(
                            report,
                            activity["title"],
                            activity["numbered_source"],
                            candidate,
                            variant_plan,
                        ),
                        max_tokens=8000,
                        system_message=(
                            "你是保守的 AttackFlow 关系抽取器。"
                            "只使用给定 Action 和逐字原文证据，只输出 JSON。"
                        ),
                    )
                    candidate["relations"] = _merge_raw_relations(
                        candidate.get("relations", []),
                        raw_relations.get("relations", []),
                    )
                candidate["_verified_variant_plan"] = variant_plan
                aggregate["candidates"].append(candidate)
            aggregate["unassigned_evidence"].extend(
                raw.get("unassigned_evidence", [])
            )
        return aggregate

    def _retry_incomplete_variant_coverage(
        self,
        report: dict[str, Any],
        activity: dict[str, Any],
        variant_plan: dict[str, Any],
        raw_candidates: list[Any],
        source_text: str,
    ) -> tuple[list[Any], dict[str, Any]]:
        required_ids = {
            variant["id"]
            for variant in variant_plan["variants"]
        }
        _, covered_ids = _best_variant_candidate(
            raw_candidates,
            variant_plan,
            source_text,
        )
        missing_ids = sorted(required_ids - covered_ids)
        if not required_ids or not missing_ids:
            return raw_candidates, {
                "required_variant_ids": sorted(required_ids),
                "covered_variant_ids": sorted(covered_ids),
                "retry_performed": False,
            }
        retry = self._request_json(
            _activity_extraction_prompt(
                report,
                activity["title"],
                activity["numbered_source"],
                variant_plan,
                retry_context={
                    "missing_variant_ids": missing_ids,
                    "previous_candidates": _compact_raw_candidates(
                        raw_candidates
                    ),
                },
            ),
            max_tokens=12000,
            system_message=(
                "你是保守的 AttackFlow 抽取器。"
                "上一次输出漏掉了已验证的路径变体，"
                "这次必须输出一个同时覆盖全部变体的候选，只输出 JSON。"
            ),
        )
        retry_candidates = retry.get("candidates", [])
        if not isinstance(retry_candidates, list):
            retry_candidates = []
        retry_best, retry_covered_ids = _best_variant_candidate(
            retry_candidates,
            variant_plan,
            source_text,
        )
        selected_retry = False
        if (
            retry_best is not None
            and len(retry_covered_ids) > len(covered_ids)
        ):
            covered_ids = retry_covered_ids
            raw_candidates = [retry_best]
            selected_retry = True
        return raw_candidates, {
            "required_variant_ids": sorted(required_ids),
            "covered_variant_ids": sorted(covered_ids),
            "retry_performed": True,
            "complete": required_ids <= covered_ids,
            "selected_retry_candidate": selected_retry,
        }

    def _request_json(
        self,
        prompt: dict[str, Any],
        *,
        max_tokens: int,
        system_message: str,
    ) -> dict[str, Any]:
        started = perf_counter()
        with httpx.Client(trust_env=False) as client:
            response = client.post(
                f"{self.base_url.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "temperature": 0,
                    "thinking": {"type": "disabled"},
                    "max_tokens": max_tokens,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": system_message},
                        {
                            "role": "user",
                            "content": json.dumps(prompt, ensure_ascii=False),
                        },
                    ],
                },
                timeout=self.timeout_seconds,
            )
        response.raise_for_status()
        raw = json.loads(
            _strip_json_fence(response.json()["choices"][0]["message"]["content"])
        )
        raw["_request_meta"] = {
            "elapsed_seconds": round(perf_counter() - started, 3),
        }
        return raw


def _activity_extraction_prompt(
    report: dict[str, Any],
    activity_title: str,
    numbered_source: str,
    variant_plan: dict[str, Any],
    retry_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "task": (
            "从已分配给同一攻击活动的原文范围中抽取零或一个"
            "简化 AttackFlow 候选。只记录该范围内明确支持的事实。"
        ),
        "report": report,
        "activity_title": activity_title,
        "numbered_source": numbered_source,
        "verified_variant_plan": variant_plan,
        "retry_context": retry_context,
        "rules": [
                "输入已经是单一活动范围；不再跨范围合并其他活动。",
                "一个 AttackFlow 候选至少包含两个 Action；单一能力或单一行为不构成 Flow。",
                "所有 id 只是当次输出的局部临时 ID，使用 A1/C1/R1/ACTOR1 格式。",
                (
                    "Action name 必须是简短动宾短语，不是原文整句、IOC、"
                    "工具、恶意软件、文件、账户、资产或漏洞名称。"
                ),
                (
                    "IOC、工具、恶意软件、漏洞、账户、文件、进程、资产和"
                    "基础设施只能放在 Action.contexts。"
                ),
                "每个 Action、Context、Relation 和 reported Actor 都必须带原文 exact quote。",
                "quote 必须从 numbered_source 的原文部分逐字复制，不得改写、翻译或拼接。",
                (
                    "quote 只复制一个 L 行中的连续原文，不包含 L 编号；"
                    "必须保留原文 Markdown、标点和大小写。"
                ),
                "禁止用 ... 或省略号把两句、两行证据拼成一个 quote。",
                (
                    "Relation 只能使用 precedes、leads_to、enables、causes、"
                    "on_success、on_failure。"
                ),
                "没有明确关系 quote 就保持两个 Action 断开，不得为了连通补边。",
                (
                    "Relation quote 必须是同一行内能支持两个端点关系的连续"
                    "原文；可使用含 this/then/after/which/in turn 等明确指代的目标句。"
                ),
                "mainline 可留空；最终主干由后端仅根据通过验证的 Relation 生成。",
                (
                    "同一活动的不同入口、文档变体或条件路径必须保留为"
                    "不同 Action 分支；它们共享后继时，用多条允许的 Relation "
                    "指向同一后继 Action 表达汇合，不得只选一个变体。"
                ),
                (
                    "不得把变体 A 的入口动作连到变体 B 的入口动作；"
                    "并行变体应分别连向它们真正共享的后继。"
                ),
                (
                    "verified_variant_plan 非空时，每个变体至少应有一个"
                    "与其他变体不同的 Action；若证据不足，将对应原文放入"
                    "unassigned_evidence，不得默默忽略该变体。"
                ),
                "technique_ids 可留空；只输出 ATT&CK Txxxx 编号，不输出名称或 tactic。",
                "归因只保存报告原话，冲突归因分别保留，不由模型消解。",
                "无法归入任一候选的有价值原文放入 unassigned_evidence。",
                (
                    "通用能力、生态概述、未来预测、假设示例和纯历史归因"
                    "不是来源内的具体攻击活动。"
                ),
                "只输出 JSON。",
        ],
        "output_schema": {
                "candidates": [
                    {
                        "title": "简短活动标题",
                        "description": "来源内活动摘要",
                        "actions": [
                            {
                                "id": "A1",
                                "name": "简短动宾名称",
                                "description": "完整事实描述",
                                "phase": "可留空",
                                "confidence": "high|medium|low",
                                "technique_ids": [],
                                "contexts": [
                                    {
                                        "id": "C1",
                                        "type": "malware|tool|asset|vulnerability|file|process|account|infrastructure|ip|domain|url|hash|other",
                                        "name": "实体原名",
                                        "role": "uses|targets|communicates-with|exploits|downloads-from|drops-on|runs-on|modifies|creates|other",
                                        "confidence": "high|medium|low",
                                        "evidence": [{"quote": "逐字原文"}],
                                    }
                                ],
                                "evidence": [{"quote": "逐字原文"}],
                            }
                        ],
                        "relations": [
                            {
                                "id": "R1",
                                "source_action_id": "A1",
                                "target_action_id": "A2",
                                "type": "precedes|leads_to|enables|causes|on_success|on_failure",
                                "condition": None,
                                "confidence": "high|medium|low",
                                "evidence": [{"quote": "逐字原文"}],
                            }
                        ],
                        "mainline": ["A1", "A2"],
                        "reported_actors": [
                            {
                                "id": "ACTOR1",
                                "reported_name": "报告中的称呼",
                                "confidence": "high|medium|low",
                                "evidence": [{"quote": "逐字原文"}],
                            }
                        ],
                        "variant_coverage": [
                            {
                                "variant_id": "V1",
                                "action_ids": ["A1", "A2"],
                            }
                        ],
                    }
                ],
                "unassigned_evidence": [
                    {"quote": "逐字原文", "reason": "无法归属原因"}
                ],
        },
    }


def _activity_consolidation_prompt(
    report: dict[str, Any],
    activity_slices: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "task": (
            "复核初步分段，找出实际上属于同一具体攻击活动的片段。"
            "只输出需要归并的分组，其余片段由后端保持独立。"
        ),
        "report": report,
        "segments": [
            {
                "id": activity["id"],
                "title": activity["title"],
                "line_ranges": activity["line_ranges"],
                "numbered_source": activity["numbered_source"],
            }
            for activity in activity_slices
        ],
        "rules": [
            (
                "只有原文明确表明多个片段是同一案例、同一时间波次的"
                "入口变体、条件路径或共享后继时才归并。"
            ),
            (
                "仅仅使用同一攻击者、同一恶意软件、同一工具、"
                "同一报告或相似关键词，不足以归并。"
            ),
            "不同时间波次、不同受害群体或彼此独立的感染链保持分开。",
            "每个归并组至少包含两个 segment_id。",
            "evidence quote 必须从 numbered_source 原文逐字复制。",
            "只输出 JSON。",
        ],
        "output_schema": {
            "groups": [
                {
                    "segment_ids": ["S1", "S2"],
                    "title": "合并后的活动名称",
                    "reason": "案例、时间、变体或共享后继依据",
                    "evidence": [{"quote": "逐字原文"}],
                }
            ]
        },
    }


def _activity_variant_prompt(
    report: dict[str, Any],
    activity_title: str,
    numbered_source: str,
) -> dict[str, Any]:
    return {
        "task": (
            "在同一具体攻击活动中识别明确的并行入口、不同执行"
            "变体或条件成功/失败路径。本步不抽取 Action 或 Relation。"
        ),
        "report": report,
        "activity_title": activity_title,
        "numbered_source": numbered_source,
        "rules": [
            (
                "只有原文明确对比、枚举或用 variant、alternative、"
                "either/or、if/else、success/failure 等语义表达的路径才输出。"
            ),
            "文章的普通先后章节、多个 IOC 或多个下载地址不是路径变体。",
            "不同攻击活动不是同一活动的变体。",
            "每个变体必须给出所属 line_ranges 和逐字 evidence quote。",
            (
                "如果多个变体共享后继载荷或动作，在"
                "shared_successor_evidence 中给出逐字原文；没有则留空。"
            ),
            "没有至少两个明确变体时输出空 variants。",
            "只输出 JSON。",
        ],
        "output_schema": {
            "variants": [
                {
                    "id": "V1",
                    "title": "变体名称",
                    "path_type": "alternative-entry|conditional-path|execution-variant",
                    "line_ranges": [
                        {"start_line": 1, "end_line": 20}
                    ],
                    "evidence": [{"quote": "逐字原文"}],
                }
            ],
            "shared_successor_evidence": [
                {"quote": "逐字原文"}
            ],
        },
    }


def _relation_extraction_prompt(
    report: dict[str, Any],
    activity_title: str,
    numbered_source: str,
    candidate: dict[str, Any],
    variant_plan: dict[str, Any],
) -> dict[str, Any]:
    actions = candidate.get("actions", [])
    if not isinstance(actions, list):
        actions = []
    return {
        "task": (
            "在不增加、删除或改写 Action 的前提下，从原文中抽取"
            "Action 之间所有有明确证据的有向关系。"
        ),
        "report": report,
        "activity_title": activity_title,
        "numbered_source": numbered_source,
        "verified_variant_plan": variant_plan,
        "actions": [
            {
                "id": action.get("id"),
                "name": action.get("name"),
                "description": action.get("description"),
                "evidence": action.get("evidence", []),
            }
            for action in actions
            if isinstance(action, dict)
        ],
        "existing_relations": candidate.get("relations", []),
        "rules": [
            "只能连接给定的 Action id，不得生成新 Action。",
            (
                "关系只能使用 precedes、leads_to、enables、causes、"
                "on_success、on_failure。"
            ),
            (
                "遍历全部 Action，特别检查多个入口指向共享后继、"
                "一个动作导向多个条件结果的分支与汇合。"
            ),
            (
                "两个入口变体不能因为文章先后介绍就互相连接；"
                "如果它们各自进入同一载荷或后继，应保留两条汇入边。"
            ),
            "不得因为 Action 在文中相邻或输出顺序相邻就补边。",
            (
                "relation quote 必须是同一行内能支持两个端点关系的"
                "连续原文，必须逐字复制。"
            ),
            "没有明确关系证据就不输出。",
            "只输出 JSON。",
        ],
        "output_schema": {
            "relations": [
                {
                    "id": "R1",
                    "source_action_id": "A1",
                    "target_action_id": "A2",
                    "type": "precedes|leads_to|enables|causes|on_success|on_failure",
                    "condition": None,
                    "confidence": "high|medium|low",
                    "evidence": [{"quote": "逐字原文"}],
                }
            ]
        },
    }


def _numbered_source(source_text: str, start_line: int = 1) -> str:
    return "\n".join(
        f"L{index:04d}\t{line}"
        for index, line in enumerate(
            source_text.splitlines(),
            start=start_line,
        )
    )


def _validated_activity_slices(
    raw: dict[str, Any],
    source_text: str,
) -> list[dict[str, Any]]:
    lines = source_text.splitlines()
    raw_activities = raw.get("activities", [])
    if not isinstance(raw_activities, list):
        return []
    validated: list[dict[str, Any]] = []
    claimed_lines: set[int] = set()
    for index, item in enumerate(raw_activities, start=1):
        if not isinstance(item, dict):
            continue
        raw_ranges = item.get("line_ranges")
        if raw_ranges is None:
            raw_ranges = [
                {
                    "start_line": item.get("start_line"),
                    "end_line": item.get("end_line"),
                }
            ]
        if not isinstance(raw_ranges, list) or not raw_ranges:
            continue
        ranges: list[dict[str, int]] = []
        selected_lines: set[int] = set()
        for raw_range in raw_ranges:
            if not isinstance(raw_range, dict):
                ranges = []
                break
            try:
                start_line = int(raw_range.get("start_line"))
                end_line = int(raw_range.get("end_line"))
            except (TypeError, ValueError):
                ranges = []
                break
            if (
                start_line < 1
                or end_line < start_line
                or end_line > len(lines)
            ):
                ranges = []
                break
            current_lines = set(range(start_line, end_line + 1))
            if selected_lines.intersection(current_lines):
                ranges = []
                break
            selected_lines.update(current_lines)
            ranges.append(
                {"start_line": start_line, "end_line": end_line}
            )
        if not ranges or claimed_lines.intersection(selected_lines):
            continue
        ordered_line_ids = sorted(selected_lines)
        text = "\n".join(lines[line_id - 1] for line_id in ordered_line_ids).strip()
        if not text:
            continue
        claimed_lines.update(selected_lines)
        validated.append(
            {
                "id": f"S{len(validated) + 1}",
                "title": str(item.get("title", "")).strip()
                or f"攻击活动 {index}",
                "start_line": min(ordered_line_ids),
                "end_line": max(ordered_line_ids),
                "line_ranges": sorted(
                    ranges,
                    key=lambda value: (
                        value["start_line"],
                        value["end_line"],
                    ),
                ),
                "text": text,
                "numbered_source": "\n".join(
                    f"L{line_id:04d}\t{lines[line_id - 1]}"
                    for line_id in ordered_line_ids
                ),
            }
        )
    return sorted(
        validated,
        key=lambda item: (item["start_line"], item["end_line"]),
    )


def _validated_activity_groups(
    raw: dict[str, Any],
    activity_slices: list[dict[str, Any]],
    source_text: str,
) -> list[dict[str, Any]]:
    known_ids = {activity["id"] for activity in activity_slices}
    claimed_ids: set[str] = set()
    groups: list[dict[str, Any]] = []
    raw_groups = raw.get("groups", [])
    if not isinstance(raw_groups, list):
        raw_groups = []
    for item in raw_groups:
        if not isinstance(item, dict):
            continue
        raw_ids = item.get("segment_ids", [])
        if not isinstance(raw_ids, list):
            continue
        segment_ids = list(
            dict.fromkeys(str(segment_id).strip() for segment_id in raw_ids)
        )
        evidence = item.get("evidence", [])
        if not isinstance(evidence, list):
            continue
        exact_quotes = list(
            dict.fromkeys(
                exact_quote
                for evidence_item in evidence
                if (exact_quote := _resolve_exact_quote(
                    _quote_from(evidence_item),
                    source_text,
                ))
            )
        )
        if (
            len(segment_ids) < 2
            or not set(segment_ids) <= known_ids
            or claimed_ids.intersection(segment_ids)
            or not exact_quotes
        ):
            continue
        groups.append(
            {
                "segment_ids": segment_ids,
                "title": str(item.get("title", "")).strip(),
                "evidence_quotes": exact_quotes,
                "method": "evidence-backed-model",
            }
        )
        claimed_ids.update(segment_ids)
    for outer in activity_slices:
        if outer["id"] in claimed_ids:
            continue
        nested = [
            inner
            for inner in activity_slices
            if inner["id"] not in claimed_ids
            and inner["id"] != outer["id"]
            and _activity_brackets(outer, inner)
            and _activity_title_similarity(outer["title"], inner["title"])
            >= 0.7
        ]
        if not nested:
            continue
        segment_ids = [outer["id"], *(inner["id"] for inner in nested)]
        groups.append(
            {
                "segment_ids": segment_ids,
                "title": outer["title"],
                "evidence_quotes": [],
                "method": "bracketed-similar-title",
            }
        )
        claimed_ids.update(segment_ids)
    groups.extend(
        {
            "segment_ids": [activity["id"]],
            "title": activity["title"],
            "evidence_quotes": [],
            "method": "independent",
        }
        for activity in activity_slices
        if activity["id"] not in claimed_ids
    )
    activity_order = {
        activity["id"]: index
        for index, activity in enumerate(activity_slices)
    }
    return sorted(
        groups,
        key=lambda group: min(
            activity_order[segment_id]
            for segment_id in group["segment_ids"]
        ),
    )


def _consolidated_activity_slices(
    activity_slices: list[dict[str, Any]],
    activity_groups: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    activity_by_id = {
        activity["id"]: activity
        for activity in activity_slices
    }
    consolidated = []
    for group_index, group in enumerate(activity_groups, start=1):
        members = [
            activity_by_id[segment_id]
            for segment_id in group["segment_ids"]
            if segment_id in activity_by_id
        ]
        if not members:
            continue
        ranges = sorted(
            (
                line_range
                for member in members
                for line_range in member["line_ranges"]
            ),
            key=lambda line_range: (
                line_range["start_line"],
                line_range["end_line"],
            ),
        )
        numbered_lines = sorted(
            {
                line
                for member in members
                for line in member["numbered_source"].splitlines()
            },
            key=_numbered_line_id,
        )
        consolidated.append(
            {
                "id": f"G{group_index}",
                "title": group["title"] or members[0]["title"],
                "start_line": min(member["start_line"] for member in members),
                "end_line": max(member["end_line"] for member in members),
                "line_ranges": ranges,
                "text": "\n".join(
                    line.partition("\t")[2]
                    for line in numbered_lines
                ),
                "numbered_source": "\n".join(numbered_lines),
                "segment_ids": group["segment_ids"],
                "consolidation_evidence": group["evidence_quotes"],
                "consolidation_method": group["method"],
            }
        )
    return consolidated


def _activity_brackets(
    outer: dict[str, Any],
    inner: dict[str, Any],
) -> bool:
    return any(
        line_range["end_line"] < inner["start_line"]
        for line_range in outer["line_ranges"]
    ) and any(
        line_range["start_line"] > inner["end_line"]
        for line_range in outer["line_ranges"]
    )


def _activity_title_similarity(first: str, second: str) -> float:
    ignored = {
        "attack",
        "attacks",
        "activity",
        "campaign",
        "campaigns",
        "chain",
        "document",
        "documents",
        "flow",
        "report",
        "using",
        "via",
        "with",
    }
    first_tokens = {
        token
        for token in re.findall(r"[a-z0-9]+", first.casefold())
        if len(token) >= 3 and token not in ignored
    }
    second_tokens = {
        token
        for token in re.findall(r"[a-z0-9]+", second.casefold())
        if len(token) >= 3 and token not in ignored
    }
    if not first_tokens or not second_tokens:
        return 0.0
    return len(first_tokens & second_tokens) / min(
        len(first_tokens),
        len(second_tokens),
    )


def _validated_variant_plan(
    raw: dict[str, Any],
    activity: dict[str, Any],
    source_text: str,
) -> dict[str, Any]:
    allowed_line_ids = {
        _numbered_line_id(line)
        for line in activity["numbered_source"].splitlines()
    }
    variants = []
    raw_variants = raw.get("variants", [])
    if not isinstance(raw_variants, list):
        raw_variants = []
    for item in raw_variants:
        if not isinstance(item, dict):
            continue
        raw_ranges = item.get("line_ranges", [])
        if not isinstance(raw_ranges, list) or not raw_ranges:
            continue
        ranges = []
        range_line_ids: set[int] = set()
        for raw_range in raw_ranges:
            if not isinstance(raw_range, dict):
                ranges = []
                break
            try:
                start_line = int(raw_range.get("start_line"))
                end_line = int(raw_range.get("end_line"))
            except (TypeError, ValueError):
                ranges = []
                break
            current_ids = set(range(start_line, end_line + 1))
            if (
                end_line < start_line
                or not current_ids
                or not current_ids <= allowed_line_ids
            ):
                ranges = []
                break
            ranges.append(
                {"start_line": start_line, "end_line": end_line}
            )
            range_line_ids.update(current_ids)
        evidence = item.get("evidence", [])
        if not isinstance(evidence, list):
            continue
        exact_quotes = list(
            dict.fromkeys(
                exact_quote
                for evidence_item in evidence
                if (exact_quote := _resolve_exact_quote(
                    _quote_from(evidence_item),
                    source_text,
                ))
            )
        )
        if not ranges or not range_line_ids or not exact_quotes:
            continue
        variants.append(
            {
                "id": f"V{len(variants) + 1}",
                "title": str(item.get("title", "")).strip()
                or f"路径变体 {len(variants) + 1}",
                "path_type": str(item.get("path_type", "")).strip()
                or "alternative-path",
                "line_ranges": sorted(
                    ranges,
                    key=lambda line_range: (
                        line_range["start_line"],
                        line_range["end_line"],
                    ),
                ),
                "evidence_quotes": exact_quotes,
            }
        )
    if len(variants) < 2:
        variants = []
    raw_shared_evidence = raw.get("shared_successor_evidence", [])
    if not isinstance(raw_shared_evidence, list):
        raw_shared_evidence = []
    shared_successor_evidence = list(
        dict.fromkeys(
            exact_quote
            for evidence_item in raw_shared_evidence
            if (exact_quote := _resolve_exact_quote(
                _quote_from(evidence_item),
                source_text,
            ))
        )
    )
    return {
        "variants": variants,
        "shared_successor_evidence": (
            shared_successor_evidence if variants else []
        ),
    }


def _expand_single_activity_span(
    activity: dict[str, Any],
    source_text: str,
) -> dict[str, Any]:
    lines = source_text.splitlines()
    start_line = int(activity["start_line"])
    end_line = int(activity["end_line"])
    if start_line < 1 or end_line > len(lines) or end_line < start_line:
        return activity
    span_lines = lines[start_line - 1 : end_line]
    return {
        **activity,
        "line_ranges": [
            {"start_line": start_line, "end_line": end_line}
        ],
        "text": "\n".join(span_lines),
        "numbered_source": _numbered_source(
            "\n".join(span_lines),
            start_line,
        ),
    }


def _numbered_line_id(line: str) -> int:
    match = re.match(r"^L(\d+)\t", line)
    return int(match.group(1)) if match else 0


def _merge_raw_relations(existing: Any, discovered: Any) -> list[Any]:
    existing_items = existing if isinstance(existing, list) else []
    discovered_items = discovered if isinstance(discovered, list) else []
    merged: list[Any] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in [*existing_items, *discovered_items]:
        if not isinstance(item, dict):
            merged.append(item)
            continue
        key = (
            str(item.get("source_action_id", "")).strip(),
            str(item.get("target_action_id", "")).strip(),
            str(item.get("type", "")).strip(),
            str(item.get("condition", "")).strip(),
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def _best_variant_candidate(
    raw_candidates: list[Any],
    variant_plan: dict[str, Any],
    source_text: str,
) -> tuple[dict[str, Any] | None, set[str]]:
    best_candidate = None
    best_coverage: set[str] = set()
    best_score = (-1, -1, -1)
    for candidate in raw_candidates:
        if not isinstance(candidate, dict):
            continue
        coverage = _candidate_variant_coverage(
            candidate,
            variant_plan,
            source_text,
        )
        actions = candidate.get("actions", [])
        relations = candidate.get("relations", [])
        score = (
            len(coverage),
            len(actions) if isinstance(actions, list) else 0,
            len(relations) if isinstance(relations, list) else 0,
        )
        if score > best_score:
            best_candidate = candidate
            best_coverage = coverage
            best_score = score
    return best_candidate, best_coverage


def _candidate_variant_coverage(
    candidate: dict[str, Any],
    variant_plan: dict[str, Any],
    source_text: str,
) -> set[str]:
    action_line_ids: set[int] = set()
    actions = candidate.get("actions", [])
    if not isinstance(actions, list):
        return set()
    for action in actions:
        if not isinstance(action, dict):
            continue
        evidence = action.get("evidence", [])
        if not isinstance(evidence, list):
            continue
        for evidence_item in evidence:
            exact_quote = _resolve_exact_quote(
                _quote_from(evidence_item),
                source_text,
            )
            if exact_quote:
                action_line_ids.update(
                    _quote_line_ids(exact_quote, source_text)
                )
    covered = set()
    for variant in variant_plan["variants"]:
        variant_line_ids = {
            line_id
            for line_range in variant["line_ranges"]
            for line_id in range(
                line_range["start_line"],
                line_range["end_line"] + 1,
            )
        }
        if action_line_ids.intersection(variant_line_ids):
            covered.add(variant["id"])
    return covered


def _evidence_variant_ids(
    evidence: list[AttackFlowDraftEvidence],
    variant_plan: dict[str, Any],
    source_text: str,
) -> set[str]:
    evidence_line_ids = {
        line_id
        for evidence_item in evidence
        for line_id in _quote_line_ids(
            evidence_item.quote,
            source_text,
        )
    }
    covered = set()
    variants = variant_plan.get("variants", [])
    if not isinstance(variants, list):
        return covered
    for variant in variants:
        if not isinstance(variant, dict):
            continue
        line_ranges = variant.get("line_ranges", [])
        if not isinstance(line_ranges, list):
            continue
        variant_line_ids = {
            line_id
            for line_range in line_ranges
            if isinstance(line_range, dict)
            for line_id in range(
                int(line_range["start_line"]),
                int(line_range["end_line"]) + 1,
            )
        }
        if evidence_line_ids.intersection(variant_line_ids):
            covered.add(str(variant.get("id", "")).strip())
    covered.discard("")
    return covered


def _quote_line_ids(quote: str, source_text: str) -> set[int]:
    line_ids = set()
    start = 0
    while True:
        offset = source_text.find(quote, start)
        if offset < 0:
            break
        start_line = source_text.count("\n", 0, offset) + 1
        line_ids.update(
            range(start_line, start_line + quote.count("\n") + 1)
        )
        start = offset + max(len(quote), 1)
    return line_ids


def _compact_raw_candidates(raw_candidates: list[Any]) -> list[dict[str, Any]]:
    compact = []
    for candidate in raw_candidates:
        if not isinstance(candidate, dict):
            continue
        actions = candidate.get("actions", [])
        if not isinstance(actions, list):
            actions = []
        compact.append(
            {
                "title": candidate.get("title"),
                "actions": [
                    {
                        "id": action.get("id"),
                        "name": action.get("name"),
                        "evidence": action.get("evidence", []),
                    }
                    for action in actions
                    if isinstance(action, dict)
                ],
            }
        )
    return compact


def extract_attack_flow_candidates(
    language_model: AttackFlowLanguageModel,
    report: dict[str, Any],
    source_text: str,
) -> AttackFlowExtractionResult:
    raw = language_model.extract_attack_flows(report, source_text)
    rejected: list[dict[str, Any]] = []
    unassigned: list[dict[str, str]] = []
    review_fragments: list[dict[str, Any]] = []
    candidates: list[AttackFlowDraft] = []

    for item in raw.get("unassigned_evidence", []):
        quote = _quote_from(item)
        exact_quote = _resolve_exact_quote(quote, source_text)
        if exact_quote:
            unassigned.append(
                {
                    "quote": exact_quote,
                    "reason": str(item.get("reason", "未归属到具体活动")).strip(),
                }
            )
        else:
            _reject(rejected, "unassigned-evidence", "quote-not-in-source", item)

    raw_candidates = raw.get("candidates", [])
    if not isinstance(raw_candidates, list):
        _reject(rejected, "response", "candidates-must-be-list", raw_candidates)
        raw_candidates = []
    for candidate_index, raw_candidate in enumerate(raw_candidates, start=1):
        candidate = _sanitize_candidate(
            raw_candidate,
            candidate_index,
            source_text,
            rejected,
            review_fragments,
        )
        if candidate is not None:
            candidates.append(candidate)

    warnings = []
    if rejected:
        warnings.append(f"{len(rejected)} 项模型事实未通过数据规范或原文校验。")
    if unassigned:
        warnings.append(f"{len(unassigned)} 条有效证据尚未归属到具体攻击活动。")
    return AttackFlowExtractionResult(
        candidates=candidates,
        audit={
            "method": "schema-first-attack-flow-extraction",
            "model": language_model.model,
            "prompt_version": PROMPT_VERSION,
            "cache_hit": False,
            "review_state": "model-extracted-unreviewed",
            "warnings": warnings,
            "observations": [],
            "candidate_count": len(candidates),
            "activity_segmentation": raw.get("_segmentation"),
            "mainline_method": "verified-relation-graph-longest-path",
            "rejected_facts": rejected,
            "unassigned_evidence": unassigned,
            "review_fragments": review_fragments,
        },
    )


def _sanitize_candidate(
    raw: Any,
    candidate_index: int,
    source_text: str,
    rejected: list[dict[str, Any]],
    review_fragments: list[dict[str, Any]],
) -> AttackFlowDraft | None:
    if not isinstance(raw, dict):
        _reject(rejected, "candidate", "candidate-must-be-object", raw)
        return None
    raw_actions = raw.get("actions", [])
    if not isinstance(raw_actions, list):
        _reject(rejected, "candidate", "actions-must-be-list", raw_actions)
        return None

    actions: list[AttackFlowDraftAction] = []
    action_id_map: dict[str, str] = {}
    action_variant_ids: dict[str, set[str]] = {}
    variant_plan = raw.get("_verified_variant_plan", {"variants": []})
    if not isinstance(variant_plan, dict):
        variant_plan = {"variants": []}
    context_index = 0
    for raw_action in raw_actions:
        if not isinstance(raw_action, dict):
            _reject(rejected, "action", "action-must-be-object", raw_action)
            continue
        original_id = str(raw_action.get("id", "")).strip()
        if not original_id or original_id in action_id_map:
            _reject(rejected, "action", "missing-or-duplicate-local-id", raw_action)
            continue
        name = _normalize_action_name(
            str(raw_action.get("name", "")).strip()
        )
        kind = str(raw_action.get("kind", raw_action.get("type", ""))).strip()
        if not _is_concise_action_name(name) or kind in CONTEXT_TYPES:
            _reject(rejected, "action", "name-is-not-concise-verb-object", raw_action)
            continue
        evidence = _verified_evidence(
            raw_action.get("evidence", []),
            source_text,
            rejected,
            "action",
        )
        if not evidence:
            _reject(rejected, "action", "no-valid-source-quote", raw_action)
            continue
        local_id = f"A{len(actions) + 1}"
        contexts: list[AttackFlowDraftContext] = []
        for raw_context in raw_action.get("contexts", []):
            context_index += 1
            context = _sanitize_context(
                raw_context,
                f"C{context_index}",
                source_text,
                rejected,
            )
            if context is not None:
                contexts.append(context)
        technique_ids: list[str] = []
        for technique_id in raw_action.get("technique_ids", []):
            normalized = str(technique_id).strip().upper()
            if ATTACK_ID_PATTERN.fullmatch(normalized):
                technique_ids.append(normalized)
            else:
                _reject(rejected, "attack-mapping", "invalid-technique-id", technique_id)
        action_id_map[original_id] = local_id
        action_variant_ids[local_id] = _evidence_variant_ids(
            evidence,
            variant_plan,
            source_text,
        )
        actions.append(
            AttackFlowDraftAction(
                id=local_id,
                name=name,
                description=str(raw_action.get("description", "")).strip(),
                phase=str(raw_action.get("phase", "")).strip(),
                confidence=_confidence(raw_action.get("confidence")),
                technique_ids=list(dict.fromkeys(technique_ids)),
                contexts=contexts,
                evidence=evidence,
            )
        )

    if len(actions) < 2:
        _reject(rejected, "candidate", "candidate-has-fewer-than-two-actions", raw)
        return None

    relations: list[AttackFlowDraftRelation] = []
    relation_ids: set[str] = set()
    for raw_relation in raw.get("relations", []):
        if not isinstance(raw_relation, dict):
            _reject(rejected, "relation", "relation-must-be-object", raw_relation)
            continue
        original_id = str(raw_relation.get("id", "")).strip()
        if not original_id or original_id in relation_ids:
            _reject(rejected, "relation", "missing-or-duplicate-local-id", raw_relation)
            continue
        relation_ids.add(original_id)
        relation_type = str(raw_relation.get("type", "")).strip()
        if relation_type not in ALLOWED_RELATIONS:
            _reject(rejected, "relation", "unsupported-relation-type", raw_relation)
            continue
        source_id = action_id_map.get(str(raw_relation.get("source_action_id", "")).strip())
        target_id = action_id_map.get(str(raw_relation.get("target_action_id", "")).strip())
        if source_id is None or target_id is None or source_id == target_id:
            _reject(rejected, "relation", "invalid-action-reference", raw_relation)
            continue
        evidence = _verified_evidence(
            raw_relation.get("evidence", []),
            source_text,
            rejected,
            "relation",
        )
        if not evidence:
            _reject(rejected, "relation", "no-valid-source-quote", raw_relation)
            continue
        relations.append(
            AttackFlowDraftRelation(
                id=f"R{len(relations) + 1}",
                source_action_id=source_id,
                target_action_id=target_id,
                type=relation_type,
                condition=(
                    str(raw_relation["condition"]).strip()
                    if raw_relation.get("condition") is not None
                    else None
                ),
                confidence=_confidence(raw_relation.get("confidence")),
                evidence=evidence,
            )
        )

    actors: list[AttackFlowDraftActorClaim] = []
    for raw_actor in raw.get("reported_actors", []):
        if not isinstance(raw_actor, dict):
            _reject(rejected, "reported-actor", "actor-must-be-object", raw_actor)
            continue
        reported_name = str(raw_actor.get("reported_name", "")).strip()
        evidence = _verified_evidence(
            raw_actor.get("evidence", []),
            source_text,
            rejected,
            "reported-actor",
        )
        if (
            not reported_name
            or reported_name.casefold()
            in {"threat actor", "attacker", "adversary", "unknown"}
            or not evidence
        ):
            _reject(rejected, "reported-actor", "missing-name-or-source-quote", raw_actor)
            continue
        actors.append(
            AttackFlowDraftActorClaim(
                id=f"ACTOR{len(actors) + 1}",
                reported_name=reported_name,
                confidence=_confidence(raw_actor.get("confidence")),
                evidence=evidence,
            )
        )

    title = str(raw.get("title", "")).strip() or f"攻击活动 {candidate_index}"
    actions, relations, mainline = _project_verified_graph(
        title,
        actions,
        relations,
        rejected,
        review_fragments,
        action_variant_ids,
    )
    if len(actions) < 2:
        _reject(
            rejected,
            "candidate",
            "candidate-has-fewer-than-two-connected-actions",
            raw,
        )
        return None

    return AttackFlowDraft(
        title=title,
        description=str(raw.get("description", "")).strip(),
        actions=actions,
        relations=relations,
        mainline=mainline,
        reported_actors=actors,
    )


def _sanitize_context(
    raw: Any,
    local_id: str,
    source_text: str,
    rejected: list[dict[str, Any]],
) -> AttackFlowDraftContext | None:
    if not isinstance(raw, dict):
        _reject(rejected, "context", "context-must-be-object", raw)
        return None
    context_type = str(raw.get("type", "")).strip()
    role = str(raw.get("role", "")).strip()
    name = str(raw.get("name", "")).strip()
    if context_type not in CONTEXT_TYPES or role not in CONTEXT_ROLES or not name:
        _reject(rejected, "context", "invalid-context-shape", raw)
        return None
    evidence = _verified_evidence(
        raw.get("evidence", []), source_text, rejected, "context"
    )
    if not evidence:
        _reject(rejected, "context", "no-valid-source-quote", raw)
        return None
    return AttackFlowDraftContext(
        id=local_id,
        type=context_type,
        name=name,
        role=role,
        confidence=_confidence(raw.get("confidence")),
        evidence=evidence,
    )


def _project_verified_graph(
    candidate_title: str,
    actions: list[AttackFlowDraftAction],
    relations: list[AttackFlowDraftRelation],
    rejected: list[dict[str, Any]],
    review_fragments: list[dict[str, Any]],
    action_variant_ids: dict[str, set[str]] | None = None,
) -> tuple[
    list[AttackFlowDraftAction],
    list[AttackFlowDraftRelation],
    list[str],
]:
    if not relations:
        return actions, relations, []
    action_order = {action.id: index for index, action in enumerate(actions)}
    components = _weak_components(actions, relations)
    action_variant_ids = action_variant_ids or {}
    component_details = []
    for component in components:
        component_relations = [
            relation
            for relation in relations
            if relation.source_action_id in component
            and relation.target_action_id in component
        ]
        path = _longest_directed_path(
            component,
            component_relations,
            action_order,
        )
        component_details.append(
            {
                "ids": component,
                "relations": component_relations,
                "path": path,
                "variant_ids": set().union(
                    *(action_variant_ids.get(action_id, set()) for action_id in component)
                ),
            }
        )
    def component_key(item: dict[str, Any]) -> tuple[int, int, int, int]:
        return (
            len(item["path"]),
            len(item["relations"]),
            len(item["ids"]),
            -min(action_order[action_id] for action_id in item["ids"]),
        )
    primary_index = max(
        range(len(component_details)),
        key=lambda item: (
            component_key(component_details[item])
        ),
    )
    primary = component_details[primary_index]
    if not primary["path"]:
        _reject(
            rejected,
            "candidate",
            "verified-relation-graph-has-cycle",
            {"title": candidate_title},
        )
    selected_indices = {primary_index}
    variant_ids = set().union(
        *(component["variant_ids"] for component in component_details)
    )
    for variant_id in variant_ids:
        matching_indices = [
            index
            for index, component in enumerate(component_details)
            if variant_id in component["variant_ids"]
        ]
        if matching_indices:
            selected_indices.add(
                max(
                    matching_indices,
                    key=lambda index: component_key(
                        component_details[index]
                    ),
                )
            )
    action_by_id = {action.id: action for action in actions}
    for component_index, component in enumerate(component_details):
        if component_index in selected_indices:
            continue
        review_fragments.append(
            {
                "candidate_title": candidate_title,
                "reason": "disconnected-from-primary-flow",
                "actions": [
                    {
                        "id": action_id,
                        "name": action_by_id[action_id].name,
                        "evidence": [
                            evidence.model_dump()
                            for evidence in action_by_id[action_id].evidence
                        ],
                    }
                    for action_id in sorted(
                        component["ids"],
                        key=action_order.get,
                    )
                ],
                "relations": [
                    relation.model_dump()
                    for relation in component["relations"]
                ],
            }
        )

    kept_ids = set().union(
        *(
            component_details[index]["ids"]
            for index in selected_indices
        )
    )
    kept_relations = [
        relation
        for relation in relations
        if relation.source_action_id in kept_ids
        and relation.target_action_id in kept_ids
    ]
    kept_actions = [action for action in actions if action.id in kept_ids]
    action_id_map = {
        action.id: f"A{index}"
        for index, action in enumerate(kept_actions, start=1)
    }
    context_index = 0
    normalized_actions: list[AttackFlowDraftAction] = []
    for action in kept_actions:
        contexts: list[AttackFlowDraftContext] = []
        for context in action.contexts:
            context_index += 1
            contexts.append(
                context.model_copy(update={"id": f"C{context_index}"})
            )
        normalized_actions.append(
            action.model_copy(
                update={
                    "id": action_id_map[action.id],
                    "contexts": contexts,
                }
            )
        )
    normalized_relations = [
        relation.model_copy(
            update={
                "id": f"R{index}",
                "source_action_id": action_id_map[relation.source_action_id],
                "target_action_id": action_id_map[relation.target_action_id],
            }
        )
        for index, relation in enumerate(kept_relations, start=1)
    ]
    mainline = [action_id_map[action_id] for action_id in primary["path"]]
    return normalized_actions, normalized_relations, mainline


def _weak_components(
    actions: list[AttackFlowDraftAction],
    relations: list[AttackFlowDraftRelation],
) -> list[set[str]]:
    neighbors = {action.id: set() for action in actions}
    for relation in relations:
        neighbors[relation.source_action_id].add(relation.target_action_id)
        neighbors[relation.target_action_id].add(relation.source_action_id)
    components: list[set[str]] = []
    unseen = set(neighbors)
    while unseen:
        start = min(unseen)
        component: set[str] = set()
        pending = [start]
        while pending:
            action_id = pending.pop()
            if action_id in component:
                continue
            component.add(action_id)
            pending.extend(neighbors[action_id] - component)
        unseen -= component
        components.append(component)
    return components


def _longest_directed_path(
    component: set[str],
    relations: list[AttackFlowDraftRelation],
    action_order: dict[str, int],
) -> list[str]:
    outgoing = {action_id: set() for action_id in component}
    indegree = {action_id: 0 for action_id in component}
    for relation in relations:
        if relation.target_action_id in outgoing[relation.source_action_id]:
            continue
        outgoing[relation.source_action_id].add(relation.target_action_id)
        indegree[relation.target_action_id] += 1
    ready = sorted(
        (action_id for action_id, degree in indegree.items() if degree == 0),
        key=action_order.get,
    )
    topological: list[str] = []
    while ready:
        action_id = ready.pop(0)
        topological.append(action_id)
        for target_id in sorted(outgoing[action_id], key=action_order.get):
            indegree[target_id] -= 1
            if indegree[target_id] == 0:
                ready.append(target_id)
                ready.sort(key=action_order.get)
    if len(topological) != len(component):
        return []
    best_path = {action_id: [action_id] for action_id in component}
    for action_id in topological:
        for target_id in sorted(outgoing[action_id], key=action_order.get):
            candidate = [*best_path[action_id], target_id]
            if len(candidate) > len(best_path[target_id]):
                best_path[target_id] = candidate
    return max(
        best_path.values(),
        key=lambda path: (
            len(path),
            tuple(-action_order[action_id] for action_id in path),
        ),
    )


def _verified_evidence(
    raw_items: Any,
    source_text: str,
    rejected: list[dict[str, Any]],
    fact_type: str,
) -> list[AttackFlowDraftEvidence]:
    if not isinstance(raw_items, list):
        _reject(rejected, fact_type, "evidence-must-be-list", raw_items)
        return []
    verified: list[AttackFlowDraftEvidence] = []
    for item in raw_items:
        quote = _quote_from(item)
        exact_quote = _resolve_exact_quote(quote, source_text)
        if not exact_quote:
            _reject(rejected, fact_type, "quote-not-in-source", item)
            continue
        verified.append(AttackFlowDraftEvidence(quote=exact_quote))
    return list({item.quote: item for item in verified}.values())


def _quote_from(raw: Any) -> str:
    if isinstance(raw, str):
        return raw.strip()
    if isinstance(raw, dict):
        return str(raw.get("quote", "")).strip()
    return ""


def _resolve_exact_quote(quote: str, source_text: str) -> str | None:
    if not quote:
        return None
    if quote in source_text:
        return quote
    tokens = quote.split()
    if not tokens:
        return None
    pattern = r"\s+".join(re.escape(token) for token in tokens)
    matches = list(re.finditer(pattern, source_text))
    if len(matches) != 1:
        return None
    return matches[0].group(0)


def _is_concise_action_name(name: str) -> bool:
    if not name or len(name) > 72 or "\n" in name:
        return False
    if name.endswith((".", "?", "!", "。", "？", "！", ";", "；")):
        return False
    if ENTITY_NAME_PATTERN.fullmatch(name):
        return False
    words = name.split()
    if len(words) > 8:
        return False
    return bool(
        ENGLISH_ACTION_PATTERN.search(name)
        or _has_english_action_verb(name)
        or CHINESE_ACTION_PATTERN.search(name)
    )


def _normalize_action_name(name: str) -> str:
    nominalizations = {
        "communication": "Communicate with",
        "delivery": "Deliver",
        "download": "Download",
        "execution": "Execute",
        "exfiltration": "Exfiltrate",
    }
    match = re.fullmatch(
        r"(.+?)\s+(communication|delivery|download|execution|exfiltration)",
        name,
        flags=re.IGNORECASE,
    )
    if not match:
        return name
    target, nominalization = match.groups()
    return f"{nominalizations[nominalization.casefold()]} {target}"


def _has_english_action_verb(name: str) -> bool:
    first_word = name.split(maxsplit=1)[0].casefold()
    candidates = {first_word}
    if first_word.endswith("ies"):
        candidates.add(f"{first_word[:-3]}y")
    if first_word.endswith("es"):
        candidates.add(first_word[:-1])
        candidates.add(first_word[:-2])
    if first_word.endswith("s"):
        candidates.add(first_word[:-1])
    if first_word.endswith("ed"):
        candidates.add(first_word[:-1])
        candidates.add(first_word[:-2])
    if first_word.endswith("ing"):
        candidates.add(first_word[:-3])
        candidates.add(f"{first_word[:-3]}e")
    return bool(candidates.intersection(ENGLISH_ACTION_VERBS))


def _confidence(raw: Any) -> str:
    value = str(raw or "medium").strip().lower()
    return value if value in CONFIDENCE_LEVELS else "medium"


def _reject(
    rejected: list[dict[str, Any]],
    fact_type: str,
    reason: str,
    item: Any,
) -> None:
    rejected.append({"fact_type": fact_type, "reason": reason, "item": item})


def _strip_json_fence(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
    return stripped


def deepseek_attack_flow_from_environment() -> DeepSeekAttackFlowExtractor | None:
    base_url = os.environ.get("ARGUS_LLM_BASE_URL", "").strip()
    api_key = os.environ.get("ARGUS_LLM_API_KEY", "").strip()
    model = os.environ.get("ARGUS_LLM_MODEL", "").strip()
    if not base_url or not api_key or not model:
        return None
    return DeepSeekAttackFlowExtractor(
        base_url=base_url,
        api_key=api_key,
        model=model,
    )
