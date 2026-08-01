from difflib import SequenceMatcher
from hashlib import sha256
import json
import re
import unicodedata

from .models import (
    AttackFlow,
    FlowActionState,
    FlowMatchCandidate,
    FlowMatchDetail,
    FlowMatchInput,
    FlowMatchKind,
    FlowMatchRequest,
    FlowMatchRun,
    NormalizedFlowMatchInput,
)


ALGORITHM_VERSION = "attack-flow-matcher/1.0"
CANDIDATE_THRESHOLD = 0.42
MATCH_THRESHOLD = 0.58


class AttackFlowMatcher:
    def __init__(self, flows: list[AttackFlow]) -> None:
        self.flows = sorted(flows, key=lambda flow: flow.id)

    def match(self, run_id: str, request: FlowMatchRequest) -> FlowMatchRun:
        normalized_inputs = self._normalize_inputs(request)
        candidates = [
            candidate
            for flow in self.flows
            if (candidate := self._candidate(flow, normalized_inputs)) is not None
        ]
        candidates.sort(key=lambda item: (-item.score, item.flow_id))
        query_text = request.query_text or "；".join(
            item.value for item in normalized_inputs
        )
        return FlowMatchRun(
            id=run_id,
            algorithm_version=ALGORITHM_VERSION,
            knowledge_snapshot=self._knowledge_snapshot(),
            query_text=query_text,
            normalized_inputs=normalized_inputs,
            candidates=candidates,
        )

    def _candidate(
        self,
        flow: AttackFlow,
        inputs: list[NormalizedFlowMatchInput],
    ) -> FlowMatchCandidate | None:
        matches: list[FlowMatchDetail] = []
        matched_input_indexes: set[int] = set()
        for input_index, item in enumerate(inputs):
            best = self._best_match(flow, input_index, item)
            required_confidence = (
                0.3 if best is not None and best.match_kind == "attack" else MATCH_THRESHOLD
            )
            if best is not None and best.confidence >= required_confidence:
                matches.append(best)
                matched_input_indexes.add(input_index)

        primary_matches = [item for item in matches if item.match_kind != "attack"]
        if not primary_matches:
            return None

        score = self._candidate_score(inputs, matches)
        if score < CANDIDATE_THRESHOLD:
            return None

        mainline_index = {action_id: index for index, action_id in enumerate(flow.mainline)}
        frontier_indexes = [
            mainline_index[item.action_id]
            for item in primary_matches
            if item.action_id in mainline_index
        ]
        frontier_index = max(frontier_indexes) if frontier_indexes else None
        matched_action_ids = {item.action_id for item in matches}
        action_states = []
        for action in flow.actions:
            if action.id in matched_action_ids:
                state = "input_hit"
            elif action.id not in mainline_index or frontier_index is None:
                state = "reference"
            elif mainline_index[action.id] <= frontier_index:
                state = "reconstructed"
            else:
                state = "predicted"
            action_states.append(FlowActionState(action_id=action.id, state=state))

        return FlowMatchCandidate(
            flow_id=flow.id,
            flow_title=flow.title,
            score=score,
            matches=sorted(matches, key=lambda item: item.input_index),
            unmatched_inputs=[
                item
                for index, item in enumerate(inputs)
                if index not in matched_input_indexes
            ],
            mainline_frontier_action_id=(
                flow.mainline[frontier_index] if frontier_index is not None else None
            ),
            mainline_frontier_index=frontier_index,
            action_states=action_states,
        )

    def _best_match(
        self,
        flow: AttackFlow,
        input_index: int,
        item: NormalizedFlowMatchInput,
    ) -> FlowMatchDetail | None:
        allowed = self._allowed_match_kinds(item.kind)
        ranked: list[tuple[float, int, str, FlowMatchDetail]] = []
        for action_index, action in enumerate(flow.actions):
            if "behavior" in allowed:
                behavior_values = [action.name]
                if action.description:
                    behavior_values.append(action.description)
                for value in behavior_values:
                    lexical_score = self._text_score(item.normalized_value, value)
                    confidence = lexical_score
                    ranked.append(
                        (
                            confidence,
                            action_index,
                            "behavior",
                            FlowMatchDetail(
                                input_index=input_index,
                                input_value=item.value,
                                input_kind=item.kind,
                                action_id=action.id,
                                match_kind="behavior",
                                matched_value=value,
                                confidence=round(confidence, 3),
                                explanation=(
                                    f"输入行为“{item.value}”与历史行为“{value}”匹配。"
                                ),
                            ),
                        )
                    )
            if "context" in allowed:
                for context in action.contexts:
                    if not self._context_type_matches(item.kind, context.type):
                        continue
                    lexical_score = self._text_score(item.normalized_value, context.name)
                    confidence = lexical_score * 0.97
                    ranked.append(
                        (
                            confidence,
                            action_index,
                            "context",
                            FlowMatchDetail(
                                input_index=input_index,
                                input_value=item.value,
                                input_kind=item.kind,
                                action_id=action.id,
                                match_kind="context",
                                matched_value=context.name,
                                confidence=round(confidence, 3),
                                explanation=(
                                    f"输入线索“{item.value}”命中该行为旁的 Context"
                                    f"“{context.name}”；这不代表行为本身被直接观测。"
                                ),
                            ),
                        )
                    )
            if "attack" in allowed:
                for technique_id in action.technique_ids:
                    lexical_score = self._text_score(
                        item.normalized_value, technique_id
                    )
                    confidence = lexical_score * 0.35
                    ranked.append(
                        (
                            confidence,
                            action_index,
                            "attack",
                            FlowMatchDetail(
                                input_index=input_index,
                                input_value=item.value,
                                input_kind=item.kind,
                                action_id=action.id,
                                match_kind="attack",
                                matched_value=technique_id,
                                confidence=round(confidence, 3),
                                explanation=(
                                    f"输入 ATT&CK 标注“{item.value}”与行为注解"
                                    f"“{technique_id}”匹配，仅作为辅助依据。"
                                ),
                            ),
                        )
                    )
        if not ranked:
            return None
        return max(
            ranked,
            key=lambda item: (item[0], -item[1], self._kind_priority(item[2])),
        )[3]

    @staticmethod
    def _candidate_score(
        inputs: list[NormalizedFlowMatchInput], matches: list[FlowMatchDetail]
    ) -> float:
        if not inputs:
            return 0.0
        coverage = sum(item.confidence for item in matches) / len(inputs)
        strongest = max((item.confidence for item in matches), default=0.0)
        diversity = min(len({item.action_id for item in matches}), 3) / 3
        return round(0.6 * coverage + 0.25 * strongest + 0.15 * diversity, 3)

    def _knowledge_snapshot(self) -> str:
        payload = [flow.model_dump(mode="json") for flow in self.flows]
        return sha256(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    @classmethod
    def _normalize_inputs(
        cls, request: FlowMatchRequest
    ) -> list[NormalizedFlowMatchInput]:
        supplied = request.inputs
        if not supplied and request.query_text:
            supplied = [
                FlowMatchInput(value=value, kind="auto")
                for value in re.split(r"[\n；;→]+", request.query_text)
                if value.strip()
            ]
        if not supplied:
            raise ValueError("At least one flow matching input is required")
        return [
            NormalizedFlowMatchInput(
                value=item.value,
                kind=cls._normalize_kind(item.kind),
                normalized_value=cls._normalize_text(item.value),
            )
            for item in supplied
        ]

    @staticmethod
    def _normalize_kind(kind: str) -> str:
        value = kind.casefold().strip()
        aliases = {
            "行为": "behavior",
            "action": "behavior",
            "technique": "attack",
            "att&ck": "attack",
            "漏洞": "vulnerability",
            "恶意软件": "malware",
            "工具": "tool",
        }
        return aliases.get(value, value or "auto")

    @classmethod
    def _text_score(cls, normalized_input: str, target: str) -> float:
        normalized_target = cls._normalize_text(target)
        if not normalized_input or not normalized_target:
            return 0.0
        if normalized_input == normalized_target:
            return 1.0
        if min(len(normalized_input), len(normalized_target)) >= 4 and (
            normalized_input in normalized_target
            or normalized_target in normalized_input
        ):
            return 0.9
        input_tokens = cls._tokens(normalized_input)
        target_tokens = cls._tokens(normalized_target)
        if any(
            len(left) >= 4 and (left in right or right in left)
            for left in input_tokens
            for right in target_tokens
        ):
            return 0.84
        return SequenceMatcher(None, normalized_input, normalized_target).ratio()

    @staticmethod
    def _normalize_text(value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value).casefold()
        return "".join(character for character in normalized if character.isalnum())

    @staticmethod
    def _tokens(value: str) -> list[str]:
        return [token for token in re.split(r"[^a-z0-9\u3400-\u9fff]+", value) if token]

    @staticmethod
    def _allowed_match_kinds(kind: str) -> set[FlowMatchKind]:
        if kind in {"behavior"}:
            return {"behavior"}
        if kind in {"attack"}:
            return {"attack"}
        if kind in {
            "context",
            "ioc",
            "malware",
            "tool",
            "vulnerability",
            "file",
            "process",
            "account",
            "asset",
            "infrastructure",
            "ip",
            "domain",
            "url",
            "hash",
        }:
            return {"context"}
        return {"behavior", "context", "attack"}

    @staticmethod
    def _context_type_matches(input_kind: str, context_type: str) -> bool:
        if input_kind in {"auto", "context", "ioc"}:
            return True
        if input_kind == "infrastructure":
            return context_type in {"infrastructure", "ip", "domain", "url"}
        return input_kind == context_type

    @staticmethod
    def _kind_priority(kind: str) -> int:
        return {"behavior": 3, "context": 2, "attack": 1}[kind]
