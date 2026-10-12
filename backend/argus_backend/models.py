from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class SourceArchiveRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    title: str = Field(min_length=1)
    publisher: str = Field(min_length=1)
    canonical_url: HttpUrl
    published_at: str = Field(min_length=1)
    mime_type: str = Field(min_length=1)
    content: str = Field(min_length=1)


class SourceDocument(BaseModel):
    id: str
    title: str
    publisher: str
    canonical_url: str
    published_at: str
    mime_type: str
    sha256: str
    content_size: int
    review_state: str


class SourceSpan(BaseModel):
    id: str
    source_document_id: str
    locator: str
    start_offset: int
    end_offset: int
    text: str
    extraction_method: str


class SourceArchiveResponse(BaseModel):
    source_document: SourceDocument
    source_spans: list[SourceSpan]
    created: bool


ConfidenceLevel = Literal["high", "medium", "low"]
AttackFlowContextType = Literal[
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
]
AttackFlowContextRole = Literal[
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
]
AttackFlowRelationType = Literal[
    "precedes",
    "leads_to",
    "enables",
    "causes",
    "on_success",
    "on_failure",
]


class AttackFlowSource(BaseModel):
    id: str
    title: str
    publisher: str
    canonical_url: str
    published_at: str


class AttackFlowEvidence(BaseModel):
    id: str
    source_span_id: str
    source_id: str
    title: str
    publisher: str
    canonical_url: str
    locator: str
    quote: str
    confidence: float


class AttackFlowContext(BaseModel):
    id: str
    entity_id: str | None
    type: AttackFlowContextType
    name: str
    role: AttackFlowContextRole
    direction: str
    confidence: ConfidenceLevel
    evidence: list[AttackFlowEvidence]


class AttackFlowAction(BaseModel):
    id: str
    name: str
    description: str
    phase: str
    confidence: ConfidenceLevel
    technique_ids: list[str]
    contexts: list[AttackFlowContext]
    evidence: list[AttackFlowEvidence]


class AttackFlowRelation(BaseModel):
    id: str
    source_action_id: str
    target_action_id: str
    type: AttackFlowRelationType
    condition: str | None
    confidence: ConfidenceLevel
    evidence: list[AttackFlowEvidence]


class AttackFlowReportedActor(BaseModel):
    id: str
    reported_name: str
    actor_id: str | None
    confidence: ConfidenceLevel
    evidence: list[AttackFlowEvidence]


class AttackFlow(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    id: str
    title: str
    description: str
    sources: list[AttackFlowSource]
    reported_actors: list[AttackFlowReportedActor] = Field(default_factory=list)
    actions: list[AttackFlowAction]
    relations: list[AttackFlowRelation]
    mainline: list[str]


AttackFlowSourceAnnotationKind = Literal[
    "attack-process",
    "ioc",
    "software",
    "vulnerability",
    "asset",
    "actor",
]


class AttackFlowSourceAnnotation(BaseModel):
    id: str
    kind: AttackFlowSourceAnnotationKind
    label: str
    start_offset: int
    end_offset: int
    quote: str
    confidence: float
    action_ids: list[str] = Field(default_factory=list)
    entity_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class AttackFlowSourceDocumentView(BaseModel):
    id: str
    title: str
    publisher: str
    canonical_url: str
    published_at: str
    mime_type: str
    content: str
    annotations: list[AttackFlowSourceAnnotation]


PanoramicNodeKind = Literal[
    "entity",
    "actor",
    "attack-flow",
    "action",
    "source",
    "evidence",
]


class PanoramicGraphNode(BaseModel):
    id: str
    kind: PanoramicNodeKind
    label: str
    type: str
    description: str = ""
    confidence: float = 1.0
    properties: dict = Field(default_factory=dict)


class PanoramicGraphExplanation(BaseModel):
    node_ids: list[str]
    edge_ids: list[str]


class PanoramicGraphEdge(BaseModel):
    id: str
    source_id: str
    target_id: str
    type: str
    label: str
    confidence: float = 1.0
    aggregate: bool = False
    evidence_ids: list[str] = Field(default_factory=list)
    evidence: list[AttackFlowEvidence] = Field(default_factory=list)
    explanation: PanoramicGraphExplanation | None = None


class PanoramicGraphIndexItem(PanoramicGraphNode):
    relation_count: int = 0
    evidence_count: int = 0


class PanoramicGraphIndex(BaseModel):
    nodes: list[PanoramicGraphIndexItem]
    node_count: int
    evidence_node_count: int = 0
    atomic_edge_count: int
    aggregate_edge_count: int
    knowledge_version: str


class PanoramicGraphNeighborhood(BaseModel):
    root_id: str
    depth: int
    nodes: list[PanoramicGraphNode]
    edges: list[PanoramicGraphEdge]
    available_expansions: dict[str, int]
    knowledge_version: str


class AttackFlowDraftEvidence(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    quote: str = Field(min_length=1)


class AttackFlowDraftContext(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    id: str = Field(min_length=1)
    type: AttackFlowContextType
    name: str = Field(min_length=1)
    role: AttackFlowContextRole
    confidence: ConfidenceLevel = "medium"
    evidence: list[AttackFlowDraftEvidence] = Field(default_factory=list)


class AttackFlowDraftAction(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = ""
    phase: str = ""
    confidence: ConfidenceLevel = "medium"
    technique_ids: list[str] = Field(default_factory=list)
    contexts: list[AttackFlowDraftContext] = Field(default_factory=list)
    evidence: list[AttackFlowDraftEvidence] = Field(default_factory=list)


class AttackFlowDraftRelation(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    id: str = Field(min_length=1)
    source_action_id: str = Field(min_length=1)
    target_action_id: str = Field(min_length=1)
    type: str = Field(min_length=1)
    condition: str | None = None
    confidence: ConfidenceLevel = "medium"
    evidence: list[AttackFlowDraftEvidence] = Field(default_factory=list)


class AttackFlowDraftActorClaim(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    id: str = Field(min_length=1)
    reported_name: str = Field(min_length=1)
    confidence: ConfidenceLevel = "medium"
    evidence: list[AttackFlowDraftEvidence] = Field(default_factory=list)


class AttackFlowDraft(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    title: str = Field(min_length=1)
    description: str = ""
    actions: list[AttackFlowDraftAction] = Field(default_factory=list)
    relations: list[AttackFlowDraftRelation] = Field(default_factory=list)
    mainline: list[str] = Field(default_factory=list)
    reported_actors: list[AttackFlowDraftActorClaim] = Field(default_factory=list)


class AttackFlowMergeReview(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    target_flow_id: str = Field(min_length=1)
    confirmed: bool = False
    action_map: dict[str, str] = Field(default_factory=dict)


FlowMatchKind = Literal["behavior", "context", "attack"]
FlowActionStateValue = Literal[
    "input_hit",
    "reconstructed",
    "predicted",
    "reference",
]


class FlowMatchInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    value: str = Field(min_length=1)
    kind: str = Field(default="auto", min_length=1)


class FlowMatchRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    query_text: str | None = None
    inputs: list[FlowMatchInput] = Field(default_factory=list)


class NormalizedFlowMatchInput(BaseModel):
    value: str
    kind: str
    normalized_value: str


class FlowMatchDetail(BaseModel):
    input_index: int
    input_value: str
    input_kind: str
    action_id: str
    match_kind: FlowMatchKind
    matched_value: str
    confidence: float
    explanation: str


class FlowActionState(BaseModel):
    action_id: str
    state: FlowActionStateValue


class FlowMatchCandidate(BaseModel):
    flow_id: str
    flow_title: str
    score: float
    matches: list[FlowMatchDetail]
    unmatched_inputs: list[NormalizedFlowMatchInput]
    mainline_frontier_action_id: str | None
    mainline_frontier_index: int | None
    action_states: list[FlowActionState]


class FlowMatchRun(BaseModel):
    id: str
    status: Literal["completed"] = "completed"
    algorithm_version: str
    knowledge_snapshot: str
    query_text: str
    normalized_inputs: list[NormalizedFlowMatchInput]
    candidates: list[FlowMatchCandidate]


class ObservationInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    value: str = Field(min_length=1)
    kind: str = Field(min_length=1)


class PathAnalysisRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    source_document_id: str = Field(min_length=1)
    query_text: str | None = None
    observations: list[ObservationInput] = Field(default_factory=list)


class ExtractedObservation(BaseModel):
    value: str
    kind: str
    confidence: float
    source_span_ids: list[str]
    quote: str


class ExtractionAudit(BaseModel):
    method: str
    model: str | None
    cache_hit: bool
    review_state: str
    warnings: list[str]
    observations: list[ExtractedObservation]


class ActivityClusterSummary(BaseModel):
    id: str
    title: str
    matched_observation_count: int
    observation_count: int


class EvidenceLink(BaseModel):
    evidence_id: str
    relation_id: str
    report_id: str
    title: str
    publisher: str
    canonical_url: str
    locator: str
    excerpt: str
    confidence: float


class PathStep(BaseModel):
    id: str
    sequence: int
    label: str
    disposition: str
    confidence: float
    input_observation: str | None
    explanation: str
    evidence_links: list[EvidenceLink]


class PathEdge(BaseModel):
    id: str
    source_step_id: str
    target_step_id: str
    relation_type: str
    confidence: float
    evidence_links: list[EvidenceLink]


class PathSummary(BaseModel):
    observed: int
    reconstructed: int
    predicted: int
    total: int


class ScoreAudit(BaseModel):
    input_coverage: float
    path_continuity: float
    source_reliability: float
    temporal_coherence: float
    final_score: float


class PathAnalysisResponse(BaseModel):
    id: str
    status: str
    algorithm_version: str
    knowledge_snapshot: str
    source_document_id: str
    extraction_audit: ExtractionAudit
    selected_activity_cluster: ActivityClusterSummary
    summary: PathSummary
    steps: list[PathStep]
    edges: list[PathEdge]
    score_audit: ScoreAudit
