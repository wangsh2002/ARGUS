export type Entity = {
  id: string;
  entity_type: string;
  canonical_key: string;
  label: string;
  normalized_value: string;
  description: string;
  first_seen: string | null;
  last_seen: string | null;
  source_count: number;
  properties: Record<string, unknown> & {
    actor?: string;
    event?: string;
    sub?: string;
    entity_value?: string;
    ui_type?: string;
    confidence?: number;
    status?: string;
    source_ref?: string;
  };
};

export type EntityAlias = {
  id: string;
  entity_id: string;
  alias: string;
  alias_type: string;
  source: string;
  confidence: number;
};

export type Relationship = {
  id: string;
  source_entity_id: string;
  target_entity_id: string;
  relation_type: string;
  confidence: number;
  evidence_count: number;
  first_seen: string | null;
  last_seen: string | null;
  category: string;
  status: string;
  properties: Record<string, unknown>;
};

export type Evidence = {
  id: string;
  relationship_id: string;
  report_id: string;
  source_ref: string;
  location: string;
  excerpt: string;
  confidence: number;
  report_title: string;
  publisher: string;
  report_date: string;
  canonical_url?: string;
};

export type Report = {
  id: string;
  title: string;
  source: string;
  report_date: string;
  classification: string;
  language: string;
  original_filename: string | null;
  mime_type: string | null;
  size_bytes: number;
  sha256: string;
  extracted_text: string;
  extraction_note: string;
  created_at: string;
  source_ref: string;
  reliability: string;
  external_url: string;
  assessment: string;
};

export type Actor = {
  id: string;
  label: string;
  description: string;
  source_count: number;
  properties: Record<string, unknown> & { sub?: string; confidence?: number };
  profile_status: string;
  origin_label: string;
  active_from: string | null;
  active_to: string | null;
  public_attribution: string;
  motivations: string[];
  target_sectors: string[];
  source_refs: string[];
  source_urls: string[];
  source_grade: number;
  updated_at: string;
};

export type ResponseRule = {
  id: string;
  match_entity_type: string;
  priority: string;
  action_template: string;
  rationale: string;
  source_url: string;
  title: string;
  group_label: string;
  match_event: string;
};

export type AlgorithmConfig = {
  id: string;
  algorithm_version: string;
  description: string;
  created_at: string;
  weights: Record<string, number>;
};

export type SourceArtifact = {
  id: string;
  collection_id: string;
  collection_record_id: string;
  title: string;
  publisher: string;
  canonical_url: string;
  acquisition_source: string;
  acquisition_url: string;
  published_at: string;
  collected_at: string;
  mime_type: string;
  size_bytes: number;
  sha256: string;
  storage_path: string;
  dataset_license: string;
  source_license: string;
  tlp: string;
  archive_status: string;
  canonical_verification_state: string;
  canonical_verified_at: string | null;
  review_state: string;
  metadata: Record<string, unknown>;
};

export type Snapshot = {
  meta: {
    source: string;
    generated_at: string;
    is_demo: boolean;
  };
  stats: {
    entities: number;
    relationships: number;
    evidence: number;
    reports: number;
    actors: number;
    iocs: number;
    attack_steps: number;
    corpus_artifacts: number;
    reviewed_paths: number;
  };
  entities: Entity[];
  relationships: Relationship[];
  evidence: Evidence[];
  reports: Report[];
  aliases: EntityAlias[];
  actors: Actor[];
  responseRules: ResponseRule[];
  algorithms: AlgorithmConfig[];
  sourceArtifacts: SourceArtifact[];
  historicalPaths: Array<{
    id: string;
    name: string;
    description: string;
    activity_key: string;
    path_kind: string;
    review_state: string;
    reviewer_type: string;
    reviewer_id: string | null;
    reviewed_at: string | null;
    primary_artifact_id: string | null;
    started_at: string | null;
    ended_at: string | null;
    victim_scope: string;
    confidence: number;
    metadata: Record<string, unknown>;
    nodes: Array<Record<string, unknown>>;
    edges: Array<Record<string, unknown>>;
    evidence: Array<Record<string, unknown>>;
    contextLinks: Array<{
      id: string;
      path_id: string;
      action_node_id: string;
      entity_id: string;
      role: string;
      direction: string;
      first_seen: string | null;
      last_seen: string | null;
      assertion_origin: string;
      review_state: string;
      confidence: number;
      properties: Record<string, unknown>;
    }>;
    contextEvidence: Array<Record<string, unknown>>;
    projection: {
      id: string;
      path_id: string;
      projection_kind: string;
      root_action_refs: string[];
      mainline_action_refs: string[];
      mainline_dependency_refs: string[];
      branch_groups: Array<Record<string, unknown>>;
      key_context_by_action: Partial<Record<string, string[]>>;
      lane_assignment: Partial<Record<string, Record<string, unknown>>>;
      node_state: Partial<Record<string, string>>;
      selection_reason: string;
      algorithm_version: string;
      generated_at: string;
    } | null;
  }>;
};

export type AttackFlowConfidence = "high" | "medium" | "low";
export type AttackFlowContextType =
  | "malware"
  | "tool"
  | "asset"
  | "vulnerability"
  | "file"
  | "process"
  | "account"
  | "infrastructure"
  | "ip"
  | "domain"
  | "url"
  | "hash"
  | "other";
export type AttackFlowContextRole =
  | "uses"
  | "targets"
  | "communicates-with"
  | "exploits"
  | "downloads-from"
  | "drops-on"
  | "runs-on"
  | "modifies"
  | "creates"
  | "other";
export type AttackFlowRelationType =
  | "precedes"
  | "leads_to"
  | "enables"
  | "causes"
  | "on_success"
  | "on_failure";

export type AttackFlowEvidence = {
  id: string;
  source_span_id: string;
  source_id: string;
  title: string;
  publisher: string;
  canonical_url: string;
  locator: string;
  quote: string;
  confidence: number;
};

export type AttackFlowContext = {
  id: string;
  entity_id: string;
  type: AttackFlowContextType;
  name: string;
  role: AttackFlowContextRole;
  direction: string;
  confidence: AttackFlowConfidence;
  evidence: AttackFlowEvidence[];
};

export type AttackFlow = {
  schema_version: "1.0";
  id: string;
  title: string;
  description: string;
  sources: Array<{
    id: string;
    title: string;
    publisher: string;
    canonical_url: string;
    published_at: string;
  }>;
  reported_actors?: Array<{
    id: string;
    reported_name: string;
    actor_id: string | null;
    confidence: AttackFlowConfidence;
    evidence: AttackFlowEvidence[];
  }>;
  actions: Array<{
    id: string;
    name: string;
    description: string;
    phase: string;
    confidence: AttackFlowConfidence;
    technique_ids: string[];
    contexts: AttackFlowContext[];
    evidence: AttackFlowEvidence[];
  }>;
  relations: Array<{
    id: string;
    source_action_id: string;
    target_action_id: string;
    type: AttackFlowRelationType;
    condition: string | null;
    confidence: AttackFlowConfidence;
    evidence: AttackFlowEvidence[];
  }>;
  mainline: string[];
};

export type ActorKnowledgeSlice = {
  meta: {
    source: string;
    generated_at: string;
    version: string;
  };
  scope: {
    actor_ids: string[];
    entity_ids: string[];
    relationship_ids: string[];
  };
  actors: Actor[];
  entities: Entity[];
  relationships: Relationship[];
  evidence: Evidence[];
  reports: Report[];
  aliases: EntityAlias[];
};

export type RuntimeCatalog = {
  meta: {
    source: string;
    generated_at: string;
    version: string;
  };
  stats: Snapshot["stats"];
  entities: Entity[];
  reports: Report[];
  aliases: EntityAlias[];
  responseRules: ResponseRule[];
  algorithms: AlgorithmConfig[];
};

export type RuntimeEntityIntelligence = {
  entity: Entity;
  entities: Entity[];
  relationships: Relationship[];
  evidence: Evidence[];
  reports: Report[];
  source_artifacts: SourceArtifact[];
  attack_flows: AttackFlow[];
};

export type IntelligenceWorkspace = {
  entities: Entity[];
  relationships: Relationship[];
  evidence: Evidence[];
  reports: Report[];
  aliases: EntityAlias[];
  historicalPaths: Snapshot["historicalPaths"];
  sourceArtifacts: SourceArtifact[];
};

export type PathWorkspace = IntelligenceWorkspace & {
  meta: Snapshot["meta"];
  stats: Snapshot["stats"];
  actors: Actor[];
  responseRules: ResponseRule[];
  algorithms: AlgorithmConfig[];
};

export type ActorKnowledgeSync = {
  status: "idle" | "loading" | "ready" | "offline";
  updatedAt?: string;
  version?: string;
  error?: string;
  refresh: () => void;
};

export type GraphNode = {
  id: string;
  label: string;
  type: string;
  status?: string;
  confidence?: number;
  entity?: Entity;
  virtual?: boolean;
  historicalPathId?: string;
  description?: string;
  properties?: Record<string, unknown>;
};

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  label: string;
  category?: string;
  status?: string;
  confidence?: number;
  relationship?: Relationship;
  historicalPathId?: string;
  aggregate?: boolean;
  evidence?: Evidence[];
  explanation?: {
    nodeIds: string[];
    edgeIds: string[];
  };
};

export type PanoramicGraphNode = {
  id: string;
  kind: "entity" | "actor" | "attack-flow" | "action" | "source" | "evidence";
  label: string;
  type: string;
  description: string;
  confidence: number;
  properties: Record<string, unknown>;
};

export type PanoramicGraphIndexNode = PanoramicGraphNode & {
  relation_count: number;
  evidence_count: number;
};

export type PanoramicGraphIndex = {
  nodes: PanoramicGraphIndexNode[];
  node_count: number;
  atomic_edge_count: number;
  aggregate_edge_count: number;
  knowledge_version: string;
};

export type PanoramicGraphNeighborhood = {
  root_id: string;
  depth: number;
  nodes: PanoramicGraphNode[];
  edges: Array<{
    id: string;
    source_id: string;
    target_id: string;
    type: string;
    label: string;
    confidence: number;
    aggregate: boolean;
    evidence_ids: string[];
    explanation: {
      node_ids: string[];
      edge_ids: string[];
    } | null;
  }>;
  available_expansions: Record<string, number>;
  knowledge_version: string;
};

export type SearchMode = "intel" | "path" | "graph" | "gpt";

export type AppPage =
  | "search"
  | "intel"
  | "actors"
  | "actor"
  | "path-review"
  | "path"
  | "ingest"
  | "fragment-review"
  | "report"
  | "gpt"
  | "graph";

type NodeOrigin = "database" | "log" | "manual" | "gpt";
type NodeReviewStatus = "matched" | "confirmed" | "candidate" | "excluded";

export type ChainStep = {
  id: string;
  entityId?: string;
  label: string;
  type: string;
  relation: string;
  phase: string;
  attackId?: string;
  occurredAt?: string | null;
  confidence: number;
  evidenceCount: number;
  status: string;
  origin: NodeOrigin;
  reviewStatus: NodeReviewStatus;
  branch?: boolean;
  gap?: boolean;
  description?: string;
};

export type ChainLink = {
  id: string;
  source: string;
  target: string;
  label: string;
  confidence: number;
  status: string;
  relationshipId?: string;
};

export type InvestigationCase = {
  id: string;
  title: string;
  summary: string;
  sourceKind: "report" | "query" | "log" | "manual" | "gpt";
  sourceLabel: string;
  actor?: string;
  event?: string;
  createdAt: string;
  updatedAt: string;
  steps: ChainStep[];
  links: ChainLink[];
  notes: string;
  completedAdviceIds: string[];
  version: 1;
};

export type PathCandidateStep = {
  id: string;
  entityId?: string;
  pathNodeId?: string;
  contextEntityIds?: string[];
  label: string;
  description?: string;
  phase: string;
  analysisState:
    | "observed"
    | "reconstructed"
    | "predicted"
    | "reference"
    | "candidate"
    | "blocked";
  confidence: number;
  evidenceCount: number;
  matchKind?: "behavior" | "context" | "attack";
  matchReason?: string;
};

export type PathCandidateLink = {
  id: string;
  sourceStepId: string;
  targetStepId: string;
  label: string;
  reviewStatus: "observed" | "suggested" | "predicted" | "rejected";
  confidence: number;
};

export type PathCandidate = {
  id: string;
  activityId?: string;
  historicalPathId?: string;
  title: string;
  summary: string;
  reason: string;
  gap: string;
  confidence: number;
  sourceCount: number;
  disposition: "primary" | "blocked" | "candidate";
  steps: PathCandidateStep[];
  links?: PathCandidateLink[];
  analysisQuery?: string;
  backendAnalysisId?: string;
  knowledgeSnapshot?: string;
  extractionMethod?: string;
  extractionWarnings?: string[];
};

export type AttackActivityCluster = {
  id: string;
  title: string;
  summary: string;
  scope: string;
  timeRange: string;
  confidence: number;
  sourceCount: number;
  disposition: "confirmed" | "review" | "candidate";
  sharedSteps: PathCandidateStep[];
  candidates: PathCandidate[];
};

type BackendExtractedObservation = {
  value: string;
  kind: string;
  confidence: number;
  source_span_ids: string[];
  quote: string;
};

export type BackendExtractionAudit = {
  method: string;
  model: string | null;
  cache_hit: boolean;
  review_state: string;
  warnings: string[];
  observations: BackendExtractedObservation[];
  prompt_version?: string;
  candidate_count?: number;
  rejected_facts?: Array<{
    fact_type: string;
    reason: string;
    item: unknown;
  }>;
  unassigned_evidence?: Array<{
    quote: string;
    reason: string;
  }>;
  activity_segmentation?: null | {
    prompt_version: string;
    activities: Array<{
      title: string;
      line_ranges: Array<{
        start_line: number;
        end_line: number;
      }>;
    }>;
  };
  mainline_method?: string;
  review_fragments?: Array<{
    candidate_title: string;
    reason: string;
    actions: Array<{
      id: string;
      name: string;
      evidence: Array<{ quote: string }>;
    }>;
    relations: Array<{
      id: string;
      source_action_id: string;
      target_action_id: string;
      type: string;
    }>;
  }>;

};

export type BackendFlowMatchRun = {
  id: string;
  status: "completed";
  algorithm_version: string;
  knowledge_snapshot: string;
  query_text: string;
  normalized_inputs: Array<{
    value: string;
    kind: string;
    normalized_value: string;
  }>;
  candidates: Array<{
    flow_id: string;
    flow_title: string;
    score: number;
    matches: Array<{
      input_index: number;
      input_value: string;
      input_kind: string;
      action_id: string;
      match_kind: "behavior" | "context" | "attack";
      matched_value: string;
      confidence: number;
      explanation: string;
    }>;
    unmatched_inputs: Array<{
      value: string;
      kind: string;
      normalized_value: string;
    }>;
    mainline_frontier_action_id: string | null;
    mainline_frontier_index: number | null;
    action_states: Array<{
      action_id: string;
      state: "input_hit" | "reconstructed" | "predicted" | "reference";
    }>;
  }>;
};

export type BackendFlowMatchAnalysis = BackendFlowMatchRun & {
  flows: AttackFlow[];
};

export type KnowledgeIngestionResult = {
  id: string;
  ingestion_kind?: "attack-flow" | "attack-flow-no-flow" | "entity-evidence";
  source_document_id: string;
  status: "staged" | "published" | "rolled_back" | "rejected";
  publishable: boolean;
  graph_write_performed: boolean;
  extraction_audit: BackendExtractionAudit;
  quality_gates: Array<{
    id: string;
    label: string;
    status: "pass" | "warn" | "block";
    detail: string;
  }>;
  delta: {
    create_entities: number;
    merge_entities: number;
    create_relationships: number;
    reinforce_relationships: number;
  };
  canonical_delta: {
    create_entities: number;
    merge_entities: number;
    mentions: number;
  };
  document_scope: {
    scope:
      | "empty"
      | "ioc-only"
      | "attribution-context-only"
      | "attack-lifecycle-candidate"
      | "no-attack-flow"
      | "entity-evidence"
      | "capability-or-ioc-reference";
    attack_path_eligible: boolean;
    reason: string;
  };
  path_outcome: {
    status: "no-path" | "not-run" | "extracted" | "partial" | "review";
    path_count: number;
    review_path_count?: number;
    entity_evidence_count?: number;
    usable_as?: "paths-and-entities" | "entity-evidence" | "source-only";
    no_path_reason: string | null;
    detail: string;
  };
  entities: Array<{
    stage_id: string;
    value: string;
    kind: string;
    confidence: number;
    decision: "create" | "merge";
    merge_target_id: string | null;
    merge_target_label: string | null;
    source_span_ids: string[];
    quote: string;
  }>;
  canonical_entities: Array<{
    stage_id: string;
    value: string;
    kind: string;
    label: string;
    entity_type: string;
    value_type: string;
    canonical_key: string;
    normalized_value: string;
    entity_id: string;
    confidence: number;
    decision: "create" | "merge";
    merge_target_id: string | null;
    merge_target_label: string | null;
    duplicate_candidate_ids: string[];
    source_span_ids: string[];
    quotes: string[];
    original_values: string[];
  }>;
  relations: Array<{
    stage_id: string;
    source_stage_id: string;
    target_stage_id: string;
    relationship_id: string;
    relation_type: string;
    decision: "reinforce";
    confidence: number;
    source_span_ids: string[];
    locator: string;
    excerpt: string;
  }>;
  path_delta?: null | {
    events: number;
    relations: number;
    branch_groups: number;
    merge_groups: number;
    core_events: number;
    spine_events: number;
    branch_events: number;
    detail_events: number;
    context_events: number;
  };
  event_graph_extraction?: null | {
    events: Array<{
      id: string;
      label: string;
      tactic?: string;
      tactic_label?: string;
      confidence?: number;
      mainline_role?: "backbone" | "branch" | "detail" | "context";
      detail_parent_id?: string | null;
      model_role_suggestion?: null | {
        role: "milestone" | "detail" | "context";
        confidence: number;
        rationale: string;
      };
      source_line_ids?: number[];
    }>;
    relations: Array<{
      id?: string;
      source_event_id: string;
      target_event_id: string;
      relation_type: string;
      confidence?: number;
    }>;
    mainline: {
      definition: string;
      flow_scope: string;
      projection_goal?: {
        id: "incident-response" | "soc-triage";
        label: string;
        description: string;
      };
      layer_contract?: {
        evidence_graph: string;
        core_process: string;
        presentation_spine: string;
        model_role_is_advisory: boolean;
      };
      review_queue?: Array<{
        activity_id: string;
        edge_id: string;
        source_event_id: string;
        target_event_id: string;
        reason: string;
      }>;
      stats: {
        activities: number;
        usable_paths?: number;
        review_paths?: number;
        supplemental_components?: number;
        core_events: number;
        spine_events: number;
        branch_events: number;
        detail_events: number;
        context_events: number;
      };
      activities: Array<{
        id: string;
        title: string;
        flow_scope: string;
        core_event_ids: string[];
        spine_event_ids: string[];
        branch_event_ids: string[];
        detail_event_ids: string[];
        context_event_ids: string[];
        start_event_ids: string[];
        terminal_event_ids: string[];
        path_units?: Array<{
          id: string;
          kind:
            | "observed-path"
            | "path-fragment"
            | "supplemental-information";
          publication_status: "usable" | "review" | "supplemental";
          event_ids: string[];
          spine_event_ids: string[];
          branch_event_ids: string[];
          start_event_ids: string[];
          terminal_event_ids: string[];
          edges: Array<{
            id: string;
            source_event_id: string;
            target_event_id: string;
            precondition_status?: "supported" | "needs-review" | "not-declared";
          }>;
          warnings: string[];
        }>;
        branch_groups: Array<{
          id: string;
          root_event_id: string;
          arm_event_ids: string[];
          logic: "condition" | "or" | "parallel-or-unknown";
        }>;
        detail_groups: Array<{
          parent_event_id: string;
          event_ids: string[];
        }>;
        warnings: string[];
      }>;
    };
    evidence_graph_policy?: {
      scope: string;
      preserves: string[];
      excludes_as_standalone_steps: string[];
      model_role_is_advisory: boolean;
      backend_projection_is_authoritative: boolean;
    };
  };
  attack_flow_candidate?: {
    title: string;
    description: string;
    actions: Array<{
      id: string;
      name: string;
      description: string;
      phase: string;
      confidence: AttackFlowConfidence;
      technique_ids: string[];
      contexts: Array<{
        id: string;
        type: AttackFlowContextType;
        name: string;
        role: AttackFlowContextRole;
        confidence: AttackFlowConfidence;
        evidence: Array<{ quote: string }>;
      }>;
      evidence: Array<{ quote: string }>;
    }>;
    relations: Array<{
      id: string;
      source_action_id: string;
      target_action_id: string;
      type: string;
      condition: string | null;
      confidence: AttackFlowConfidence;
      evidence: Array<{ quote: string }>;
    }>;
    mainline: string[];
    reported_actors: Array<{
      id: string;
      reported_name: string;
      confidence: AttackFlowConfidence;
      evidence: Array<{ quote: string }>;
    }>;
  };
  attack_flow_preview?: {
    flow_id: string;
    title: string;
    description: string;
    mainline: string[];
    actions: Array<{
      id: string;
      local_id: string;
      name: string;
      phase: string;
      contexts: Array<{
        id: string;
        name: string;
        role: AttackFlowContextRole;
        resolution: {
          status: "create" | "reuse" | "review";
          canonical_key: string | null;
        };
      }>;
    }>;
    relations: Array<{
      id: string;
      source_action_id: string;
      target_action_id: string;
      type: string;
    }>;
    reported_actors: Array<{
      id: string;
      reported_name: string;
      actor_id: string | null;
    }>;
  };
  publish_mode?: "create" | "merge";
  merge_review?: null | {
    target_flow_id: string;
    confirmed: boolean;
    action_map: Record<string, string>;
  };
  flow_candidate_summary?: {
    status: "no-flow" | "single" | "multiple";
    candidate_count: number;
    recommendation: "no-flow" | "create" | "merge" | "review";
    merge_target_flow_id: string | null;
    suggested_action_map?: Record<string, string>;
    reason: string;
  };
  version: null | {
    id: string;
    status: "published" | "rolled_back";
    changes: {
      reinforced_entities: number;
      created_evidence: number;
      removed_evidence?: number;
      created_canonical_entities?: number;
      reinforced_canonical_entities?: number;
      created_entity_mentions?: number;
      removed_entity_mentions?: number;
      created_attack_flow_id?: string;
      created_context_entity_ids?: string[];
      removed_attack_flow_id?: string;
      supported_attack_flow_id?: string;
      flow_source_support_id?: string;
      support_already_present?: boolean;
    };
    published_at: string;
    rolled_back_at?: string;
  };
};

export type KnowledgeIngestionBatchResult = {
  ingestion_kind: "attack-flow-batch";
  source_document_id: string;
  status: "staged";
  extraction_audit?: BackendExtractionAudit;
  flow_candidate_summary: {
    status: "single" | "multiple";
    candidate_count: number;
    recommendation: "review";
    merge_target_flow_id: null;
    reason: string;
  };
  candidates: KnowledgeIngestionResult[];
};

type SearchHit = {
  entity: Entity;
  score: number;
};

export type SearchResult = {
  queryType: string;
  entities: SearchHit[];
  reports: Array<{ report: Report; score: number }>;
};

export type SourceCitation = {
  id: string;
  reportId: string;
  title: string;
  publisher: string;
  reportDate: string;
  sourceRef: string;
  excerpt: string;
  location: string;
  confidence: number;
  externalUrl: string;
};

export type AdviceItem = {
  id: string;
  group: "立即遏制" | "排查狩猎" | "清除恢复" | "长期加固";
  priority: string;
  title: string;
  recommendation: string;
  condition: string;
  rationale: string;
  sourceUrl?: string;
  stepIds: string[];
};

type GptCitation = {
  id: string;
  label: string;
  reportId?: string;
  url?: string;
};

type GptSuggestedNode = {
  id: string;
  label: string;
  type: string;
  relation: string;
  confidence: number;
};

export type GptResponse = {
  answer: string;
  citations: GptCitation[];
  suggested_nodes: GptSuggestedNode[];
  model: string;
};
