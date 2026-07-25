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
  };
  entities: Entity[];
  relationships: Relationship[];
  evidence: Evidence[];
  reports: Report[];
  aliases: Array<{
    id: string;
    entity_id: string;
    alias: string;
    alias_type: string;
    source: string;
    confidence: number;
  }>;
  actors: Actor[];
  responseRules: ResponseRule[];
  algorithms: Array<{
    id: string;
    algorithm_version: string;
    description: string;
    created_at: string;
    weights: Record<string, number>;
  }>;
};

export type GraphNode = {
  id: string;
  label: string;
  type: string;
  status?: string;
  confidence?: number;
  entity?: Entity;
  virtual?: boolean;
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
};

export type SearchMode = "intel" | "chain" | "graph" | "gpt";

export type AppPage =
  | "search"
  | "intel"
  | "chain-intake"
  | "chain"
  | "cases"
  | "reports"
  | "gpt"
  | "actors"
  | "graph";

export type NodeOrigin = "database" | "log" | "manual" | "gpt";
export type NodeReviewStatus = "matched" | "confirmed" | "candidate" | "excluded";

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

export type SearchHit = {
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

export type HistoricalFinding = {
  id: string;
  phase: string;
  title: string;
  summary: string;
  tone: "consensus" | "difference" | "timeline";
  citationIds: string[];
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

export type GptCitation = {
  id: string;
  label: string;
  reportId?: string;
  url?: string;
};

export type GptSuggestedNode = {
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
