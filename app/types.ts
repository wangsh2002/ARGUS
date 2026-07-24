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
