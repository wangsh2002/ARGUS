import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const database = resolve(root, "data/argus_cti.db");
const output = resolve(root, "lib/argus-data.json");

function query(sql) {
  const raw = execFileSync("sqlite3", ["-json", database, sql], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  }).trim();
  return raw ? JSON.parse(raw) : [];
}

function parseJson(value, fallback) {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

const entities = query(`
  SELECT id, entity_type, canonical_key, label, normalized_value, description,
         first_seen, last_seen, source_count, properties_json
  FROM entities ORDER BY entity_type, label
`).map(({ properties_json, ...entity }) => ({
  ...entity,
  properties: parseJson(properties_json, {}),
}));

const relationships = query(`
  SELECT id, source_entity_id, target_entity_id, relation_type, confidence,
         evidence_count, first_seen, last_seen, category, status, properties_json
  FROM relationships ORDER BY category, source_entity_id, target_entity_id
`).map(({ properties_json, ...relationship }) => ({
  ...relationship,
  properties: parseJson(properties_json, {}),
}));

const evidence = query(`
  SELECT ev.id, ev.relationship_id, ev.report_id, ev.source_ref, ev.location,
         ev.excerpt, ev.confidence, rr.title AS report_title,
         rr.source AS publisher, rr.report_date
  FROM evidence ev
  JOIN raw_reports rr ON rr.id = ev.report_id
  ORDER BY rr.report_date DESC, ev.id
`);

const reports = query(`
  SELECT id, title, source, report_date, classification, language,
         original_filename, mime_type, size_bytes, sha256, extracted_text,
         extraction_note, created_at, source_ref, reliability, external_url,
         assessment
  FROM raw_reports ORDER BY report_date DESC, created_at DESC
`);

const aliases = query(`
  SELECT id, entity_id, alias, alias_type, source, confidence
  FROM aliases ORDER BY entity_id, confidence DESC
`);

const actors = query(`
  SELECT e.id, e.label, e.description, e.source_count, e.properties_json,
         ap.profile_status, ap.origin_label, ap.active_from, ap.active_to,
         ap.public_attribution, ap.motivations_json, ap.target_sectors_json,
         ap.source_refs_json, ap.source_urls_json, ap.source_grade, ap.updated_at
  FROM entities e
  JOIN actor_profiles ap ON ap.actor_id = e.id
  WHERE e.entity_type = '攻击组织'
  ORDER BY e.label
`).map((actor) => ({
  id: actor.id,
  label: actor.label,
  description: actor.description,
  source_count: actor.source_count,
  properties: parseJson(actor.properties_json, {}),
  profile_status: actor.profile_status,
  origin_label: actor.origin_label,
  active_from: actor.active_from,
  active_to: actor.active_to,
  public_attribution: actor.public_attribution,
  motivations: parseJson(actor.motivations_json, []),
  target_sectors: parseJson(actor.target_sectors_json, []),
  source_refs: parseJson(actor.source_refs_json, []),
  source_urls: parseJson(actor.source_urls_json, []),
  source_grade: actor.source_grade,
  updated_at: actor.updated_at,
}));

const responseRules = query(`
  SELECT id, match_entity_type, priority, action_template, rationale, source_url
  FROM response_rules ORDER BY priority, id
`);

const algorithms = query(`
  SELECT id, algorithm_version, weights_json, description, created_at
  FROM algorithm_configs ORDER BY created_at DESC
`).map(({ weights_json, ...algorithm }) => ({
  ...algorithm,
  weights: parseJson(weights_json, {}),
}));

const stats = {
  entities: entities.length,
  relationships: relationships.length,
  evidence: evidence.length,
  reports: reports.length,
  actors: actors.length,
  iocs: entities.filter((item) => item.entity_type === "IOC/基础设施").length,
  attack_steps: entities.filter((item) => item.entity_type === "攻击步骤").length,
};

const snapshot = {
  meta: {
    source: "data/argus_cti.db",
    generated_at: new Date().toISOString(),
    is_demo: false,
  },
  stats,
  entities,
  relationships,
  evidence,
  reports,
  aliases,
  actors,
  responseRules,
  algorithms,
};

mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, `${JSON.stringify(snapshot)}\n`, "utf8");
console.log(
  `Synced ${stats.entities} entities, ${stats.relationships} relationships, ${stats.reports} reports.`,
);
