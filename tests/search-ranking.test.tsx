import { describe, expect, it } from "vitest";
import { exactReportMatch, searchSnapshot } from "../app/argus-domain";
import type { Entity, Report } from "../app/types";


const actor: Entity = {
  id: "ACTOR-THREAT",
  entity_type: "攻击组织",
  canonical_key: "actor:threat-actors",
  label: "Threat Actors",
  normalized_value: "threat actors",
  description: "Generic actor mention",
  first_seen: null,
  last_seen: null,
  source_count: 1,
  properties: {},
};

const report: Report = {
  id: "REPORT-SECURITY-BRIEF",
  title:
    "Security Brief: Threat Actors Pair Tax-Themed Lures With COVID-19, Healthcare Themes",
  source: "Proofpoint",
  report_date: "2021-04-15",
  classification: "public",
  language: "en",
  original_filename: null,
  mime_type: "text/plain",
  size_bytes: 1,
  sha256: "a".repeat(64),
  extracted_text: "Threat actors used tax-themed lures.",
  extraction_note: "",
  created_at: "2021-04-15",
  source_ref: "SRC-REPORT",
  reliability: "A",
  external_url: "https://example.test/report",
  assessment: "Tax-themed lure campaign.",
};

describe("search result ranking", () => {
  it("ranks an exact report title above partial entity token matches", () => {
    const result = searchSnapshot(
      { entities: [actor], aliases: [], reports: [report] },
      report.title,
    );

    expect(result.reports[0]?.score).toBe(100);
    expect(result.reports[0]?.score).toBeGreaterThanOrEqual(
      result.entities[0]?.score ?? 0,
    );
    expect(exactReportMatch([report], report.title)).toEqual(report);
  });
});
