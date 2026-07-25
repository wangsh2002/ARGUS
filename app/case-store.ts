"use client";

import type { InvestigationCase } from "./types";

const STORAGE_KEY = "argus:investigation-cases:v1";

function isCase(value: unknown): value is InvestigationCase {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<InvestigationCase>;
  return (
    candidate.version === 1 &&
    typeof candidate.id === "string" &&
    typeof candidate.title === "string" &&
    Array.isArray(candidate.steps) &&
    Array.isArray(candidate.links)
  );
}

export function loadCases(): InvestigationCase[] {
  if (typeof window === "undefined") return [];
  try {
    const parsed = JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "[]");
    return Array.isArray(parsed)
      ? parsed.filter(isCase).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
      : [];
  } catch {
    return [];
  }
}

export function saveCases(cases: InvestigationCase[]) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(cases));
}

export function upsertCase(
  cases: InvestigationCase[],
  investigation: InvestigationCase,
) {
  const next = {
    ...investigation,
    updatedAt: new Date().toISOString(),
  };
  return [
    next,
    ...cases.filter((item) => item.id !== investigation.id),
  ].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

export function removeCase(cases: InvestigationCase[], caseId: string) {
  return cases.filter((item) => item.id !== caseId);
}
