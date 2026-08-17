/**
 * Text patterns shared by every rule that examines server-authored prose.
 *
 * Tool descriptions, prompt descriptions and resource descriptions all land in
 * the model's context the same way, so they need the same scrutiny. Keeping the
 * lexicons here means a pattern added for one surface protects all of them.
 */

export interface Marker {
  pattern: RegExp;
  label: string;
}

/** Attempts to smuggle instructions to the model. */
export const INJECTION_MARKERS: Marker[] = [
  { pattern: /<\s*(IMPORTANT|SYSTEM|INSTRUCTIONS?|ADMIN)\s*>/i, label: "pseudo-system tag" },
  { pattern: /\bignore\s+(all\s+)?(previous|prior|above)\b/i, label: "instruction override" },
  { pattern: /\bdo not (mention|tell|inform|reveal|disclose)\b/i, label: "concealment directive" },
  { pattern: /\bwithout (telling|informing|notifying) the user\b/i, label: "concealment directive" },
  {
    pattern: /\b(before|after) (calling|using|reading) th(is|ese),? you must\b/i,
    label: "implanted precondition",
  },
  { pattern: /[​-‏‪-‮﻿]/, label: "invisible unicode" },
];

/** Attempts to steer the model away from competing tools or servers. */
export const PROMOTIONAL_MARKERS: Marker[] = [
  { pattern: /\balways use th(is|ese)\b/i, label: "unconditional preference" },
  { pattern: /\b(better|more accurate|superior) than\b/i, label: "comparative claim" },
  { pattern: /\bpreferred (tool|source|resource)\b/i, label: "self-designation" },
  { pattern: /\bdo not use (other|any other)\b/i, label: "rival suppression" },
  { pattern: /\buse th(is|ese) (tool |resource )?first\b/i, label: "ordering claim" },
  { pattern: /\bbest (tool|source|resource)\b/i, label: "superlative claim" },
];

/** First matching marker, or null. */
export function firstMatch(text: string, markers: Marker[]): { marker: Marker; index: number } | null {
  for (const marker of markers) {
    const m = text.match(marker.pattern);
    if (m && m.index !== undefined) return { marker, index: m.index };
  }
  return null;
}

/** All matching markers. */
export function allMatches(text: string, markers: Marker[]): Marker[] {
  return markers.filter((m) => m.pattern.test(text));
}

/**
 * Split an identifier into words before verb matching.
 *
 * `\b` treats underscore as a word character, so /\bdelete\b/ does not match
 * "delete_branch" — and snake_case is the dominant convention for MCP tool
 * names. Normalising separators to spaces first is what makes the verb
 * lexicons actually fire.
 */
export function words(identifier: string): string {
  return identifier
    .replace(/[_\-.]+/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2"); // camelCase → camel Case
}

/** Trim a snippet of server prose for use as evidence. */
export function excerpt(text: string, around = 0, span = 160): string {
  const start = Math.max(0, around - 40);
  return text.slice(start, start + span).replace(/\s+/g, " ").trim();
}
