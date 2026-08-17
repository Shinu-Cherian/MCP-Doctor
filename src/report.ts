/**
 * Rendering. Terminal output for humans, Markdown for sharing, JSON for tools.
 */

import { countBySeverity } from "./rules/index.js";
import type { CostReport } from "./cost.js";
import type { Finding, ScanResult, Severity } from "./types.js";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";

const SEVERITY_COLOUR: Record<Severity, string> = {
  critical: "\x1b[41m\x1b[97m", // white on red
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[2m",
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: " CRITICAL ",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const word of words) {
    if (line.length + word.length + 1 > width) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(line);
  return lines.map((l) => indent + l).join("\n");
}

function location(f: Finding): string {
  if (f.servers && f.servers.length > 1) return f.servers.join(" + ");
  if (f.server && f.tool) return `${f.server}.${f.tool}`;
  if (f.server) return f.server;
  if (f.servers?.length) return f.servers[0];
  return "";
}

export function renderTerminal(
  result: ScanResult,
  findings: Finding[],
  cost: CostReport,
): string {
  const out: string[] = [];
  const counts = countBySeverity(findings);

  out.push("");
  out.push(`${BOLD}mcp-doctor${RESET} ${DIM}· audit · ${result.scannedAt}${RESET}`);
  out.push("");

  /* Summary ---------------------------------------------------------- */
  const scanned = result.servers.filter((s) => s.status === "ok");
  const skipped = result.servers.filter((s) => s.status !== "ok");
  const toolTotal = scanned.reduce((n, s) => n + s.tools.length, 0);

  out.push(
    `  ${result.discovery.servers.length} declared · ${scanned.length} scanned · ` +
      `${toolTotal} tools · ${findings.length} findings`,
  );

  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const badges = order
    .filter((s) => counts[s])
    .map((s) => `${SEVERITY_COLOUR[s]}${SEVERITY_LABEL[s].trim()} ${counts[s]}${RESET}`);
  if (badges.length > 0) out.push(`  ${badges.join("  ")}`);
  out.push("");

  /* Findings --------------------------------------------------------- */
  if (findings.length === 0) {
    out.push(`  ${DIM}No findings.${RESET}`);
  }

  for (const f of findings) {
    const tag = `${SEVERITY_COLOUR[f.severity]} ${SEVERITY_LABEL[f.severity].trim()} ${RESET}`;
    out.push(`${tag} ${BOLD}${f.title}${RESET}`);
    const where = location(f);
    if (where) out.push(`${DIM}         ${where} · ${f.rule}${RESET}`);
    out.push(wrap(f.detail, 78, "         "));
    if (f.evidence) out.push(`${DIM}         evidence: ${f.evidence.replace(/\s+/g, " ")}${RESET}`);
    if (f.remediation) out.push(`${DIM}         fix: ${f.remediation}${RESET}`);
    out.push("");
  }

  /* Skipped ---------------------------------------------------------- */
  if (skipped.length > 0) {
    out.push(`${BOLD}Not scanned${RESET}`);
    for (const s of skipped) out.push(`  ${s.name} ${DIM}— ${s.note ?? s.status}${RESET}`);
    out.push("");
  }

  /* Cost ------------------------------------------------------------- */
  if (cost.perServer.length > 0) {
    out.push(`${BOLD}Context cost${RESET} ${DIM}(estimated)${RESET}`);
    for (const c of cost.perServer) {
      const heaviest = c.heaviestTool
        ? ` ${DIM}heaviest: ${c.heaviestTool.name} (${c.heaviestTool.tokens})${RESET}`
        : "";
      out.push(
        `  ${String(c.estimatedTokens).padStart(6)} tok  ${c.server} ${DIM}(${c.toolCount} tools)${RESET}${heaviest}`,
      );
    }
    out.push(`  ${BOLD}${String(cost.totalTokens).padStart(6)} tok  total${RESET}`);
    out.push(wrap(cost.note, 78, "  "));
    out.push("");
  }

  return out.join("\n");
}

export function renderMarkdown(
  result: ScanResult,
  findings: Finding[],
  cost: CostReport,
): string {
  const counts = countBySeverity(findings);
  const out: string[] = [];

  out.push("# MCP audit report");
  out.push("");
  out.push(`Generated ${result.scannedAt}`);
  out.push("");

  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  out.push("| Severity | Count |");
  out.push("| --- | --- |");
  for (const s of order) if (counts[s]) out.push(`| ${s} | ${counts[s]} |`);
  out.push("");

  out.push("## Findings");
  out.push("");
  if (findings.length === 0) out.push("None.");

  for (const f of findings) {
    out.push(`### ${f.title}`);
    out.push("");
    out.push(`**${f.severity.toUpperCase()}** · \`${f.rule}\`${location(f) ? ` · ${location(f)}` : ""}`);
    out.push("");
    out.push(f.detail);
    if (f.evidence) {
      out.push("");
      out.push("```");
      out.push(f.evidence);
      out.push("```");
    }
    if (f.remediation) {
      out.push("");
      out.push(`**Fix:** ${f.remediation}`);
    }
    out.push("");
  }

  out.push("## Context cost");
  out.push("");
  out.push("| Server | Tools | Est. tokens |");
  out.push("| --- | ---: | ---: |");
  for (const c of cost.perServer) {
    out.push(`| ${c.server} | ${c.toolCount} | ${c.estimatedTokens} |`);
  }
  out.push(`| **Total** | | **${cost.totalTokens}** |`);
  out.push("");
  out.push(cost.note);
  out.push("");

  return out.join("\n");
}
