/**
 * Rule runner.
 *
 * Severity is decided here, by deterministic rules, and nowhere else. An
 * optional LLM pass may later add explanation to a finding, but it may not
 * create one or raise its severity — small local models are confidently wrong
 * often enough that letting them set severity would make the report untrustworthy.
 */

import { SEVERITY_ORDER, type Finding, type ScanResult } from "../types.js";
import { configRules } from "./config.js";
import { crossRules } from "./cross.js";
import { resourceRules } from "./resources.js";
import { toolRules } from "./tools.js";

export function runRules(result: ScanResult): Finding[] {
  const findings: Finding[] = [];

  // A config we could not read is a gap in the audit, not a detail to log and
  // move past. Reporting "0 servers" while quietly failing to parse a file is
  // the precise failure this tool exists to argue against.
  for (const err of result.discovery.errors) {
    findings.push({
      rule: "unreadable-config",
      severity: "high",
      title: "A config file exists but could not be parsed",
      detail:
        `${err.path} could not be read, so any servers declared in it were not audited. ` +
        "Treat this report as incomplete until the file parses.",
      evidence: err.message,
      remediation: "Fix the JSON syntax, then re-run.",
    });
  }

  // Config-level rules apply to every declared server, scanned or not — this
  // is what still works in --static mode where nothing is executed.
  for (const declared of result.discovery.servers) {
    findings.push(...configRules(declared));
  }

  for (const scan of result.servers) {
    if (scan.status !== "ok") continue;
    findings.push(...toolRules(scan));
    findings.push(...resourceRules(scan));
  }

  findings.push(...crossRules(result.servers));

  return findings.sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (bySeverity !== 0) return bySeverity;
    return (a.server ?? "").localeCompare(b.server ?? "");
  });
}

export function countBySeverity(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}
