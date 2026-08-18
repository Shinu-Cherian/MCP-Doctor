/**
 * Rules comparing what is running against what was written down.
 *
 * Every other scanner reads configuration and stops there. Configuration is a
 * record of intent, and intent and reality drift apart: servers arrive as
 * extensions, connectors or bundled features that never touch `mcpServers`.
 * A report that says "0 servers, no risks" on a machine running three of them
 * is not merely incomplete, it is actively misleading — it answers the
 * question the user asked with a confident wrong answer.
 */

import type { Finding, ScanResult } from "../types.js";

export function liveRules(result: ScanResult): Finding[] {
  const live = result.live;
  if (!live) return [];

  const findings: Finding[] = [];

  /* The check could not run at all. Say so rather than implying a clean result. */
  if (!live.supported) {
    findings.push({
      rule: "live-check-unavailable",
      severity: "low",
      title: "Could not check what is actually running",
      detail:
        "Only configuration was examined, so a server started outside a config file " +
        "would not appear in this report. Treat the result as covering declared " +
        "servers only.",
      evidence: live.note,
      remediation: "Re-run with permission to read the process table.",
    });
    return findings;
  }


  const undeclared = live.servers.filter((s) => !s.declaredAs);

  for (const server of undeclared) {
    findings.push({
      rule: "undeclared-server",
      severity: "high",
      title: `An MCP server is running that no config file declares (pid ${server.pid})`,
      detail:
        (server.client
          ? `${server.client} started this process, `
          : "This process is running, ") +
        "but nothing in the config files this tool can read accounts for it. It may " +
        "be an extension, a connector, or a bundled feature — all of which grant the " +
        "assistant tools without appearing anywhere you would normally look. Its " +
        "tools were not analysed, because there is no configuration describing how " +
        "to reach it.",
      evidence: server.command.slice(0, 200),
      remediation:
        "Identify what installed it. If you did not add it deliberately, remove it.",
    });
  }

  /*
   * The reassuring case is worth stating explicitly. "Nothing hidden" is a
   * result the user came for, and silence does not deliver it.
   */
  if (undeclared.length === 0 && result.discovery.servers.length > 0) {
    findings.push({
      rule: "live-matches-declared",
      severity: "info",
      title: "Everything running matches what the config files declare",
      detail:
        `${live.examined} processes were examined and every MCP server among them ` +
        "corresponds to a declared entry. Nothing is running that you did not write down.",
    });
  }

  return findings;
}

/**
 * Servers recovered from client logs.
 *
 * Separate from the process-table rules on purpose: a log is readable even
 * when the process table is not, so this must not sit behind that check.
 */
export function logRules(result: ScanResult): Finding[] {
  const findings: Finding[] = [];
  /*
   * Servers the client has run that no config file mentions.
   *
   * These are the ones every config-reading scanner misses: an extension runs
   * inside the client's own process, so it never lands in `mcpServers` and
   * never becomes a child process to enumerate. The only trace is the log the
   * client kept while talking to it.
   */
  const logs = result.logs;
  if (logs && logs.undeclared.length > 0) {
  for (const name of logs.undeclared) {
    const scan = result.servers.find((s) => s.name === name && s.discoveredVia === "log");
    const identity = scan?.serverInfo ? scan.serverInfo.name + " v" + scan.serverInfo.version : undefined;

    findings.push({
      rule: "undeclared-in-logs",
      severity: "high",
      title: 'An MCP server has been used that no config file declares: "' + name + '"',
      detail:
        "The client kept a log of a session with this server, so it is installed and " +
        "has run, yet nothing in the config files this tool can read accounts for it. " +
        "That is what an extension or connector looks like: it grants the assistant " +
        "tools without appearing anywhere you would normally look for them.",
      evidence: identity ? identity + " — " + scan?.declared.source.path : scan?.declared.source.path,
      remediation:
        "Check the client's extensions or connectors list. If you did not add it deliberately, remove it.",
      server: name,
    });
  }
  }


  return findings;
}
