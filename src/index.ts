#!/usr/bin/env node
/**
 * mcp-doctor CLI.
 *
 * Stage 1 ships a single command, `discover`: find every MCP server declared
 * in config files on this machine and print what was found — including which
 * paths were checked and came up empty.
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { computeCost } from "./cost.js";
import { discover } from "./discover.js";
import {
  LOCKFILE_NAME,
  buildLockfile,
  diffAgainstLock,
  readLockfile,
  writeLockfile,
} from "./lockfile.js";
import { renderMarkdown, renderTerminal } from "./report.js";
import { runRules } from "./rules/index.js";
import { scanAll } from "./scan.js";
import { SEVERITY_ORDER } from "./types.js";
import type { DeclaredServer, DiscoveryResult, ScanResult } from "./types.js";

const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";
const YELLOW = "\x1b[33m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";

function describeTarget(s: DeclaredServer): string {
  if (s.transport === "stdio") {
    return [s.command, ...(s.args ?? [])].filter(Boolean).join(" ");
  }
  if (s.transport === "http") return s.url ?? "(no url)";
  return "(unknown)";
}

function printHuman(result: DiscoveryResult): void {
  console.log(`\n${BOLD}mcp-doctor${RESET} ${DIM}· discover${RESET}`);
  console.log(`${DIM}${result.platform} · ${result.scannedAt}${RESET}\n`);

  console.log(`${BOLD}Config locations checked${RESET}`);
  const foundPaths = new Set(result.sources.map((s) => s.path));
  for (const path of result.checkedPaths) {
    const mark = foundPaths.has(path) ? `${GREEN}found${RESET}` : `${DIM}missing${RESET}`;
    console.log(`  ${mark}  ${DIM}${path}${RESET}`);
  }

  if (result.errors.length > 0) {
    console.log(`\n${YELLOW}Unreadable files${RESET}`);
    for (const e of result.errors) {
      console.log(`  ${e.path}\n    ${DIM}${e.message}${RESET}`);
    }
  }

  console.log(`\n${BOLD}Declared servers${RESET}`);
  if (result.servers.length === 0) {
    console.log(`  ${YELLOW}none${RESET}`);
    console.log(
      `  ${DIM}Config files declare no MCP servers. That is not the same as${RESET}`,
    );
    console.log(
      `  ${DIM}"this machine runs none" — connectors, plugins and built-in${RESET}`,
    );
    console.log(
      `  ${DIM}extensions register outside these files. Stage 4 checks that.${RESET}`,
    );
  } else {
    for (const s of result.servers) {
      console.log(`\n  ${BOLD}${s.name}${RESET}  ${DIM}[${s.transport}]${RESET}`);
      console.log(`    target : ${describeTarget(s)}`);
      if (s.envKeys.length > 0) {
        console.log(`    secrets: ${s.envKeys.join(", ")} ${DIM}(names only)${RESET}`);
      }
      console.log(`    from   : ${DIM}${s.source.path}${RESET}`);
    }
  }

  console.log(
    `\n${DIM}${result.servers.length} declared server(s) across ${result.sources.length} file(s).${RESET}\n`,
  );
}

function printScan(result: ScanResult): void {
  console.log(`\n${BOLD}mcp-doctor${RESET} ${DIM}· scan${RESET}`);
  console.log(`${DIM}${result.scannedAt}${RESET}\n`);

  // Never let an unreadable config pass unmentioned; a silent zero is worse
  // than an error.
  for (const err of result.discovery.errors) {
    console.log(`${YELLOW}unreadable${RESET} ${err.path}\n  ${DIM}${err.message}${RESET}\n`);
  }

  for (const s of result.servers) {
    const badge =
      s.status === "ok"
        ? `${GREEN}ok${RESET}`
        : s.status === "failed"
          ? `${RED}failed${RESET}`
          : `${YELLOW}skipped${RESET}`;

    console.log(`${BOLD}${s.name}${RESET}  ${badge}  ${DIM}[${s.declared.transport}]${RESET}`);

    if (s.status !== "ok") {
      console.log(`  ${DIM}${s.note ?? ""}${RESET}\n`);
      continue;
    }

    if (s.serverInfo) {
      console.log(`  identity : ${s.serverInfo.name} v${s.serverInfo.version}`);
    }
    const caps = s.capabilities;
    if (caps) {
      const on = Object.entries(caps)
        .filter(([, v]) => v)
        .map(([k]) => k);
      console.log(`  declares : ${on.join(", ") || "nothing"}`);
    }
    console.log(
      `  surface  : ${s.tools.length} tools, ${s.resources.length} resources, ${s.prompts.length} prompts` +
        `  ${DIM}(${s.durationMs}ms)${RESET}`,
    );

    for (const t of s.tools) {
      const a = t.annotations ?? {};
      const hints = [
        a.readOnlyHint ? "readOnly" : null,
        a.destructiveHint ? "destructive" : null,
        a.openWorldHint ? "openWorld" : null,
      ].filter(Boolean);
      const hintText = hints.length > 0 ? ` ${DIM}{${hints.join(" ")}}${RESET}` : "";
      console.log(`    · ${t.name}${hintText}`);
    }
    for (const p of s.prompts) {
      console.log(`    ${DIM}/${p.name}${RESET}`);
    }
    console.log();
  }

  const ok = result.servers.filter((s) => s.status === "ok");
  const toolTotal = ok.reduce((n, s) => n + s.tools.length, 0);
  console.log(
    `${DIM}${ok.length}/${result.servers.length} server(s) scanned · ${toolTotal} tools total.${RESET}\n`,
  );
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const command = argv[0] ?? "discover";
  const flags = argv.filter((a) => a.startsWith("--"));
  const asJson = flags.includes("--json");

  // Positional args are directories, except the value belonging to --markdown.
  const mdValueIndex = argv.indexOf("--markdown") + 1;
  const dirs = argv
    .slice(1)
    .filter((a, i) => !a.startsWith("--") && i + 1 !== mdValueIndex);

  // Serving speaks MCP on stdout, so it must not share it with a report.
  if (command === "serve") {
    const { startServer } = await import("./server.js");
    await startServer();
    return;
  }

  if (command !== "discover" && command !== "scan" && command !== "audit") {
    console.error(
      `unknown command: ${command}\n` +
        `usage:\n` +
        `  mcp-doctor discover [--json] [dir...]\n` +
        `  mcp-doctor scan    [--json] [--spawn] [--network] [--forward-env] [dir...]\n` +
        `  mcp-doctor audit   [--json] [--markdown FILE] [--spawn] [--network] [dir...]\n` +
        `  mcp-doctor serve   run as an MCP server over stdio`,
    );
    process.exit(1);
  }

  // With no directories given, look at the current project too.
  const discovery = discover(dirs.length > 0 ? dirs : [process.cwd()]);

  if (command === "discover") {
    if (asJson) console.log(JSON.stringify(discovery, null, 2));
    else printHuman(discovery);
    return;
  }

  const result = await scanAll(discovery, {
    checkLive: !flags.includes("--no-live"),
    allowSpawn: flags.includes("--spawn"),
    allowNetwork: flags.includes("--network"),
    forwardEnv: flags.includes("--forward-env"),
  });

  if (command === "scan") {
    if (asJson) console.log(JSON.stringify(result, null, 2));
    else printScan(result);
    return;
  }

  // audit = scan + rules + cost + drift
  const findings = runRules(result);
  const cost = computeCost(result);

  // Compare against the last approved snapshot, if there is one.
  const lockPath = join(process.cwd(), LOCKFILE_NAME);
  const previous = readLockfile(lockPath);
  if (previous) {
    findings.push(...diffAgainstLock(previous, result));
    findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  }

  if (flags.includes("--lock")) {
    writeLockfile(lockPath, buildLockfile(result));
    console.error(`lockfile written to ${lockPath}`);
  } else if (!previous) {
    console.error(`no ${LOCKFILE_NAME} found — run with --lock to record this state`);
  }

  const mdIndex = argv.indexOf("--markdown");
  if (mdIndex !== -1 && argv[mdIndex + 1]) {
    const path = argv[mdIndex + 1];
    writeFileSync(path, renderMarkdown(result, findings, cost), "utf8");
    console.error(`markdown report written to ${path}`);
  }

  if (asJson) {
    console.log(JSON.stringify({ scan: result, findings, cost }, null, 2));
  } else {
    console.log(renderTerminal(result, findings, cost));
  }

  // Non-zero exit on serious findings makes this usable in CI.
  if (findings.some((f) => f.severity === "critical")) process.exitCode = 2;
  else if (findings.some((f) => f.severity === "high")) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
