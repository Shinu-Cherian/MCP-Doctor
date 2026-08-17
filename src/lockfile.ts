/**
 * Drift detection — the defence against rug pulls.
 *
 * A rug pull works because approval is granted once, against metadata the user
 * read at the time, and is never revisited. The server behaves for a month,
 * then rewrites a tool description; the approval still stands and nothing in
 * the client says anything changed.
 *
 * The countermeasure is unglamorous: hash every definition, write it down, and
 * compare next time. No model required, no heuristics to tune.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { Finding, ScanResult, ServerScan } from "./types.js";

export const LOCKFILE_NAME = "mcp-doctor.lock.json";

interface LockedServer {
  /** Tool name → hash of its full definition. */
  tools: Record<string, string>;
  /** Prompt name → hash. */
  prompts: Record<string, string>;
  identity?: string;
}

export interface Lockfile {
  version: 1;
  generatedAt: string;
  servers: Record<string, LockedServer>;
}

function hash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex").slice(0, 16);
}

/**
 * Hash everything the model is influenced by.
 *
 * Description is included deliberately: a changed description with an unchanged
 * schema is the exact shape of a tool-poisoning rug pull, and hashing the
 * schema alone would miss it entirely.
 */
function hashTool(tool: {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: unknown;
}): string {
  return hash({
    name: tool.name,
    description: tool.description ?? "",
    inputSchema: tool.inputSchema ?? null,
    annotations: tool.annotations ?? null,
  });
}

export function buildLockfile(result: ScanResult): Lockfile {
  const servers: Record<string, LockedServer> = {};

  for (const scan of result.servers) {
    if (scan.status !== "ok") continue;
    const tools: Record<string, string> = {};
    for (const t of scan.tools) tools[t.name] = hashTool(t);

    const prompts: Record<string, string> = {};
    for (const p of scan.prompts) {
      prompts[p.name] = hash({ name: p.name, description: p.description ?? "", args: p.argumentNames });
    }

    servers[scan.name] = {
      tools,
      prompts,
      identity: scan.serverInfo ? `${scan.serverInfo.name}@${scan.serverInfo.version}` : undefined,
    };
  }

  return { version: 1, generatedAt: new Date().toISOString(), servers };
}

export function readLockfile(path: string): Lockfile | null {
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Lockfile;
    return parsed.version === 1 ? parsed : null;
  } catch {
    return null;
  }
}

export function writeLockfile(path: string, lock: Lockfile): void {
  writeFileSync(path, `${JSON.stringify(lock, null, 2)}\n`, "utf8");
}

/** Compare a fresh scan against a previously approved lockfile. */
export function diffAgainstLock(previous: Lockfile, result: ScanResult): Finding[] {
  const findings: Finding[] = [];
  const current = buildLockfile(result);

  for (const [serverName, before] of Object.entries(previous.servers)) {
    const after = current.servers[serverName];
    const scan: ServerScan | undefined = result.servers.find((s) => s.name === serverName);

    if (!after) {
      // Absent from this scan: could be removed, could be failing to start.
      if (scan && scan.status !== "ok") continue; // already reported as a scan failure
      findings.push({
        rule: "server-disappeared",
        severity: "low",
        title: `Server "${serverName}" is in the lockfile but was not scanned`,
        detail: "It may have been removed intentionally. Refresh the lockfile if so.",
        server: serverName,
      });
      continue;
    }

    if (before.identity && after.identity && before.identity !== after.identity) {
      findings.push({
        rule: "identity-changed",
        severity: "medium",
        title: `"${serverName}" now identifies as ${after.identity}`,
        detail:
          `It previously identified as ${before.identity}. A version bump is normal; a change ` +
          "of name is not, and can indicate the config now points at a different program.",
        evidence: `${before.identity} → ${after.identity}`,
        server: serverName,
      });
    }

    for (const [tool, beforeHash] of Object.entries(before.tools)) {
      const afterHash = after.tools[tool];
      if (afterHash === undefined) {
        findings.push({
          rule: "tool-removed",
          severity: "low",
          title: `"${serverName}" no longer offers "${tool}"`,
          detail: "Anything depending on this tool will now fail or silently take another path.",
          server: serverName,
          tool,
        });
      } else if (afterHash !== beforeHash) {
        findings.push({
          rule: "definition-drift",
          severity: "critical",
          title: `"${tool}" changed since you approved it`,
          detail:
            "The description, schema or annotations of this tool differ from the version " +
            "recorded in the lockfile, while your approval carried over unchanged. This is " +
            "the mechanism behind rug-pull attacks: behave until trusted, then rewrite.",
          evidence: `${beforeHash} → ${afterHash}`,
          remediation: "Re-read this tool's definition before using it again, then re-lock.",
          server: serverName,
          tool,
        });
      }
    }

    for (const tool of Object.keys(after.tools)) {
      if (before.tools[tool] === undefined) {
        findings.push({
          rule: "tool-added",
          severity: "medium",
          title: `"${serverName}" added a new tool: "${tool}"`,
          detail:
            "A tool that appeared after you approved this server has never been reviewed, " +
            "yet inherits the trust you granted the server as a whole.",
          server: serverName,
          tool,
        });
      }
    }

    for (const [prompt, beforeHash] of Object.entries(before.prompts)) {
      const afterHash = after.prompts[prompt];
      if (afterHash !== undefined && afterHash !== beforeHash) {
        findings.push({
          rule: "definition-drift",
          severity: "high",
          title: `Prompt /${prompt} changed since you approved it`,
          detail:
            "Prompts expand into instructions sent on your behalf. A silently edited prompt " +
            "changes what a familiar command actually does.",
          evidence: `${beforeHash} → ${afterHash}`,
          server: serverName,
        });
      }
    }
  }

  // Servers present now but absent from the lockfile.
  for (const serverName of Object.keys(current.servers)) {
    if (previous.servers[serverName] === undefined) {
      findings.push({
        rule: "server-added",
        severity: "medium",
        title: `New server since last lock: "${serverName}"`,
        detail: "This server was not present when the lockfile was written.",
        server: serverName,
      });
    }
  }

  return findings;
}
