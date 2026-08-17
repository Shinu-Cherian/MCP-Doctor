/**
 * Rules that only exist when you look at several servers together.
 *
 * A tool that reads files is fine. A tool that posts to the internet is fine.
 * Installed side by side with nothing between them, they are an exfiltration
 * path — and no per-server scan can see it.
 */

import type { Finding, ServerScan, ToolDef } from "../types.js";
import { excerpt, words } from "./markers.js";

/** Tools that pull data the user would not want published. */
const SENSITIVE_READ = /\b(read|get|fetch|load|open|cat|dump|list|export|query|select)\b/i;

/** Parameters that make a tool an outbound channel. */
const SINK_PARAM = /^(url|endpoint|uri|webhook|destination|to|recipient|channel)$/i;

function propNames(tool: ToolDef): string[] {
  const props = tool.inputSchema?.properties;
  if (typeof props !== "object" || props === null) return [];
  return Object.keys(props as Record<string, unknown>);
}

function isUnconstrainedString(tool: ToolDef, name: string): boolean {
  const props = tool.inputSchema?.properties as Record<string, unknown> | undefined;
  const p = props?.[name];
  if (typeof p !== "object" || p === null) return false;
  const s = p as Record<string, unknown>;
  return s.type === "string" && !Array.isArray(s.enum) && s.const === undefined;
}

/** Does this tool pull potentially sensitive data into the conversation? */
function isSource(tool: ToolDef): string | null {
  const names = propNames(tool);
  const pathish = names.find(
    (n) => /^(path|file|filepath|filename|dir)$/i.test(n) && isUnconstrainedString(tool, n),
  );
  if (pathish) return `reads any "${pathish}" on disk`;
  if (SENSITIVE_READ.test(words(tool.name)) && names.some((n) => isUnconstrainedString(tool, n))) {
    return `"${tool.name}" retrieves unconstrained data`;
  }
  return null;
}

/** Can this tool move data off the machine? */
function isSink(tool: ToolDef): string | null {
  if (tool.annotations?.openWorldHint === true) {
    return `"${tool.name}" is declared openWorld (reaches the network)`;
  }
  const names = propNames(tool);
  const target = names.find((n) => SINK_PARAM.test(n) && isUnconstrainedString(tool, n));
  if (target) return `"${tool.name}" accepts an arbitrary "${target}"`;
  return null;
}

export function crossRules(servers: ServerScan[]): Finding[] {
  const findings: Finding[] = [];
  const live = servers.filter((s) => s.status === "ok");

  /* 1. Prompt (slash command) collisions ------------------------------- */
  const promptOwners = new Map<string, string[]>();
  for (const s of live) {
    for (const p of s.prompts) {
      promptOwners.set(p.name, [...(promptOwners.get(p.name) ?? []), s.name]);
    }
  }
  for (const [name, owners] of promptOwners) {
    if (owners.length > 1) {
      findings.push({
        rule: "prompt-collision",
        severity: "high",
        title: `/${name} is published by ${owners.length} servers`,
        detail:
          `${owners.join(" and ")} both expose a prompt named "${name}". You see one entry ` +
          "in the command list and cannot tell which server will answer; resolution depends " +
          "on client load order, so a later-installed server can quietly take over a command " +
          "you have been using for months.",
        evidence: `/${name} ← ${owners.join(", ")}`,
        remediation: "Remove one server, or use a client that namespaces prompts per server.",
        servers: owners,
      });
    }
  }

  /* 2. Tool name shadowing --------------------------------------------- */
  const toolOwners = new Map<string, string[]>();
  for (const s of live) {
    for (const t of s.tools) {
      toolOwners.set(t.name, [...(toolOwners.get(t.name) ?? []), s.name]);
    }
  }
  for (const [name, owners] of toolOwners) {
    if (owners.length > 1) {
      findings.push({
        rule: "tool-shadowing",
        severity: "medium",
        title: `Tool "${name}" is defined by ${owners.length} servers`,
        detail:
          `${owners.join(" and ")} each define "${name}". The model picks between them using ` +
          "descriptions alone, so the more persuasively worded one wins — which is exactly " +
          "what an impersonating server relies on.",
        evidence: `${name} ← ${owners.join(", ")}`,
        remediation: "Keep only the server you actually intended to use for this capability.",
        servers: owners,
      });
    }
  }

  /* 3. Exfiltration paths ---------------------------------------------- */
  const sources: { server: string; tool: string; why: string }[] = [];
  const sinks: { server: string; tool: string; why: string }[] = [];
  for (const s of live) {
    for (const t of s.tools) {
      const src = isSource(t);
      if (src) sources.push({ server: s.name, tool: t.name, why: src });
      const snk = isSink(t);
      if (snk) sinks.push({ server: s.name, tool: t.name, why: snk });
    }
  }

  // Report one finding per (source server → sink server) pair rather than one
  // per tool pair. Twenty readers and ten senders is two hundred tool pairs but
  // still only one decision for the user to make.
  const pairs = new Map<
    string,
    { src: (typeof sources)[number]; snk: (typeof sinks)[number]; extra: number }
  >();

  for (const src of sources) {
    for (const snk of sinks) {
      if (src.server === snk.server && src.tool === snk.tool) continue;
      const key = `${src.server}→${snk.server}`;
      const existing = pairs.get(key);
      if (existing) existing.extra += 1;
      else pairs.set(key, { src, snk, extra: 0 });
    }
  }

  for (const { src, snk, extra } of pairs.values()) {
    const sameServer = src.server === snk.server;
    findings.push({
      rule: "exfiltration-path",
      severity: sameServer ? "high" : "critical",
      title: `${src.server} can read data that ${snk.server} can send off this machine`,
      detail:
        `${src.why}, and ${snk.why}. Neither tool is dangerous alone, and a scanner that ` +
        "examines servers one at a time will pass both. Chained, they are a complete path " +
        "from your filesystem to an address the model can choose" +
        (sameServer ? "." : " — spanning two independently installed servers.") +
        (extra > 0 ? ` ${extra} further tool combination(s) form the same path.` : ""),
      evidence: `${src.server}.${src.tool}  →  ${snk.server}.${snk.tool}`,
      remediation: "Require confirmation on the outbound tool, or do not run these together.",
      servers: sameServer ? [src.server] : [src.server, snk.server],
    });
  }

  /* 4. One server naming another's tools -------------------------------- */
  for (const s of live) {
    const foreign = new Set(
      live.filter((o) => o.name !== s.name).flatMap((o) => o.tools.map((t) => t.name)),
    );
    for (const t of s.tools) {
      const desc = t.description ?? "";
      for (const other of foreign) {
        // Ignore names this server also defines itself.
        if (s.tools.some((own) => own.name === other)) continue;
        if (new RegExp(`\\b${other}\\b`).test(desc)) {
          findings.push({
            rule: "cross-server-reference",
            severity: "high",
            title: `"${t.name}" gives the model instructions about another server's "${other}"`,
            detail:
              "A tool description should describe its own tool. Referring to a tool that " +
              "belongs to a different server is how one server modifies the behaviour of " +
              "another without ever being called.",
            evidence: excerpt(desc),
            remediation: "Treat this server as hostile to the others and remove it.",
            server: s.name,
            tool: t.name,
          });
        }
      }
    }
  }

  return findings;
}
