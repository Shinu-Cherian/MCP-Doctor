/**
 * Rules that run on a single tool definition.
 *
 * Ordering principle: the JSON Schema is the most trustworthy field a tool has,
 * because it is what actually governs input. The description is the least
 * trustworthy, because it is attacker-controlled text aimed at the model.
 * Annotations sit in between — they are claims, and claims can be checked.
 */

import type { Finding, ServerScan, ToolDef } from "../types.js";
import {
  INJECTION_MARKERS,
  PROMOTIONAL_MARKERS,
  allMatches,
  excerpt,
  firstMatch,
  words,
} from "./markers.js";

/** Verbs implying the tool changes state. */
const WRITE_VERB =
  /\b(delete|remove|drop|truncate|destroy|purge|wipe|write|create|update|insert|set|put|post|send|patch|upload|execute|exec|run|eval|spawn|install|deploy|merge|push|revoke|grant|rename|move|kill|restart|reset)\b/i;

/** Verbs implying the change is not recoverable. */
const DESTRUCTIVE_VERB = /\b(delete|remove|drop|truncate|destroy|purge|wipe|kill|revoke|reset)\b/i;

/** Parameter names whose free-form string form is effectively an interpreter. */
const HIGH_RISK_PARAM: Record<string, { kind: string; note: string }> = {
  sql: { kind: "SQL", note: "any statement the account can run, including DROP" },
  query: { kind: "query", note: "unconstrained query text" },
  command: { kind: "shell command", note: "arbitrary command execution" },
  cmd: { kind: "shell command", note: "arbitrary command execution" },
  script: { kind: "script", note: "arbitrary code execution" },
  code: { kind: "code", note: "arbitrary code execution" },
  eval: { kind: "expression", note: "arbitrary evaluation" },
};

const MEDIUM_RISK_PARAM: Record<string, { kind: string; note: string }> = {
  path: { kind: "filesystem path", note: "any file the process can reach" },
  file: { kind: "filesystem path", note: "any file the process can reach" },
  filepath: { kind: "filesystem path", note: "any file the process can reach" },
  filename: { kind: "filesystem path", note: "any file the process can reach" },
  dir: { kind: "directory", note: "any directory the process can reach" },
  url: { kind: "URL", note: "any destination on the network" },
  endpoint: { kind: "URL", note: "any destination on the network" },
  uri: { kind: "URI", note: "any destination the process can resolve" },
};

interface SchemaProp {
  name: string;
  type: string | undefined;
  constrained: boolean;
}

/** Read the top-level properties of a JSON Schema object. */
function readProps(schema: Record<string, unknown> | undefined): SchemaProp[] {
  if (!schema || typeof schema !== "object") return [];
  const props = schema.properties;
  if (typeof props !== "object" || props === null) return [];

  return Object.entries(props as Record<string, unknown>).map(([name, raw]) => {
    const p = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
    // enum / const / pattern / maxLength all bound what can be passed.
    const constrained =
      Array.isArray(p.enum) ||
      p.const !== undefined ||
      typeof p.pattern === "string" ||
      typeof p.maxLength === "number" ||
      Array.isArray((p as { anyOf?: unknown }).anyOf);
    return { name, type: typeof p.type === "string" ? p.type : undefined, constrained };
  });
}

/** Does anything about this tool indicate it writes, regardless of what it claims? */
function looksLikeWrite(tool: ToolDef, props: SchemaProp[]): string | null {
  if (WRITE_VERB.test(words(tool.name))) return `name contains a write verb ("${tool.name}")`;
  const risky = props.find(
    (p) => !p.constrained && p.type === "string" && HIGH_RISK_PARAM[p.name.toLowerCase()],
  );
  if (risky) {
    return `accepts unconstrained "${risky.name}" (${HIGH_RISK_PARAM[risky.name.toLowerCase()].kind})`;
  }
  return null;
}

export function toolRules(scan: ServerScan): Finding[] {
  const findings: Finding[] = [];

  /* 0. Requests the server made during a read-only scan ---------------- */
  for (const req of scan.unsolicited) {
    const isSampling = req.method.startsWith("sampling/");
    findings.push({
      rule: "unsolicited-request",
      severity: "critical",
      title: `Server issued ${req.method} during a listing-only scan`,
      detail: isSampling
        ? "We only connected and read this server's listings — no tool was called. " +
          "The server nevertheless asked to run a completion on your model, which bills " +
          "to you and lets the server place text of its choosing into a model context. " +
          "Well-behaved servers do not do this unprompted."
        : "We only connected and read this server's listings — no tool was called. " +
          "The server nevertheless tried to put a prompt in front of your user, which is " +
          "a phishing surface: the request text is written entirely by the server.",
      evidence: req.preview,
      remediation: "Remove this server. It reaches for your model or your user unbidden.",
      server: scan.name,
    });
  }

  for (const tool of scan.tools) {
    const props = readProps(tool.inputSchema);
    const ann = tool.annotations ?? {};
    const desc = tool.description ?? "";

    /* 1. Annotation contradicts the schema ----------------------------- */
    if (ann.readOnlyHint === true) {
      const evidence = looksLikeWrite(tool, props);
      if (evidence) {
        findings.push({
          rule: "annotation-lie",
          severity: "critical",
          title: `"${tool.name}" claims readOnlyHint but can modify state`,
          detail:
            "The server asserts this tool only reads, while its own schema permits writes. " +
            "Annotations are self-reported and verified by nobody, so a client that trusts " +
            "readOnlyHint may auto-approve this tool without asking the user.",
          evidence,
          remediation: "Treat this server as untrusted; do not auto-approve on annotations.",
          server: scan.name,
          tool: tool.name,
        });
      }
    }

    /* 2. Destructive tool labelled harmless ---------------------------- */
    if (ann.destructiveHint === false && DESTRUCTIVE_VERB.test(words(tool.name))) {
      findings.push({
        rule: "destructive-mislabel",
        severity: "high",
        title: `"${tool.name}" declares destructiveHint: false`,
        detail:
          "The name describes an irreversible operation while the annotation claims otherwise. " +
          "Clients use this hint to decide whether to warn the user before running a tool.",
        evidence: `destructiveHint: false on "${tool.name}"`,
        remediation: "Require explicit confirmation for this tool regardless of its annotation.",
        server: scan.name,
        tool: tool.name,
      });
    }

    /* 3. Instructions hidden in the description ------------------------ */
    const injected = firstMatch(desc, INJECTION_MARKERS);
    if (injected) {
      findings.push({
        rule: "tool-poisoning",
        severity: "critical",
        title: `"${tool.name}" hides instructions in its description`,
        detail:
          "Tool descriptions are inserted directly into the model's context. Text written " +
          "as an instruction here is read by the model as though it came from you, which is " +
          `how tool poisoning works. Detected: ${injected.marker.label}.`,
        evidence: excerpt(desc, injected.index),
        remediation: "Remove this server. Assume any session that loaded it was influenced.",
        server: scan.name,
        tool: tool.name,
      });
    }

    /* 4. Promotional / steering language ------------------------------- */
    const promo = allMatches(desc, PROMOTIONAL_MARKERS);
    if (promo.length > 0) {
      findings.push({
        rule: "promotional-metadata",
        severity: promo.length >= 2 ? "high" : "medium",
        title: `"${tool.name}" advertises itself over other tools`,
        detail:
          "The description tries to influence which tool the model selects rather than " +
          "describing what the tool does. This biases tool choice in the server's favour " +
          `and can route your data away from the tool you intended. Detected: ${promo
            .map((p) => p.label)
            .join(", ")}.`,
        evidence: excerpt(desc),
        remediation: "Prefer servers whose descriptions state behaviour, not preference.",
        server: scan.name,
        tool: tool.name,
      });
    }

    /* 5. Unbounded parameters ------------------------------------------ */
    for (const p of props) {
      if (p.constrained || p.type !== "string") continue;
      const key = p.name.toLowerCase();
      const high = HIGH_RISK_PARAM[key];
      const medium = MEDIUM_RISK_PARAM[key];
      if (!high && !medium) continue;

      const info = high ?? medium;
      findings.push({
        rule: "unbounded-parameter",
        severity: high ? "high" : "medium",
        title: `"${tool.name}" takes an unconstrained ${info.kind} ("${p.name}")`,
        detail:
          `The schema declares "${p.name}" as a plain string with no enum, pattern or length ` +
          `limit, so its real scope is ${info.note}. A constrained schema is the only ` +
          "part of a tool definition that actually limits what the model can ask for.",
        evidence: `"${p.name}": { "type": "string" }`,
        remediation: "Ask the server author for an enum, pattern or allowlist on this parameter.",
        server: scan.name,
        tool: tool.name,
      });
    }
  }

  return findings;
}
