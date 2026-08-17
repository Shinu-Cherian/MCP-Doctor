/**
 * Builders for test fixtures.
 *
 * Rules take whole ServerScan objects, so without these every test would need
 * fifteen lines of boilerplate to assert one thing.
 */

import type {
  DeclaredServer,
  DiscoveryResult,
  PromptDef,
  ResourceDef,
  ResourceTemplateDef,
  ScanResult,
  ServerScan,
  ToolDef,
} from "../src/types.js";

export function declared(over: Partial<DeclaredServer> = {}): DeclaredServer {
  return {
    name: "test-server",
    transport: "stdio",
    command: "node",
    args: [],
    envKeys: [],
    source: { client: "project", path: "/tmp/.mcp.json", serverCount: 1 },
    ...over,
  };
}

export function tool(over: Partial<ToolDef> & { name: string }): ToolDef {
  return {
    description: "",
    inputSchema: { type: "object", properties: {} },
    ...over,
  };
}

/** A tool with one plain, unconstrained string parameter. */
export function toolWithParam(
  name: string,
  param: string,
  over: Partial<ToolDef> = {},
): ToolDef {
  return tool({
    name,
    inputSchema: {
      type: "object",
      properties: { [param]: { type: "string" } },
      required: [param],
    },
    ...over,
  });
}

export function scan(over: Partial<ServerScan> = {}): ServerScan {
  return {
    name: over.name ?? "test-server",
    declared: over.declared ?? declared({ name: over.name ?? "test-server" }),
    status: "ok",
    tools: [],
    resources: [],
    resourceTemplates: [],
    prompts: [],
    unsolicited: [],
    ...over,
  };
}

export function prompt(name: string, description = ""): PromptDef {
  return { name, description, argumentNames: [] };
}

export function resource(over: Partial<ResourceDef> & { uri: string }): ResourceDef {
  return { ...over };
}

export function template(
  over: Partial<ResourceTemplateDef> & { uriTemplate: string },
): ResourceTemplateDef {
  return { ...over };
}

export function scanResult(servers: ServerScan[]): ScanResult {
  const discovery: DiscoveryResult = {
    scannedAt: new Date().toISOString(),
    platform: "test",
    checkedPaths: [],
    sources: [],
    servers: servers.map((s) => s.declared),
    errors: [],
  };
  return { scannedAt: new Date().toISOString(), discovery, servers };
}

/** Rule ids present in a finding list — the usual assertion target. */
export function ruleIds(findings: { rule: string }[]): string[] {
  return findings.map((f) => f.rule);
}
