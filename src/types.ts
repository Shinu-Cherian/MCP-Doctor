/**
 * Core data shapes for mcp-doctor.
 *
 * Design rule that everything else depends on:
 * we record the NAMES of secrets, never their VALUES. A security tool that
 * copies your tokens into a report file is a liability, not a defence.
 */

/** How a client talks to a server. */
export type Transport = "stdio" | "http" | "unknown";

/** Which AI app a config file belongs to. */
export type ClientKind =
  | "claude-desktop"
  | "claude-code"
  | "cursor"
  | "vscode"
  | "windsurf"
  | "project";

/** A config file we found on disk. */
export interface ConfigSource {
  client: ClientKind;
  path: string;
  /** Number of server entries this file contributed. */
  serverCount: number;
}

/**
 * One MCP server as *declared* in a config file.
 * This is what the config claims. Whether it matches reality is a later question.
 */
export interface DeclaredServer {
  /** Key used in the config, e.g. "github". */
  name: string;
  transport: Transport;

  /** stdio only: the program that gets executed. */
  command?: string;
  args?: string[];

  /** http only: the endpoint. */
  url?: string;

  /**
   * Names of environment variables handed to this server — values deliberately
   * omitted. `GITHUB_TOKEN` tells us everything we need; its value tells us
   * nothing extra and creates a leak risk.
   */
  envKeys: string[];

  /** Where we found it, so findings can be traced back to a file. */
  source: ConfigSource;
}

/** Result of scanning every known config location. */
export interface DiscoveryResult {
  scannedAt: string;
  platform: string;
  /** Config paths we looked at, whether or not they existed. */
  checkedPaths: string[];
  sources: ConfigSource[];
  servers: DeclaredServer[];
  /** Files that exist but could not be parsed. */
  errors: { path: string; message: string }[];
}

/* ------------------------------------------------------------------ *
 * Live scan: what a server actually reports when we connect to it.
 * ------------------------------------------------------------------ */

/**
 * The four annotation hints from the MCP spec.
 *
 * Every one of these is written by the server about itself and verified by
 * nobody. We store them so we can compare the claim against the schema —
 * a tool that claims `readOnlyHint` while accepting free-form SQL is lying.
 */
export interface ToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface ToolDef {
  name: string;
  description?: string;
  /** JSON Schema. The most honest field a tool has. */
  inputSchema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  annotations?: ToolAnnotations;
}

export interface ResourceDef {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

/**
 * A parameterised resource, e.g. `file:///{path}`.
 *
 * Templates matter more than fixed resources: a single template can stand for
 * every file on the disk, which no listing of concrete URIs would reveal.
 */
export interface ResourceTemplateDef {
  uriTemplate: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

export interface PromptDef {
  name: string;
  description?: string;
  argumentNames: string[];
}

/**
 * What the server declared during the handshake.
 *
 * Note that `sampling` and `elicitation` are *client* capabilities, not server
 * ones: a server never announces that it will ask your model for completions
 * or prompt your user — it simply sends the request. That asymmetry is why we
 * detect those behaviourally, via `unsolicited` below.
 */
export interface ServerCapabilities {
  tools: boolean;
  resources: boolean;
  prompts: boolean;
  logging: boolean;
  completions: boolean;
  experimental: boolean;
}

/**
 * A request the server sent to us that we never asked for.
 *
 * We connect and read listings only. A server that issues sampling/createMessage
 * or elicitation/create during that is reaching for your model or your user
 * before any tool has been invoked.
 */
export interface UnsolicitedRequest {
  method: string;
  /** Short excerpt, for evidence. Truncated; never the full payload. */
  preview?: string;
}

export type ScanStatus = "ok" | "failed" | "skipped";

/** One server, after we tried to talk to it. */
export interface ServerScan {
  name: string;
  declared: DeclaredServer;
  status: ScanStatus;
  /** Why it failed or was skipped. */
  note?: string;

  serverInfo?: { name: string; version: string };
  protocolVersion?: string;
  capabilities?: ServerCapabilities;

  tools: ToolDef[];
  resources: ResourceDef[];
  resourceTemplates: ResourceTemplateDef[];
  prompts: PromptDef[];

  /** Requests the server made of us during a read-only scan. */
  unsolicited: UnsolicitedRequest[];

  /** Milliseconds for handshake + listing, useful as a crude health signal. */
  durationMs?: number;

  /**
   * Where this surface came from. "log" means it was reconstructed from a
   * client log rather than obtained by connecting, so it describes the last
   * recorded session rather than this moment.
   */
  discoveredVia?: "config" | "log";
}

export interface ScanResult {
  scannedAt: string;
  discovery: DiscoveryResult;
  servers: ServerScan[];
  /** What was actually running, when the check was performed. */
  live?: LiveResult;
  /** What the client logs revealed, including servers config never mentions. */
  logs?: LogSummary;
}

/** Which log directories were read, and what they yielded. */
export interface LogSummary {
  checkedDirs: string[];
  supportedClients: ClientKind[];
  /** Names of servers found only in logs — nothing in config declares them. */
  undeclared: string[];
}

/* ------------------------------------------------------------------ *
 * Live processes: what is actually running, as opposed to declared.
 * ------------------------------------------------------------------ */

/** One row from the operating system's process table. */
export interface RunningProcess {
  pid: number;
  ppid: number;
  /** Full command line, when the OS will give us one. */
  command: string;
}

/**
 * A process that looks like an MCP server currently running on this machine.
 *
 * Config files are a statement of intent. This is what is actually there —
 * and the two are not always the same, which is the entire point of the check.
 */
export interface LiveServer {
  pid: number;
  command: string;
  /** Client application that spawned it, if the ancestry says so. */
  client?: string;
  /** Name of the matching entry in a config file, when one matches. */
  declaredAs?: string;
  /** Why we concluded this is an MCP server. */
  reason: string;
}

export interface LiveResult {
  /** False when the platform gave us nothing usable. */
  supported: boolean;
  /** Total processes examined, for context in the report. */
  examined: number;
  servers: LiveServer[];
  /** Why enumeration failed or was partial. */
  note?: string;
}

/* ------------------------------------------------------------------ *
 * Client logs: servers the client has run, recorded on disk.
 * ------------------------------------------------------------------ */

/**
 * A server recovered from a client log rather than from config.
 *
 * The handshake is written out in full, so this carries the same tool
 * definitions a live scan would return — obtained without starting anything.
 */
export interface LoggedServer {
  /** Name the client used, taken from the log filename. */
  name: string;
  client: ClientKind;
  logPath: string;
  serverInfo?: { name: string; version: string };
  tools: ToolDef[];
  prompts: PromptDef[];
  /** When the log was last written, as a rough "last used". */
  lastSeen?: string;

  /**
   * False when the client's logger cut the payload short.
   *
   * Claude Desktop replaces the middle of a long message with a marker like
   * "[29928 chars truncated]", which leaves the JSON unparseable. The server
   * is still proof of an installation, but its tool list is not trustworthy —
   * and running rules over a partial list would report "no findings" for tools
   * that were never read, which is worse than admitting the gap.
   */
  listingComplete: boolean;
  /** Tool names recovered before the cut, for information only. */
  partialToolNames: string[];
}

/* ------------------------------------------------------------------ *
 * Findings
 * ------------------------------------------------------------------ */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export interface Finding {
  /** Stable identifier, e.g. "annotation-lie". Used for suppression and diffing. */
  rule: string;
  severity: Severity;
  /** One line stating the defect. */
  title: string;
  /** Why it matters, in plain language. */
  detail: string;
  /** The specific text or value that triggered the rule. */
  evidence?: string;
  /** What the user should do about it. */
  remediation?: string;

  server?: string;
  tool?: string;
  /** Servers involved, when a finding spans more than one. */
  servers?: string[];
}
