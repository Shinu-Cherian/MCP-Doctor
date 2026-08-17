/**
 * Rules that run on config alone — no server is contacted or executed.
 *
 * This layer answers the question no existing scanner asks:
 * "which of my secrets did I hand to which program?"
 */

import type { DeclaredServer, Finding } from "../types.js";

/** Redact anything that looks like a password inside a connection string. */
export function redact(text: string): string {
  return text
    .replace(/(:\/\/[^:/@\s]+:)[^@\s]+(@)/g, "$1***$2") // user:pass@host
    .replace(/((?:token|key|secret|password|pwd)=)[^\s&]+/gi, "$1***");
}

/** Env var names that carry credentials rather than configuration. */
const SECRET_NAME = /(TOKEN|SECRET|PASSWORD|PASSWD|PWD|API_?KEY|CREDENTIAL|AUTH|DSN|CONNECTION_STRING)/i;

/** Groups of env vars that authenticate to the same system. */
const OVERLAPPING_GROUPS: { label: string; members: RegExp[] }[] = [
  {
    label: "PostgreSQL",
    members: [/^DATABASE_URL$/i, /^PG(PASSWORD|USER|DATABASE|HOST)$/i, /^POSTGRES_/i],
  },
  { label: "GitHub", members: [/^GITHUB_(TOKEN|PERSONAL_ACCESS_TOKEN|PAT)$/i, /^GH_TOKEN$/i] },
  { label: "AWS", members: [/^AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|PROFILE)$/i] },
];

/** Paths that hand a server far more of the disk than any task needs. */
const OVERBROAD_PATH =
  /^(?:[A-Za-z]:[\\/]?$|[\\/]$|~[\\/]?$|\/(?:home|Users|etc|var|root)\/?$)/;

function isUnpinned(command: string | undefined, args: string[]): string | null {
  if (!command) return null;
  const runner = /^(npx|uvx|pnpm|bunx|dlx)$/i.test(command);
  if (!runner) return null;

  // The package spec is the first argument that isn't a flag.
  const spec = args.find((a) => !a.startsWith("-"));
  if (!spec) return null;

  if (/@latest$/i.test(spec)) return spec;
  // scoped @org/pkg with no trailing @version is also unpinned
  const withoutScope = spec.startsWith("@") ? spec.slice(1) : spec;
  if (!withoutScope.includes("@")) return spec;
  return null;
}

export function configRules(server: DeclaredServer): Finding[] {
  const findings: Finding[] = [];
  const args = server.args ?? [];
  const argText = args.join(" ");

  /* 1. Unpinned remote code -------------------------------------------- */
  const unpinned = isUnpinned(server.command, args);
  if (unpinned) {
    findings.push({
      rule: "unpinned-package",
      severity: "high",
      title: "Server runs an unpinned package fetched at launch",
      detail:
        `"${server.command}" downloads ${unpinned} every time this server starts. ` +
        "Whoever controls that package controls code running on this machine, and " +
        "the version you audited is not necessarily the version that runs tomorrow.",
      evidence: `${server.command} ${argText}`,
      remediation: "Pin an exact version, e.g. package@1.2.3, and review updates deliberately.",
      server: server.name,
    });
  }

  /* 2. Credentials passed on the command line -------------------------- */
  const secretInArgs = args.find(
    (a) => /:\/\/[^:/@\s]+:[^@\s]+@/.test(a) || /(password|token|api[_-]?key)=/i.test(a),
  );
  if (secretInArgs) {
    findings.push({
      rule: "secret-in-args",
      severity: "critical",
      title: "Credential passed as a command-line argument",
      detail:
        "Command-line arguments are visible to every process on this machine and are " +
        "routinely captured by shell history, crash dumps and process listings. A " +
        "secret placed here should be treated as already disclosed.",
      evidence: redact(secretInArgs),
      remediation: "Move the value into env and rotate the credential — assume it leaked.",
      server: server.name,
    });
  }

  /* 3. Privileged database account ------------------------------------- */
  // Only args can be inspected here: env *values* are deliberately never read,
  // so an admin DSN hidden in DATABASE_URL is invisible to this rule by design.
  if (/:\/\/(admin|root|postgres|sa|superuser)[:@]/i.test(argText)) {
    findings.push({
      rule: "privileged-account",
      severity: "high",
      title: "Server connects with a privileged database account",
      detail:
        "The connection string uses an administrative account. Any tool this server " +
        "exposes inherits that authority, so a read-only-looking tool can still drop " +
        "tables if its input is not constrained.",
      evidence: redact(argText),
      remediation: "Create a least-privilege role for this server instead.",
      server: server.name,
    });
  }

  /* 4. Over-broad filesystem grant ------------------------------------- */
  for (const arg of args) {
    if (OVERBROAD_PATH.test(arg)) {
      findings.push({
        rule: "overbroad-root",
        severity: "high",
        title: `Server is granted a filesystem root: ${arg}`,
        detail:
          "Every file readable by your user account is in scope for this server, " +
          "including SSH keys, browser profiles and cloud credentials.",
        evidence: arg,
        remediation: "Point the server at the narrowest directory the task requires.",
        server: server.name,
      });
    }
  }

  /* 5. Overlapping credentials ----------------------------------------- */
  for (const group of OVERLAPPING_GROUPS) {
    const matched = server.envKeys.filter((k) => group.members.some((m) => m.test(k)));
    if (matched.length > 1) {
      findings.push({
        rule: "redundant-credentials",
        severity: "medium",
        title: `Server holds ${matched.length} overlapping ${group.label} credentials`,
        detail:
          `${matched.join(", ")} all authenticate to ${group.label}. Only one is needed; ` +
          "each extra copy is another place the secret can leak from and another thing " +
          "to remember during rotation.",
        evidence: matched.join(", "),
        remediation: "Keep a single credential and remove the rest.",
        server: server.name,
      });
    }
  }

  /* 6. Secret breadth --------------------------------------------------- */
  const secrets = server.envKeys.filter((k) => SECRET_NAME.test(k));
  if (secrets.length >= 3) {
    findings.push({
      rule: "secret-breadth",
      severity: "medium",
      title: `Server receives ${secrets.length} distinct secrets`,
      detail:
        "This server's blast radius is the union of everything these credentials unlock, " +
        "regardless of what its tools claim to do. Compromising the server compromises all of them.",
      evidence: secrets.join(", "),
      remediation: "Split unrelated capabilities across servers so one breach is not total.",
      server: server.name,
    });
  }

  /* 7. Plaintext transport ---------------------------------------------- */
  if (server.url && server.url.startsWith("http://")) {
    const host = (() => {
      try {
        return new URL(server.url!).hostname;
      } catch {
        return "";
      }
    })();
    const local = host === "localhost" || host === "127.0.0.1" || host === "::1";
    findings.push({
      rule: "plaintext-transport",
      severity: local ? "low" : "high",
      title: "Server is contacted over plaintext HTTP",
      detail: local
        ? "Traffic stays on the loopback interface, but any local process can still observe it."
        : "Tool calls, arguments and any bearer token travel unencrypted and can be read or modified in transit.",
      evidence: server.url,
      remediation: local ? "Prefer https even locally where the server supports it." : "Use https.",
      server: server.name,
    });
  }

  return findings;
}
