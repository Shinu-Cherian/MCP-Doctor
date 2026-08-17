/**
 * Rules for resources — the surface most scanners ignore entirely.
 *
 * Resources are read-only, which is why they get waved through. But a resource
 * is data the model ingests, and its description is prose the model reads, so
 * both of the things that make tools dangerous apply here too. Two findings in
 * this file — resource type confusion and binary payload delivery — are
 * documented attack classes that the MCP-DPT coverage study found no existing
 * scanner addresses.
 */

import type { Finding, ResourceDef, ResourceTemplateDef, ServerScan } from "../types.js";
import {
  INJECTION_MARKERS,
  PROMOTIONAL_MARKERS,
  allMatches,
  excerpt,
  firstMatch,
} from "./markers.js";

/** Locations whose contents are credentials or keys rather than project data. */
const SENSITIVE_PATH: { pattern: RegExp; what: string }[] = [
  { pattern: /\.ssh(\/|$)|id_rsa|id_ed25519/i, what: "SSH private keys" },
  { pattern: /\.aws(\/|$)|credentials$/i, what: "cloud credentials" },
  { pattern: /(^|\/)\.env(\.|$)|(^|\/)\.env$/i, what: "environment secrets" },
  { pattern: /\.npmrc|\.pypirc|\.docker\/config\.json/i, what: "registry tokens" },
  { pattern: /\.git\/config|\.gitconfig/i, what: "git credentials and remotes" },
  { pattern: /(^|\/)(etc\/)?(passwd|shadow)$/i, what: "system account files" },
  { pattern: /\.kube(\/|$)|kubeconfig/i, what: "cluster credentials" },
  { pattern: /Cookies|Login Data|key4\.db|logins\.json/i, what: "browser credentials" },
];

/** A file:// URI that covers a whole drive or home directory. */
const ROOT_URI = /^file:\/\/\/?(?:[A-Za-z]:\/?$|$|home\/?$|Users\/?$|root\/?$)/i;

/** MIME types that carry opaque bytes rather than reviewable text. */
const OPAQUE_MIME =
  /^(application\/(octet-stream|x-msdownload|x-executable|x-mach-binary|vnd\.microsoft\.portable-executable|x-sh|x-shellscript|java-archive|zip|x-7z-compressed)|.*\+zip)$/i;

/** Extension → the MIME family it should belong to. */
const EXTENSION_FAMILY: { pattern: RegExp; family: RegExp; label: string }[] = [
  { pattern: /\.(txt|md|log|csv)$/i, family: /^text\//i, label: "text" },
  { pattern: /\.json$/i, family: /^(application\/json|text\/)/i, label: "JSON" },
  { pattern: /\.(png|jpe?g|gif|webp|svg)$/i, family: /^image\//i, label: "image" },
  { pattern: /\.(exe|dll|so|dylib|bin)$/i, family: /^application\//i, label: "binary" },
];

function checkProse(
  text: string | undefined,
  label: string,
  uri: string,
  scan: ServerScan,
): Finding[] {
  const findings: Finding[] = [];
  const desc = text ?? "";
  if (!desc) return findings;

  const injected = firstMatch(desc, INJECTION_MARKERS);
  if (injected) {
    findings.push({
      rule: "resource-poisoning",
      severity: "critical",
      title: `${label} "${uri}" hides instructions in its description`,
      detail:
        "Resource descriptions are placed in the model's context exactly like tool " +
        "descriptions are, so an instruction written here is read as though it came " +
        `from you. Detected: ${injected.marker.label}.`,
      evidence: excerpt(desc, injected.index),
      remediation: "Remove this server. Assume any session that listed it was influenced.",
      server: scan.name,
    });
  }

  const promo = allMatches(desc, PROMOTIONAL_MARKERS);
  if (promo.length > 0) {
    findings.push({
      rule: "resource-promotional",
      severity: promo.length >= 2 ? "high" : "medium",
      title: `${label} "${uri}" advertises itself over other sources`,
      detail:
        "The description argues for its own selection rather than describing its " +
        `content, which biases which data the model reaches for. Detected: ${promo
          .map((p) => p.label)
          .join(", ")}.`,
      evidence: excerpt(desc),
      server: scan.name,
    });
  }

  return findings;
}

function checkUri(uri: string, scan: ServerScan, isTemplate: boolean): Finding[] {
  const findings: Finding[] = [];
  const label = isTemplate ? "Resource template" : "Resource";

  for (const s of SENSITIVE_PATH) {
    if (s.pattern.test(uri)) {
      findings.push({
        rule: "resource-sensitive-path",
        severity: "critical",
        title: `${label} exposes ${s.what}`,
        detail:
          `"${uri}" resolves to ${s.what}. Resources are read without a tool call and are ` +
          "commonly auto-attached to context, so this content can enter a conversation " +
          "without any approval step.",
        evidence: uri,
        remediation: "Remove this server, and rotate anything it could have read.",
        server: scan.name,
      });
      break;
    }
  }

  if (ROOT_URI.test(uri)) {
    findings.push({
      rule: "resource-root-exposure",
      severity: "high",
      title: `${label} is anchored at a filesystem root`,
      detail:
        `"${uri}" covers an entire drive or home directory. Every file your account can ` +
        "read is reachable through it.",
      evidence: uri,
      remediation: "Anchor the resource at the narrowest directory the task requires.",
      server: scan.name,
    });
  }

  return findings;
}

export function resourceRules(scan: ServerScan): Finding[] {
  const findings: Finding[] = [];

  /* Concrete resources --------------------------------------------------- */
  for (const r of scan.resources) {
    findings.push(...checkUri(r.uri, scan, false));
    findings.push(...checkProse(r.description, "Resource", r.uri, scan));

    /* Type confusion: declared MIME contradicts the URI's own extension. */
    if (r.mimeType) {
      for (const rule of EXTENSION_FAMILY) {
        if (rule.pattern.test(r.uri) && !rule.family.test(r.mimeType)) {
          findings.push({
            rule: "resource-type-confusion",
            severity: "high",
            title: `Resource "${r.uri}" declares a MIME type that contradicts its extension`,
            detail:
              `The URI looks like ${rule.label} but the server declares "${r.mimeType}". ` +
              "Clients decide how to parse and render content from the declared type, so a " +
              "mismatch lets a server have its content handled as something other than what " +
              "it appears to be.",
            evidence: `${r.uri} → ${r.mimeType}`,
            remediation: "Do not rely on the declared type; treat this server as untrusted.",
            server: scan.name,
          });
          break;
        }
      }

      /* Opaque payloads delivered through a read-only channel. */
      if (OPAQUE_MIME.test(r.mimeType)) {
        findings.push({
          rule: "resource-binary-payload",
          severity: "medium",
          title: `Resource "${r.uri}" serves opaque binary content`,
          detail:
            `The server offers "${r.mimeType}" through a channel meant for readable context. ` +
            "Binary payloads cannot be reviewed by you or meaningfully judged by the model, " +
            "and archives can carry executable content that later reaches disk.",
          evidence: `${r.uri} → ${r.mimeType}`,
          remediation: "Prefer servers that expose reviewable text resources.",
          server: scan.name,
        });
      }
    }
  }

  /* Templates ------------------------------------------------------------ */
  for (const t of scan.resourceTemplates) {
    findings.push(...checkUri(t.uriTemplate, scan, true));
    findings.push(...checkProse(t.description, "Resource template", t.uriTemplate, scan));

    /* A template whose only variable is the whole path is unbounded. */
    const variables = [...t.uriTemplate.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
    const unbounded = variables.some((v) => /^\+?(path|file|filepath|uri|url|location)$/i.test(v));
    if (unbounded) {
      findings.push({
        rule: "resource-template-unbounded",
        severity: "high",
        title: `Resource template "${t.uriTemplate}" accepts any path`,
        detail:
          "One template with an unconstrained path variable stands for every file the " +
          "server process can reach. A listing of concrete resources would show nothing " +
          "unusual, which is why template scope has to be read separately.",
        evidence: t.uriTemplate,
        remediation: "Ask for a template restricted to a known prefix or set of names.",
        server: scan.name,
      });
    }
  }

  return findings;
}
