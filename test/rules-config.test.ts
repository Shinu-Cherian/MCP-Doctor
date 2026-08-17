import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { configRules, redact } from "../src/rules/config.js";
import { declared, ruleIds } from "./factories.js";

describe("config rules", () => {
  describe("unpinned-package", () => {
    it("fires on an explicit @latest", () => {
      const findings = configRules(
        declared({ command: "npx", args: ["-y", "some-server@latest"] }),
      );
      assert.ok(ruleIds(findings).includes("unpinned-package"));
    });

    it("fires when no version is given at all", () => {
      const findings = configRules(declared({ command: "npx", args: ["-y", "some-server"] }));
      assert.ok(ruleIds(findings).includes("unpinned-package"));
    });

    it("fires on a scoped package with no version", () => {
      const findings = configRules(
        declared({ command: "npx", args: ["-y", "@scope/some-server"] }),
      );
      assert.ok(ruleIds(findings).includes("unpinned-package"));
    });

    it("does not fire on a pinned version", () => {
      const findings = configRules(declared({ command: "npx", args: ["-y", "some-server@1.2.3"] }));
      assert.ok(!ruleIds(findings).includes("unpinned-package"));
    });

    it("does not fire for a direct binary that fetches nothing", () => {
      const findings = configRules(declared({ command: "node", args: ["server.js"] }));
      assert.ok(!ruleIds(findings).includes("unpinned-package"));
    });
  });

  describe("secret-in-args", () => {
    it("fires on a connection string containing a password", () => {
      const findings = configRules(
        declared({ command: "uvx", args: ["srv@1.0.0", "--dsn", "postgres://u:pw@host/db"] }),
      );
      const finding = findings.find((f) => f.rule === "secret-in-args");
      assert.ok(finding, "a password on the command line must be reported");
      assert.ok(
        !finding.evidence?.includes("pw@"),
        "evidence must not reproduce the password verbatim",
      );
    });

    it("does not fire on a password-free connection string", () => {
      const findings = configRules(
        declared({ command: "uvx", args: ["srv@1.0.0", "--dsn", "postgres://host/db"] }),
      );
      assert.ok(!ruleIds(findings).includes("secret-in-args"));
    });
  });

  describe("overbroad-root", () => {
    it("fires on a Windows drive root", () => {
      const findings = configRules(declared({ command: "node", args: ["srv.js", "C:\\"] }));
      assert.ok(ruleIds(findings).includes("overbroad-root"));
    });

    it("fires on a POSIX root", () => {
      const findings = configRules(declared({ command: "node", args: ["srv.js", "/"] }));
      assert.ok(ruleIds(findings).includes("overbroad-root"));
    });

    it("does not fire on a specific directory", () => {
      const findings = configRules(
        declared({ command: "node", args: ["srv.js", "/home/user/projects"] }),
      );
      assert.ok(!ruleIds(findings).includes("overbroad-root"));
    });
  });

  describe("redundant-credentials", () => {
    it("fires when two variables authenticate to the same system", () => {
      const findings = configRules(declared({ envKeys: ["DATABASE_URL", "PGPASSWORD"] }));
      assert.ok(ruleIds(findings).includes("redundant-credentials"));
    });

    it("does not fire for credentials to different systems", () => {
      const findings = configRules(declared({ envKeys: ["GITHUB_TOKEN", "AWS_PROFILE"] }));
      assert.ok(!ruleIds(findings).includes("redundant-credentials"));
    });
  });

  describe("secret-breadth", () => {
    it("fires once a server holds three or more secrets", () => {
      const findings = configRules(
        declared({ envKeys: ["GITHUB_TOKEN", "SLACK_TOKEN", "STRIPE_API_KEY"] }),
      );
      assert.ok(ruleIds(findings).includes("secret-breadth"));
    });

    it("ignores non-secret environment variables", () => {
      const findings = configRules(declared({ envKeys: ["LOG_LEVEL", "PORT", "NODE_ENV"] }));
      assert.ok(!ruleIds(findings).includes("secret-breadth"));
    });
  });

  describe("plaintext-transport", () => {
    it("is high severity for a remote host", () => {
      const findings = configRules(
        declared({ transport: "http", url: "http://api.example.com/mcp", command: undefined }),
      );
      const finding = findings.find((f) => f.rule === "plaintext-transport");
      assert.equal(finding?.severity, "high");
    });

    it("is low severity on loopback", () => {
      const findings = configRules(
        declared({ transport: "http", url: "http://localhost:3000/mcp", command: undefined }),
      );
      const finding = findings.find((f) => f.rule === "plaintext-transport");
      assert.equal(finding?.severity, "low");
    });

    it("does not fire for https", () => {
      const findings = configRules(
        declared({ transport: "http", url: "https://api.example.com/mcp", command: undefined }),
      );
      assert.ok(!ruleIds(findings).includes("plaintext-transport"));
    });
  });

  describe("redact", () => {
    it("removes the password from a connection string", () => {
      assert.equal(redact("postgres://admin:s3cret@host/db"), "postgres://admin:***@host/db");
    });

    it("removes query-string style secrets", () => {
      assert.equal(redact("https://x/y?token=abc123"), "https://x/y?token=***");
    });

    it("leaves clean text untouched", () => {
      assert.equal(redact("npx -y server@1.0.0"), "npx -y server@1.0.0");
    });
  });
});
