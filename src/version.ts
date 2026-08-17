/**
 * The package version, read from package.json rather than written twice.
 *
 * mcp-doctor announces this version to every server it connects to, and its own
 * MCP server announces it to clients. Hardcoding it means the number drifts
 * from reality the moment a release is cut — and this tool has a rule that
 * flags servers whose reported identity changes unexpectedly, so being wrong
 * about our own is worse than merely untidy.
 *
 * The relative path resolves correctly from both `src/` under tsx and `dist/`
 * after compilation, and npm always includes package.json in a published
 * package regardless of the `files` list.
 */

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

interface PackageManifest {
  name: string;
  version: string;
}

const manifest = require("../package.json") as PackageManifest;

/** e.g. "0.2.0" */
export const VERSION: string = manifest.version;

/** Identity announced during the MCP handshake, in both directions. */
export const IMPLEMENTATION = { name: "mcp-doctor", version: VERSION } as const;
