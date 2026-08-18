# Changelog

## 0.2.1

**Says at the top when a report covers only part of the picture.**

A default run reads configuration and stops there, because reading a server's
tools means executing it and that stays opt-in. On the bundled fixtures that is
the difference between 5 findings and 23 — and every critical one sits in the
missing eighteen.

The skipped servers were already listed, but at the bottom, in dim text, after
every finding. The summary said "5 findings" with nothing to suggest anything
had been left out, which reads as a clean bill of health. That is the same
failure this tool exists to point at: a confident partial answer.

Both the terminal and markdown reports now state how many servers were not
inspected, and which flag would include them, beside the counts rather than
beneath them.

## 0.2.0

**Compares what is running against what the config files declare.**

Every scanner in this space reads configuration and stops there. Configuration
records intent; servers also arrive as extensions, connectors and bundled
features that never touch `mcpServers`. A config-only scan can therefore answer
"0 servers, no risks" on a machine that is running several — not merely
incomplete, but confidently wrong.

Detection uses the process table rather than client logs. A stdio MCP server is
a child process of whatever launched it, so the operating system knows about it
regardless of which application started it or where that application keeps its
settings — the one method that works the same for Claude, Cursor, VS Code and
Windsurf. Claude Desktop writes parseable per-server logs, but Cursor and VS
Code send theirs to an editor output panel and Windsurf documents no location,
so a log-based approach would have covered one client in four.

New rules:

- `undeclared-server` — a running MCP server no config file accounts for
- `live-check-unavailable` — the process table could not be read, so coverage is
  incomplete and the report says so rather than implying a clean result
- `live-matches-declared` — informational; everything running is accounted for

New flag: `--no-live` opts out. The check reads the process table, which
executes nothing and contacts nobody, so it is on by default.

Two false positives found and fixed while building it:

- A checkout in a directory called `MCP server` put "mcp" into the path of every
  command run from it. Matching now examines each argument's filename rather
  than the whole command line, and requires "mcp" to be joined to something:
  `mcp-server-git` matches, a directory called `mcp` does not.
- mcp-doctor reported itself, running through a script runner from that same
  directory, spawned by the very client whose children it was inspecting.

The process snapshot is taken before scanning. With `--spawn` we start servers
ourselves, and npx-style launchers leave orphans whose parent pid no longer
resolves, so afterwards our own children can look like someone else's.

## 0.1.0

First release.

- 30 deterministic rules across configuration, tools, resources, cross-server
  relationships and drift over time
- Finds tool descriptions carrying hidden instructions, annotations that
  contradict their own schema, over-shared credentials, and pairs of tools that
  together form a path off the machine
- Runs as a CLI, or as an MCP server itself via `mcp-doctor serve`
- Reads config for Claude Desktop, Claude Code, Cursor, VS Code and Windsurf
- Two safety defaults: reading a stdio server means executing it, so spawning is
  opt-in; and only environment variable names are recorded, never their values
