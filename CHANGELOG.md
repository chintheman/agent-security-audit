# Changelog

All notable changes to this project are documented here.

## [0.2.0] - 2026-09-29

### Added

Four new checks (34 -> 38 total, still six categories, still zero
dependencies):

- **`secrets.seed_phrase_detected`** -- flags a run of 12, 15, 18, 21, or
  24 consecutive BIP-39 English wordlist words in a text file, or in
  `git log -p` history. The 2048-word list ships in-package
  (`asa/data/bip39_wordlist.py`, public domain, sourced verbatim from the
  BIP-39 spec). Only an exact-case-sensitive-lowercase, exact-length,
  whitespace-separated run counts, to keep false positives low. The
  finding never carries the phrase itself -- only file, line, and word
  count.
- **`agent.exfiltration_triad`** -- flags an agent config that combines
  all three of: access to private data (filesystem, secrets, email, db
  tools), ingestion of untrusted content (web fetch/browse, email,
  issue/PR comments), and an outbound channel (HTTP post, email send,
  messaging, webhook, or a shell with network access) in the same file.
  A stricter sibling of the existing `agent.prompt_injection_reachability`
  check.
- **`network.unauthenticated_dangerous_route`** -- static scan of
  Flask/FastAPI (Python) and Express/Hono (JS/TS) source for a route
  handler that executes a command, reads a file path, or proxies a URL
  built from request input, with no auth decorator/middleware/check
  visible on that route or applied app-wide earlier in the file.
  Heuristic (regex + indentation/brace-balance block extraction, not an
  AST), so every finding is confidence="low" with an explicit
  "verify manually" remediation; a command-execution sink is called out
  as remote code execution.
- **`agent.trusts_mcp_tool_annotations`** -- flags a config that
  auto-approves or blanket-allows an entire MCP server's tools (e.g. a
  Claude Code `"mcp__server__*"` or `"mcp__*"` permission entry), or that
  explicitly conditions auto-approval on a server-declared tool
  annotation (`readOnlyHint`, `destructiveHint`, `idempotentHint`) --
  both self-reported by the server, never verified by the client.

### Changed

- Version bumped to 0.2.0 (`pyproject.toml`, `asa/__init__.py`).
- `asa/ssh_remote.py`'s remote-execution bundle now includes
  `asa/data/bip39_wordlist.py` (required by the secrets checker).
- README's "What it checks" table and check count updated for the four
  new checks.

## [0.1.0] - 2026-08-06

Initial release. 34 checks across six categories (secrets, permissions,
network, agent blast radius, supply chain, GitHub Actions injection),
stdlib-only, read-only by default, remote-over-SSH support, optional
`--ai` classification hook. See the git history for the full build log
(M1 through M10).
