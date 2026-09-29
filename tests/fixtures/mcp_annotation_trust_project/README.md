# mcp_annotation_trust_project fixture

For `agent.trusts_mcp_tool_annotations` (tests/checkers/test_agent_blast_radius.py).

`.claude/settings.json` grants `mcp__github__*` -- every tool the github
MCP server exposes, auto-approved, with no per-tool review -- and must
trigger the check.
