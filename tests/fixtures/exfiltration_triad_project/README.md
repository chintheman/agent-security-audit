# exfiltration_triad_project fixture

For `agent.exfiltration_triad` (tests/checkers/test_agent_blast_radius.py).

`.mcp.json` describes one MCP server with all three exfiltration-triad legs
in the same file (filesystem access, web_fetch ingestion, http_post
outbound) and must trigger the check. `.claude/settings.json` has only an
outbound-shaped keyword (`Bash`) with no private-data or untrusted-content
leg present, and must stay silent.
