# agent-security-audit

A standalone, stdlib-only, read-only security audit CLI for personal dev/agent infrastructure.

This exists because of a real multi-day audit of one person's setup — a
Claude Code install, a "Hermes" agent framework, a remote Linux box running
various services, dozens of local git repos, GitHub account hygiene. It
turned up hardcoded secrets, world-readable credential files, an exposed
dashboard, unpinned MCP servers with full tool access, and a GitHub Actions
injection vulnerability that was live in production. This tool encodes that
methodology so anyone can point it at their own — completely different —
stack.

```
$ asa scan ~/my-project
```

```
Security Audit -- /home/user/my-project
Scanned: 2026-08-06T17:13:31Z  |  asa v0.1.0

[Fixed: 0]  [Needs You: 5]  [To Rotate: 2]  [Clean: 0]

NEED YOU (5):
  1. [High] Overly broad shell permission grant: 'Bash(*)'
     -> Scope Bash permissions to specific command prefixes (e.g. "Bash(git *)") instead of granting all shell access.  (10 min)
     at .claude/settings.json
  2. [High] Untrusted input (github.event.inputs.draw_number) interpolated directly into a `run:` shell block
     -> Pass the value through `env:` and reference it as a shell variable instead of interpolating ${{ }} directly into the script text.  (10 min)
     at .github/workflows/deploy.yml:15
  3. [High] Service appears bound to all interfaces (0.0.0.0) instead of loopback
     -> Bind to 127.0.0.1 unless this genuinely needs to be reachable from other machines.  (10 min)
     at docker-compose.yml:4
  ...
```

## Why this one

- **Zero required dependencies.** Install and run it anywhere Python 3.9+
  exists — no pip install of a dozen transitive packages, nothing that can
  break from an upstream dependency update.
- **Read-only by default.** It reports and recommends. The only thing it
  can change on disk is a narrow, permanently-narrow set of `chmod` fixes,
  and only with your explicit confirmation (`asa fix`).
- **Never makes an outbound network call**, except two explicit,
  documented opt-ins: `--allow-audit-tools` (runs your own `npm
  audit`/`pip-audit`) and `--ai` (your own API key, your own choice).
- **Never prints a secret value.** Findings carry a variable name, a byte
  length, and a truncated hash — never the value itself, not even the
  first few characters. See [SECURITY.md](SECURITY.md).
- **Understands your stack automatically.** Detects Node/Python/Docker/
  Kubernetes/GitHub Actions/SSH/Claude Code/MCP config/Hermes profiles by
  file signature — no config file to write before your first scan.

## Install

Not on PyPI yet — run from a clone. The tool is stdlib-only (zero
dependencies), so no install step beyond a plain Python 3.9+:

```
git clone https://github.com/chintheman/agent-security-audit
cd agent-security-audit
python3 -m asa scan /path/to/project
```

If you use `uv`, `uv tool install .` from the clone gives you a global `asa`
command. (`pip install agent-security-audit` will work once this is
published to PyPI.)

## Usage

```
asa scan [path]                    # scan a directory (default: current dir)
asa scan --scope machine           # also check machine-level things (~/.ssh, ~/.hermes, cron, systemd)
asa scan --host user@myhost        # scan a remote box over SSH instead
asa scan --format html --out report.html
asa scan --ai                      # opt in to AI-assisted classification of unrecognized stacks (needs your own API key)
asa scan --baseline prior-scan.json  # detect permission drift since a previous scan

asa report --from-json scan.json --format md   # re-render a saved scan without re-scanning
asa fix --from-json scan.json --dry-run        # see what a fix run would do
asa fix --from-json scan.json --yes            # apply every safe (chmod-only) fix, no prompts
asa list-checks                    # see every check this version can run
```

Every `scan` writes the full machine-readable result to
`<target>/asa-output/<timestamp>-scan.json` alongside whatever `--format`
you asked for — that's what `report`, `fix`, and `--baseline` read back in.

## What it checks

Six categories, drawn directly from real findings:

| Category | Examples |
|---|---|
| **Secrets** | hardcoded credentials instead of env-var refs, world-readable `.env` files, the same secret value stored under two different names, secrets in git history |
| **Permissions** | SSH keys with no passphrase, insecure file/umask defaults |
| **Network** | services bound to `0.0.0.0`, a tunnel with no access policy in front of it, a service reachable over both HTTPS and plaintext HTTP |
| **Agent blast radius** | `Bash(*)`-shaped tool grants, unpinned `npx -y pkg@latest` MCP servers, an unattended/cron profile with no narrower scope than an interactive one, an unpinned install grant sitting next to a web-content channel with the approval gate off (the llms.txt supply-chain vector) |
| **Supply chain** | npm install-time hooks, dependencies pulled from a git URL instead of a registry |
| **GitHub Actions injection** | untrusted input interpolated straight into a `run:`/`github-script` block — the exact pattern this project's own toto-backend audit found live in production |

Run `asa list-checks` for the full, current list with check IDs.

## Remote scanning

`asa scan --host user@myhost` runs the exact same checks against a remote
box you already have SSH access to. No pre-install needed on the remote
side beyond a plain `python3` — the tool bundles its own source into one
script and pipes it over `ssh`. It never manages credentials for you; it
uses whatever SSH access already works from your terminal.

## AI-assist (optional)

`--ai` does two things, both narrowly scoped, both off unless you ask:
finds directories that don't match any known stack signature and asks an
LLM to guess what they are, and phrases a fix for any finding that has no
built-in fix text (none currently do — every check ships with one). Set
`ASA_LLM_API_KEY` (and optionally `ASA_LLM_PROVIDER=anthropic|openai`,
default `anthropic`). Every AI-touched result is capped at medium
confidence and visibly tagged in the report. No secret value or file
snippet is ever sent — see `asa/ai_assist.py`'s docstring for the exact
guarantee.

## Don't want to install the CLI?

Two ways to run the same audit with nothing installed. Both are prose an
agent follows, so both are less reliable than the CLI — an LLM re-derives
each check from text every run instead of running tested code — but
useful when installing someone else's tool isn't an option.

**Using Claude Code:** copy
[`.claude/skills/security-audit/`](.claude/skills/security-audit/SKILL.md)
into `~/.claude/skills/` and just ask it to audit something. The skill
loads itself when the request calls for it; there's nothing to paste and
nothing to remember. It's one self-contained file and covers every check
ID the CLI ships. (Claude Code can also just run the CLI directly —
`python3 -m asa scan <path>` — since it has shell access.)

**Using Hermes:** copy
[`.hermes/skills/security-audit/`](.hermes/skills/security-audit/SKILL.md)
into `~/.hermes/skills/<category>/` (e.g. `security/`) and any Hermes
session handles "audit my machine" or "audit this repo" as a full run —
it prefers the tested CLI when present and falls back to this
methodology when it can't run.

**Using any other agent:** [`PLAYBOOK.md`](PLAYBOOK.md) is the same audit
written for whatever agent you already use and trust — paste it in and
say "audit this project."

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new checker.

## Security

See [SECURITY.md](SECURITY.md) for how this tool handles secrets, and how
to report an issue with the tool itself.

## License

MIT — see [LICENSE](LICENSE).
