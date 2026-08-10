# Security Audit Playbook (for AI agents)

## What this is

A self-contained set of instructions for an AI coding agent (Claude, ChatGPT,
Cursor, or any agent with file-read and shell access) to run a security
audit of a codebase or machine, without installing anything.

**How to use it:** paste this whole file into your agent's context — or
point it at this file directly if your agent can read a URL/file path — and
say: *"Follow this playbook and audit [this project / this machine]."*

**Using Claude Code? Use the skill instead:** copy
[`.claude/skills/security-audit/`](.claude/skills/security-audit/SKILL.md)
into `~/.claude/skills/` and it loads itself whenever you ask for an audit
— no pasting, nothing to remember. Same six categories as this file, kept
in step with the checker source.

This is the no-install alternative to
[`agent-security-audit`](https://github.com/chintheman/agent-security-audit),
the tested CLI this playbook is derived from. The CLI is more reliable (its
checks are covered by an automated test suite that has caught real bugs);
this playbook is for when you'd rather have an agent you already trust do
the work than install someone else's tool. Same checks, same categories,
same report shape.

**Two audit scopes — know which one you're doing before you start:**
- **Project audit** (default): the target is a single directory/repo.
  Categories 3–6 apply fully; in category 1 (secrets), skip the
  git-history check if it's not a git repo; in category 2 (permissions),
  skip home-directory and umask checks entirely — there's no "home
  directory" inside a project.
- **Machine audit**: the target is "this whole machine" or `~`. All
  checks in all six categories apply, including the machine-level ones in
  category 2.

If a check doesn't apply to the scope you're in, don't report it as
"clean" (that overstates what you checked) — say **not applicable**,
separately from **clean**. "Clean" means you checked and found nothing;
"not applicable" means there was nothing there to check.

---

## Ground rules (read first, follow throughout)

1. **Read-only by default.** Report findings and recommended fixes. Do not
   change, delete, or move anything without the user's explicit approval —
   see "Two kinds of findings" below.
2. **Never print, log, or repeat a secret value.** Not the full value, not
   a prefix, not a few characters "just to confirm it's real." If you need
   to reference a discovered credential, describe it as: **variable name +
   approximate length + where it is** ("`API_KEY` in `.env`, looks like ~40
   characters"). Never echo it, never include it in your response, never
   write it to a report file.
3. **Never make an outbound network call** to verify whether a credential
   is live, valid, or working. That's a judgment call for the user, one key
   at a time, not something to automate.
4. **Never rotate a key, edit git history, or restart a service.** Outside
   your scope entirely — flag it, don't do it.
5. **If something needs a shell command that could be destructive** (delete,
   overwrite, `chmod` outside the narrow list below), stop and ask first,
   every time — no "I'll just fix it while I'm here."

---

## Two kinds of findings

Every finding you report falls into exactly one of these. Say which, for
each one.

- **Auto-fixable (propose, then wait for approval)** — a small, reversible,
  mechanical fix. In this playbook, that means **exactly one thing**: fixing
  file permissions with `chmod` on a file that's more permissive than it
  should be. Nothing else qualifies, ever — no key rotation, no file
  edits, no deletions, no git operations. Show the user the exact command
  before running it, and only run it after they say yes.
- **Needs a human decision** — everything else. Describe the finding, the
  risk, and a concrete recommended next step, but the user does that step
  themselves (rotate a key, change a network setting, decide on a policy).

---

## What to check

Work through these six categories. For each finding, record: **severity**
(critical / high / medium / low / info), **what/where**, **why it matters**,
**recommended fix**, and **which of the two kinds above it is**.

### 1. Secrets & credential hygiene

- **Hardcoded value instead of an environment-variable reference.** Search
  config files (`.yaml`/`.yml`/`.json`/`.toml`/`.ini`/`.conf`/`.cfg`,
  `docker-compose.yml`, systemd `.service` files) for a line that looks
  like a credential assignment — key name containing `password`, `secret`,
  `token`, `api_key`, `access_key`, `private_key`, `client_secret`, `auth`,
  or `credential` — where the value is a **literal string** rather than an
  env-var reference (`${VAR}`, `$VAR`, `os.environ[...]`, `process.env.X`).
  Skip `.env` files themselves (that's what they're for). Skip a value only
  if it's **exactly** one of: `changeme`, `xxx` (or `xxxx`), `todo`,
  `fixme`, `your-key-here`, `example`, `test`, `fake`, `null`, `none`,
  `true`, `false`, `n/a`, `placeholder`, empty, or a single character
  repeated (`aaaa`, `----`). **This list is exhaustive, not illustrative —
  if a value merely *looks* like it might be a fake/test value but isn't
  literally one of these, flag it anyway.** A string like
  `hunter2ThisLooksFake` does not qualify for the skip-list and should be
  flagged; false positives here are cheap, false negatives are not.
  **Severity: high.**
- **Credential-shaped string anywhere in source.** Scan all text files
  (skip binaries, skip `.env*`) for strings matching known credential
  shapes: `sk-ant-...` / `sk-proj-...` (Anthropic/OpenAI), `ghp_...` /
  `github_pat_...` (GitHub), `AIza...` (Google), `xoxb-...`/`xoxp-...`
  (Slack), `AKIA.../ASIA...` (AWS), `-----BEGIN...PRIVATE KEY-----`, or a
  **generic high-entropy string**, precisely defined as: 32+ characters
  from the set `[A-Za-z0-9+_=-]` (note: no `/` in this set — deliberately
  excluded because it makes ordinary file paths match; see below),
  containing at least one letter AND at least one digit. **Be careful:** a
  long string containing `/` (like a file path) is very likely NOT a
  secret — evaluate path segments individually (split on `/`), not the
  whole path as one string, and only the named-provider shapes above
  should ever match across a `/`. **Severity: high for named-provider
  shapes, medium for generic high-entropy strings** (lower confidence).
- **World-readable `.env` file.** Any `.env`/`.env.*` file with permissions
  looser than owner-only (i.e., group or other can read it). **Severity:
  high. Auto-fixable** (`chmod 600 <file>`).
- **Same secret value under two different variable names.** Compare
  candidate secret values *without printing any of them*. If your agent
  can run code: compute a SHA-256 hash of each candidate value locally and
  compare only the hashes — never surface the hash-to-value mapping in
  your report, only "these two locations share a value" plus the two
  locations. If you can't run code: use judgment by comparing values
  in-memory without ever writing one into your response, and mark the
  finding `confidence: low` since it wasn't hash-verified. **Severity:
  medium.**
- **Generic variable name reused across unrelated tools.** `PASSWORD`,
  `EMAIL`, `KEY`, `TOKEN`, `SECRET`, `API_KEY`, `USERNAME` used bare (not
  prefixed) in more than one `.env` file for what look like different
  tools. This causes one tool's credential to silently leak into another's
  environment. **Severity: medium.**
- **Secret in git history.** If this is a git repo, check whether a
  credential-shaped file (`*.env*`, `*.pem`, `*.key`, anything with
  "secret"/"credential"/"password" in the name) was ever committed and
  later removed (`git log --all -- <path>`). A secret that was ever
  committed should be treated as compromised even if deleted now.
  **Severity: critical.** Not auto-fixable — recommend rotation, never
  attempt to rewrite git history yourself.

### 2. File & OS permissions

- **SSH private key with no passphrase.** Look in `~/.ssh/` for files
  whose content starts with a private-key header. If you can safely check
  (e.g. the environment supports it), an unencrypted key opens with no
  passphrase prompt. **Severity: high.** Not auto-fixable (adding a
  passphrase is a user action — recommend `ssh-keygen -p`).
- **SSH private key or other sensitive file with loose permissions.**
  SSH keys, `~/.aws/credentials`, `~/.ssh/config`, cloud CLI config files
  readable by group/other. **Severity: high. Auto-fixable** (`chmod 600`).
- **Home directory too permissive.** If you're auditing "the whole
  machine," check the home directory's own permissions aren't looser than
  `750`. **Severity: medium.**
- **Weak or missing default umask.** Check shell startup files
  (`.bashrc`, `.zshrc`, `.profile`) for a `umask` setting weaker than
  `077`/`027`, or note if none is set at all (don't assume that's safe —
  say "unknown, worth checking"). **Severity: low if weak, info if
  unknown.**

### 3. Network exposure

- **Service bound to all interfaces instead of loopback.** Look for
  `0.0.0.0` binds in config files, `docker-compose.yml` port mappings
  (`"0.0.0.0:8080:80"`), or `--host 0.0.0.0`-style flags. **Severity:
  high.**
- **Tunnel exposing a local service with no access policy.** If there's a
  Cloudflare Tunnel config (`.cloudflared/*.yml`) or similar routing a
  public hostname to `localhost`/`127.0.0.1`, check whether there's an
  access-control layer in front of it. If not, that service is reachable
  by anyone who finds the URL. **Severity: medium.**
- **Same service reachable over both HTTPS and plaintext HTTP.** Look for
  the same service registered on both a TLS-typical port (443, 8443) and
  a plaintext port (80, 8080, 8000, or other) — a login form served
  correctly over HTTPS but also reachable in plaintext on a different port
  silently downgrades security. **Severity: medium.**
- **Firewall disabled.** Check if there's a way to tell (e.g. `ufw`
  config showing disabled). **Severity: medium.**
- **Screen lock disabled or not requiring immediate password.** Best
  effort — only report this if you can actually check it (e.g. you're
  running with direct access to the machine's settings). **If you
  structurally can't check it from where you're running** (auditing a
  project directory, or running remotely with no access to desktop
  settings), don't report a finding at all — that's a "not applicable
  from this context," not a low-confidence guess. Never invent an
  unverifiable finding.

### 4. Agent / AI-tool blast radius

- **Overly broad shell permission grant.** In Claude Code settings
  (`.claude/settings.json`, `permissions.allow`) or similar agent configs,
  look for a bare `Bash`, `Bash(*)`, or equivalent "run anything" grant
  instead of scoped command prefixes. **Severity: high.**
- **Unpinned MCP server / tool install.** `npx -y <package>` with no
  version pin (bare package name, or `@latest`) means remote code is
  fetched fresh on every launch with full tool access. **Severity:
  medium.**
- **No separation between interactive and unattended tool scope.** A
  cron-scheduled or otherwise unattended agent profile that has the same
  broad tool access (shell execution, payments, messaging) as an
  interactive session — there's no human in the loop to catch a mistake.
  **Severity: medium.**
- **Untrusted-input tool + high-impact tool with no approval gate.** An
  agent/profile that can both ingest untrusted content (fetch web pages,
  read email, read messages) AND take high-impact action (run shell
  commands, send money, publish, delete, send messages) with nothing
  requiring confirmation in between. This is the shape of a
  prompt-injection risk. **Severity: medium.**

### 5. Supply chain

- **npm install-time script hooks.** `package.json` `scripts.preinstall`
  / `scripts.postinstall` / `scripts.prepare`. **Non-trivial (severity:
  high)**: makes a network call (`curl`, `wget`, `fetch`), executes a
  downloaded/external script, writes files outside `node_modules`, or
  calls `chmod`/`exec`/`eval`. **Trivial (severity: low)**: prints a
  message (`echo`, `console.log`), or runs a project-local build/compile
  step with no network access and no execution of anything fetched at
  install time (e.g. `tsc`, `webpack` on local source — still worth a
  low-severity note since it's still automatic, but not a high-risk
  pattern by itself).
- **Dependency sourced from a git URL or tarball instead of the
  registry.** `git+https://...` or a raw `.tar.gz` URL in
  `package.json`/`requirements.txt`/`pyproject.toml` dependencies instead
  of a normal registry version. Flag that this also can't be checked
  against upstream for drift without a network call — recommend the user
  verify manually. **Severity: medium.**
- **Known vulnerability in a dependency.** Only if the user explicitly
  asks you to actually run `npm audit` / `pip-audit` (this makes network
  calls to the package registries — don't do it silently).

### 6. GitHub Actions / CI injection

- **Untrusted input interpolated directly into a shell command.** In
  `.github/workflows/*.yml`, look for `${{ github.event.* }}` or
  `${{ github.head_ref }}` written directly inside a `run:` block, instead
  of passed through `env:` and referenced as a shell variable. This lets
  anyone who can trigger the workflow (e.g. via an issue title or PR
  branch name) inject shell commands. **Severity: high — escalate to
  critical if the same job also has a high-privilege secret "in scope,"**
  meaning referenced via `${{ secrets.NAME }}` somewhere in that same job,
  where `NAME` (case-insensitive) contains any of: `service_role`,
  `admin`, `root`, `master`, `write`, `deploy`, `aws_secret`, `private_key`.
  This exact list — nothing broader ("or similar" is not a rule, don't
  extrapolate past it). **Known
  limitation, say so if it applies:** a secret can be available to a
  workflow without being referenced by name in the visible file (inherited
  at repo/org level) — you can only detect explicit references by reading
  files, so note "could not verify whether unreferenced secrets are also
  available" rather than claiming a clean result.
- **Same pattern inside `actions/github-script`.** Same interpolation
  issue, but inside a JS `script:` block instead of a shell `run:` block.
  Same fix: pass via `env:`, read via `process.env.NAME`.
- **`pull_request_target` checking out untrusted code.** A workflow
  triggered by `pull_request_target` (which runs with write-level secrets)
  that also checks out the PR's own head commit — this runs
  attacker-controlled code with elevated permissions. **Severity:
  critical.**
- **Actions pinned by a mutable tag instead of a commit SHA.**
  `uses: actions/checkout@v4` instead of a full 40-character commit hash —
  a compromised or re-tagged action version could execute arbitrary code
  in your CI. **Severity: low.**
- **No explicit `permissions:` block, or `permissions: write-all`.**
  Missing entirely means the workflow inherits whatever the repo/org
  default is (worth stating explicitly); `write-all` is definitely too
  broad. **Severity: low for missing, medium for write-all.**

---

## How to present results

Use this shape, most severe first:

```
SECURITY AUDIT — <target>

[0 critical] [5 high] [1 medium] [2 low] [0 info]

NEEDS YOU (severity-sorted, max 7 — if there are more, say "+N more, see detail"):
  1. [severity] <one-line description>
     -> <concrete next step>
     at <file:line or location>
  2. ...

AUTO-FIXABLE (chmod only — list each, wait for approval before running):
  - <file> is <current permissions>, should be 600
    command: chmod 600 <file>

CLEAN / LOWER PRIORITY (collapsed/summarized, not the main focus):
  - <category>: checked, no findings
  - <low-severity item>: <one line>

NOT APPLICABLE (checks that don't apply to this target — different from
"clean"; say why):
  - <category/check>: <why it doesn't apply, e.g. "not a git repo", "no
    .env files present", "project audit, not machine audit">

DETAIL (only expand if asked): full finding list per category, each with
severity, what/where, why it matters, recommended fix.
```

Rules for this format, so two different agents produce comparable output:

- **Always show all five severity counts in the header, including zeros** —
  don't omit a bucket just because it's empty.
- **Within the same severity, order findings by category first** (secrets,
  then permissions, then network, then agent blast radius, then supply
  chain, then CI), **then within the same category+severity, order
  alphabetically by file path, then by line number** if there is one —
  gives a fully deterministic order instead of an arbitrary one at every
  level.
- **"Not applicable" is a separate bucket from "clean."** Clean = you
  checked and found nothing. Not applicable = there was nothing to check
  (wrong scope, feature not present, can't verify from this context).
  Don't conflate them — a reader needs to know the difference between "we
  looked and it's fine" and "we couldn't look."

Keep the top-level summary short. Nobody wants a wall of text as the first
thing they see — lead with what needs a decision, put everything else
behind a "want the full detail?" offer.

---

## When you're done

Summarize: how many findings per severity, how many you fixed (with
approval) vs. how many still need the user's decision. End with a short
list of exactly what's still on them to do — don't bury an action item
inside a long paragraph.
