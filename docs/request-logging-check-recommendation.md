# Should origin request logging / spoofed-bot detection be an asa checker?

## Verdict

**Split.** Presence detection ("is access logging even wired up") fits
asa's existing static-scan model and should become one small check.
Log *analysis* (parsing `access.jsonl` to flag spoofed-bot traffic)
should **not** live in asa — it's a different problem class (temporal,
stateful, dependent on external data that goes stale) and belongs in a
separate watchdog script/cron.

## Rationale

asa's scan model is a **point-in-time snapshot of a filesystem tree**:
`Manifest` walks `scan_root` once, classifies it via `signatures.py`, and
every checker's `activates(manifest)` predicate answers a pure yes/no
question about what's *present*. Nothing in the architecture holds state
across runs except the optional `--baseline` finding-id diff, and nothing
parses an unbounded, growing, timestamped event stream. `access.jsonl` is
exactly that: it grows forever, its useful signal is in *sequences and
rates* ("how many requests from this UA/IP pair in the last hour"), not in
static structure, and a meaningful verdict ("this traffic is spoofed")
requires comparing against externally-published, change-over-time data
(Anthropic/Google/OpenAI/Perplexity IP ranges or Web Bot Auth key
material) that a local static scanner has no legitimate way to keep
current.

That collides directly with two standing rules from `CONTRIBUTING.md`:

- **No live credential verification / no new outbound-call paths.**
  Verifying "is this IP in ClaudeBot's published range" either means
  fetching a live range list (a new outbound call — forbidden outside the
  two existing documented opt-ins) or bundling a static copy of each
  vendor's ranges in `asa/data/` that silently goes stale and produces
  false negatives (spoofed IP now outside the bundled range → not
  flagged) or false positives (legitimate bot rotated to a new published
  range not yet vendored). Neither failure mode is acceptable for a
  security tool, and there's no clean way to bound the staleness.
- **Read-only, dependency-free, run-anywhere.** A log-analysis checker
  only produces signal if `~/.hermes/logs/access.jsonl` has been
  accumulating for a while *before* the scan runs. That's fine for the
  operator's own box (continuously running services) but wrong as a
  general-audience checker default — most `asa scan ~/some-project`
  invocations are one-shot, against a target with no log history at all.
  A checker that's only meaningful for one very specific always-on
  deployment shape doesn't belong in the default registry.

Presence/config detection is different — it's a structural question about
files that exist right now, same shape as every other checker in the
repo:

- `network.py`'s `_check_tunnel_without_access_policy` already greps a
  `cloudflared_config` component's ingress file for a static pattern
  (`"ingress:"` present, no `"access"`/`"cloudflareaccess"` string nearby)
  and emits a MEDIUM finding — no live probe, no external data dependency.
- `network.py`'s `_check_firewall_disabled` is the closest existing
  analog to "is a defensive control enabled": best-effort, config-file-or-
  local-read-only-command, degrades to an "unknown, verify manually"
  finding rather than crashing or claiming clean.
- `permissions.py` and `network.py` both key off `_home_is_scan_root()`
  to activate machine-level checks only when `asa scan` is pointed at
  `~` (i.e. `--scope machine`), which is exactly the scope this would need
  (`~/.hermes/logs/` is a machine-level path, not project-level).

So "is logging even turned on for internet-facing origin services" is a
config-presence question asa is already built to answer. "Is that log
showing an active spoofing campaign right now" is a monitoring question
asa is not built to answer and structurally shouldn't try to.

## Proposed shape (presence-only)

New checks in the existing `network.py` module (not a new category —
this is squarely "network/service exposure," the same category
`tunnel_without_access_policy` lives in; a new `Category` enum value is a
bigger decision per `CONTRIBUTING.md` and isn't warranted for one check).

**`network.internet_facing_service_without_access_log`**

- **Category:** `NETWORK`. **Severity:** MEDIUM (a detective control gap,
  not an active exposure — matches `tunnel_without_access_policy`'s
  severity for the same reasoning: makes a real incident invisible after
  the fact rather than causing one).
- **`activates`**: extend the existing predicate — additionally activate
  when `manifest.has_kind("cloudflared_config")` (already true) so this
  rides the same activation the tunnel check uses; no new signature
  needed.
- **`run()` logic**: for each `cloudflared_config` component, parse the
  ingress file the same way `_check_tunnel_without_access_policy` already
  does to enumerate `service: http://127.0.0.1:PORT` targets (loopback
  origins proxied to the public internet). For each such target, look for
  *evidence the origin process logs requests* — this is a heuristic, not a
  live check, matching `firewall_disabled`'s best-effort pattern:
  - If `scope machine` and `~/.hermes/logs/access.jsonl` (or a
    configurable path) exists and was modified within some recent window
    (e.g. last 7 days) → treat as present, no finding, OR emit an INFO
    "logging present" finding for positive confirmation (see LOG-002
    below on why a positive finding is actually useful here).
    Reading *presence + mtime* is fine; do not parse the JSONL content in
    this check — that's the line where "config detection" turns into "log
    analysis."
  - If the manifest's scan includes source under the ingress target (i.e.
    a project-scope scan that happens to contain the origin server code,
    like this scenario's `hermes_cli/web_server.py`) grep for a narrow,
    literal marker — e.g. `@app.middleware("http")` co-occurring with
    `user-agent` (case-insensitive) in the same file — as *supporting*
    evidence only, never as the sole basis for a finding, since source
    presence proves the code exists, not that it runs in production.
  - If neither signal is found → emit the finding: an internet-facing
    loopback service via Cloudflare Tunnel with no discoverable
    per-request access log.
- **Evidence**: `file` = the ingress config path; `detail` = the
  `service:` target and (if checked) the log path checked and its
  existence/mtime state. No secret-shaped content is ever in scope here —
  still route through `redact.evidence_dict()`/`make_snippet()` for any
  snippet field populated from file content, per the standing rule (cheap
  insurance, not because this specific data is secret-shaped).
- **Fix**: "Add per-request access logging (method, path, status, UA,
  IP, timestamp — never query strings or secret headers) to the origin
  service in front of this tunnel, so spoofed-identity traffic is
  discoverable after the fact." **Fix time estimate**: "30 min" (matches
  the actual effort of the middleware shown in this task's background).

**`network.public_bot_ua_unauthenticated`** — considered and **rejected**
as a checker. This is the actual "spoofed ClaudeBot" detection and it
requires exactly the log-content-parsing + external-IP-range-dependency
work argued against above. Do not build it in asa. See "next steps."

Everything above stays inside the completeness contract for free —
`_check_tunnel_without_access_policy`-style checks iterate
`manifest.components_of("cloudflared_config")`, which is populated during
`Manifest.build()` and already covered by `verify_completeness()`; this
check adds no new top-level scan paths and touches no code that affects
that contract.

## Critique of the current logging implementation

Reviewed against `redact.py`'s standing rules, general request-logging
hygiene, and the specific failure modes called out in the prompt:

1. **Query strings excluded — good, but referer isn't.** `ref` (Referer
   header) is logged verbatim and is a well-known secondary leak channel:
   a token-in-URL pattern (`?token=...`) on a *referring* page, or a
   password-reset/magic-link URL a user followed from another origin,
   lands in `ref` even though the current request's own query string was
   correctly excluded. If any client-side flow in this stack ever puts a
   token in a URL and links to/from these origins, it leaks here. Either
   log `urlparse(ref).path` only (strip query+fragment) or drop `ref`
   entirely — a personal-infra access log doesn't need it.

2. **No credential-shape scrubbing on `ua`/`host`/`path`/`ref`.** Every
   one of these is attacker- or client-controlled and written to disk
   unfiltered. A malicious or malformed UA string embedding a
   credential-shaped substring (or just a huge string) goes straight into
   the JSONL. This is precisely the class of bug
   `redact.mask_credential_shapes()` / `assert_no_secret_shape()` exist to
   catch, and precisely the kind of thing `tests/test_redact.py`'s BSD-sed
   regression story is a cautionary tale about — a masking gap that only
   shows up when someone actually sends the adversarial input, i.e. now
   that this log is bot-facing. Recommend running `path`, `ua`, `host`,
   and `ref` through `mask_credential_shapes()`-equivalent logic before
   write, and hard-capping each field's length (e.g. 512 bytes) so a
   malicious client can't use the UA/path header to grow the log file
   arbitrarily fast (see #4).

3. **No rotation/size cap — unbounded growth, and it's on the
   attack-facing side.** A single JSONL file with no rotation, written
   from a middleware that (correctly) logs *every* request including
   unauthenticated 4xx/599s, is a disk-exhaustion vector: the exact
   spoofed-bot scanning campaign this logging is meant to detect can also
   be used to fill the disk by hammering the origin with requests, each
   one appended unconditionally. At minimum add size-based rotation
   (stdlib `logging.handlers.RotatingFileHandler` semantics, or manual
   rollover past e.g. 50MB) before this ships anywhere it'll see real
   scanner traffic — which, per the background here, it already is.

4. **The 599 fallback status is a made-up code and will misrender
   downstream.** `status = 599` as the "call_next raised before setting a
   real status" sentinel is fine as an internal marker but 599 isn't a
   registered HTTP status and any downstream consumer (a dashboard, a
   `status // 100` bucketing script, Cloudflare-side correlation) that
   assumes 1xx–5xx will choke or silently miscategorize it into the 5xx
   bucket by accident of arithmetic. Prefer a value clearly out of HTTP
   range paired with an explicit field (`{"status": null, "error": true}`)
   or reuse 500 with a separate `"unhandled_exception": true` flag —
   don't rely on unregistered-but-numeric-looking values downstream code
   might coerce.

5. **`finally` swallows the real exception.** `_access_log_middleware`
   catches nothing itself but relies on `_access_log_line`'s bare
   `except Exception: pass` to guarantee logging never breaks serving —
   that part's correct and matches the repo's "never raise" ethos
   (`network.py`'s best-effort checks degrade the same way). But the
   `try/finally` around `call_next` re-raises whatever `call_next` raised
   (good — response still propagates/500s correctly) *and* the log line
   for that failure still gets written via `finally`, so this part is
   actually fine on inspection. No action needed here — flagging only
   because the prompt asked about it specifically; verified correct.

6. **Host-header trust**: `request.headers.get("host", "")` is logged
   as-is. Behind Cloudflare, `Host` should be Cloudflare's own
   injected value, but if the origin is ever reachable directly (bound
   to something other than strict loopback, or the tunnel's `service:`
   target is misconfigured — exactly the shape `network.py`'s
   `tunnel_without_access_policy`/`service_bound_all_interfaces` checks
   already look for) an attacker can set an arbitrary `Host` header
   straight into this log. Since the field is only used for
   logging/display here (not for routing/auth decisions), this is low
   severity — but don't let a future feature read `host` out of this log
   and treat it as trusted without re-verifying that assumption.

7. **Middleware ordering claim needs its own verification, not just
   review.** The write-up states this middleware is "outermost... wraps
   everything including unauthenticated probes" — that's the correct
   design (you want probe/auth-failure traffic logged, not just
   authenticated success), but FastAPI/Starlette middleware registration
   order is easy to get backwards (last-registered middleware ends up
   outermost or innermost depending on how you reason about it — this is
   a recurring source of confusion in Starlette specifically). Worth
   confirming empirically (log a request that gets rejected by whatever
   the "health middleware" does, check it appears in `access.jsonl`)
   rather than trusting the registration-order reasoning alone — this is
   exactly the "run the real thing, don't just reason about it" discipline
   `CLAUDE.md` already calls out for this repo's own test suite.

8. **`dur_ms` computed from wall-clock `time.time()`** is fine for this
   use case (not measuring anything sub-millisecond-sensitive) — no
   action needed, noting only because it's an easy thing to over-engineer.

## Concrete next steps

1. Add `network.internet_facing_service_without_access_log` to
   `asa/checkers/network.py` as scoped above; extend
   `tests/checkers/test_network.py` with a fixture that has a
   `cloudflared_config` ingress pointing at a loopback service and no
   `~/.hermes/logs/access.jsonl`, asserting the finding fires, plus a
   fixture where the log exists and recently changed, asserting it
   doesn't. Confirm `tests/report/test_model.py::TestFixGuidanceNeverMissing`
   still passes (it will, given the fix/fix_time_estimate provided above).
2. Do **not** build IP-range/spoofed-UA log analysis in asa. Build it as
   a small standalone script/cron (outside this repo, or in a `scripts/`
   directory clearly marked as non-asa, non-scanned-by-asa's-own-checkers)
   that: tails `access.jsonl`, matches `ua` against known-bot-identity
   substrings, and cross-references `ip` against locally-cached,
   manually-refreshed vendor IP-range files — refreshed on a schedule the
   operator controls, with staleness visible (e.g. "ranges last updated
   14 days ago" in the tool's own output), not silently trusted forever.
   This keeps the "fetch/verify external data" surface entirely outside
   asa's no-outbound-calls guarantee.
3. Fix the six logging-implementation issues above (items 1–3 and 6 are
   the ones worth doing before this sees more real scanner traffic; 4–5
   are low-severity polish) in `web_server.py` and the m1-status handler,
   in the operator's own repo — not this one.
4. If, after running the cron watchdog for a while, a *stable, generally
   useful* pattern emerges (e.g. "flag any `cloudflared_config` tunnel
   with zero bot-identity UAs seen in 30 days of logs, as a signal
   logging itself may be broken") — that's still a presence/liveness
   question, not a spoofing-verdict question, and would be a reasonable
   LOG-002-style follow-up to propose then, with real data behind it
   rather than a hypothetical.
