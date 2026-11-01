# Changelog

## Unreleased

- Add format-valid benign fillers for `duration`, `byte`, `regex`,
  `json-pointer`, `uri-reference`, `uri-template`, `idn-email`, and `iri`
  so required sibling arguments can satisfy server-side format validation.

## 0.5.0

Compatibility: report schema stays `2.0` and this entry is additive-only —
new `coverage.probeFailures` and per-check `CheckResult.probeFailures` fields.
Exit codes are unchanged.

- Probe calls no longer auto-fill optional arguments. Args are built from
  required siblings plus the attacked argument, so servers that reject
  combinations such as `head`+`tail` (the official filesystem server) accept
  the probe instead of rejecting it outright. The SQL benign baseline uses the
  same required-only shape.
- Benign fillers are format- and enum-aware for strings: `date`, `date-time`,
  `time`, `email`, `uri`/`url`, `uuid`, `ipv4`, `ipv6` and `hostname` formats
  are captured from schemas and filled with valid literals; unknown formats
  are surfaced as coverage limitations instead of risking rejected probes.
- Per-probe transport failures (timeouts, resets) are counted in
  `CheckResult.probeFailures` and `coverage.probeFailures` instead of scan
  `errors`. A single dropped probe — for example a link-local-blackholed
  `169.254.169.254` SSRF probe — no longer flips an otherwise healthy scan to
  `partial`/exit 2. Honesty is preserved: a check whose every tool probe
  failed reports `"<check>: all N probes failed"`, and a tool whose every
  probe across all checks failed is listed in `coverage.untestedTools` with a
  limitation, still yielding `partial` for genuinely untestable tools.
- `prompts/get` protocol validation errors map to coverage skips (rejected)
  like resource reads, instead of scan errors.
- The accuracy harness is environment-independent: it passes on networks
  where link-local metadata addresses blackhole, verified twice for
  determinism, plus a new hanging-fixture e2e proving timeouts are counted
  without failing the assessment.

## 0.4.1

- Stage a production-only manifest and shrinkwrap before release packing. Normal npm installs no longer receive extraneous development tools or legacy server dependencies.
- Verify a normal clean consumer install with `npm ls --all`, retaining CLI/API/Action smoke checks. The contributor lockfile remains unchanged by packaging.

## 0.4.0

- Official stable SDK v2 client with explicit modern `2026-07-28`, auto and legacy modes; v1 retained only in compatibility fixtures.
- Bearer/custom-header credentials via environment names; HTTPS credential policy, redirect/cross-origin denial, bounded HTTP/stdio messages, precise legacy fallback.
- Optional required-auth and Origin admission probes with explicit verdicts; detection and masking of supplied opaque credentials.
- Expiring target-scoped finding baselines, hashed tool drift snapshots, reusable GitHub Action and team CI examples.
- Additional adversarial fixtures for malformed/duplicate/oversized inventories, recursive schemas, oversized content and authorization failures.


## 0.3.0

- Bounded recursive argument planning with local references and required constrained siblings; nested SQL/SSRF payload handling corrected.
- Setup diagnostics (`doctor`), measured call latency, readable grouped terminal reports and stable signal fingerprints.
- Ten-case executable accuracy corpus and a real CLI recording replace the simulated demonstration.
- Windows/macOS compatibility CI, and release validation separated from the minimal OIDC publisher job.


## 0.2.0

Compatibility: requires Node >=22.12.0. Report schema 2.0 introduces explicit
assessment status/coverage and nullable scores for incomplete or metadata-only
scans. Stdio credentials now require explicit forwarding.

- Enforce inventory-only mode, tool exclusions, shared call budgets including
  baselines, inventory limits, per-request cancellation and an overall deadline.
- Remove destructive SQL probes; confirm SQL with paired read-only controls and
  command execution with encoded markers resistant to reflected input.
- Sanitize report evidence, target arguments, URLs, supplied credentials and
  buffered target stderr. Isolate the child HOME and restrict inherited env.
- Return execution failure for incomplete assessments and mark SARIF failure
  correctly; report structured-output and metadata coverage honestly.
- Fix CLI validation, config precedence, usage exits, resource/prompt/server
  metadata inspection, API examples and exported report renderers.
- Add independent security regressions and local HTTP/SSE/fallback coverage;
  verify supported runtime installs and clear rejection of Node 18/20.
