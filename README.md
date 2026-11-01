<p align="center">
  <img src="assets/logo.svg" width="110" alt="MCPVeil logo — a shield with an active scan beam" />
</p>

# MCPVeil

**Local security regression tests for Model Context Protocol servers.**

MCPVeil connects to a real MCP server, inventories its metadata, and runs
bounded security probes. It produces evidence, explicit coverage and completion
status, JSON/SARIF reports, and exit codes for CI. Analysis runs locally without
an LLM or analysis-service API key.

[![npm](https://img.shields.io/npm/v/mcpveil-cli)](https://www.npmjs.com/package/mcpveil-cli)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Node](https://img.shields.io/badge/Node-22.12%2B%20%7C%2024-green)](package.json)

[CI](.github/workflows/ci.yml) · [Security](SECURITY.md) · [Release guide](docs/npm-release.md)

## Install and scan

Use **Node >=22.12.0**; Node 22 and 24 LTS are tested. Node 18/20 are unsupported.

```bash
npm install --global mcpveil-cli
mcpveil doctor
mcpveil --version

# Inventory metadata: no tools/call, resources/read, or prompts/get requests.
mcpveil scan --stdio "node path/to/server.js" --inventory-only --yes

# Active testing of your own disposable test server.
mcpveil scan --stdio "node path/to/server.js" --yes

# Streamable HTTP, with legacy SSE fallback when needed.
mcpveil scan --url http://127.0.0.1:8123/mcp --yes
```

Only contact servers you own or are authorized to test. **Stdio starts server
code even in inventory-only mode.** Active tool calls can have side effects;
use disposable test data and isolate untrusted servers in a container or VM.
An isolated child HOME and filtered environment do not create a filesystem
sandbox. See [safe local testing](docs/sandbox.md).

## Real CLI demonstration

![Real MCPVeil CLI: setup, safe echo server, and vulnerable SQLite](assets/demo.gif)

Recorded from actual isolated CLI runs with synthetic data. The [recording](assets/demo.cast)
and [capture script](scripts/record-demo.py) are reproducible; no real credentials are used.

## What it checks

| Check | Evidence and limits |
|---|---|
| Path traversal | Canary or recognizable file contents returned by crafted paths/resources |
| Command injection | Decoded marker on an output line; marker bytes are encoded in the POSIX probes to resist input reflection |
| SQL injection | Paired read-only true/false conditions compared with a benign baseline; SQL error text is suspicious rather than confirmed |
| SSRF | Response markers from loopback, metadata, or file targets; blind out-of-band callbacks are not verified |
| Credential exposure | Secret-shaped data in metadata, resource/prompt contents, and textual or structured tool responses |
| HTTP access policy | Optional required-auth and untrusted-Origin connection/discovery probes; public endpoints are not automatically labeled insecure |
| Prompt injection | Known override phrases and invisible Unicode in tool/schema metadata, resources, prompts, and server instructions |

These are bounded checks, not a proof that a server or an agent is secure.
Prompt-injection heuristics do not establish whether an LLM will follow an
instruction. A credential-shaped match does not validate that a credential is
live. Unsupported schemas, exhausted budgets, truncation, and operational
failures are reported as assessment limitations or failed-probe counts.

## Reports and CI

```bash
mcpveil scan --stdio "node test-server.js" --yes --format json -o report.json
mcpveil scan --stdio "node test-server.js" --yes --format sarif -o report.sarif
```

Use `--ci` to explicitly select non-interactive scanning in pipelines. It
preserves the same report formats and exit-code policy and still requires
`--yes` to authorize the target:

```bash
mcpveil scan --stdio "node test-server.js" --ci --yes --format sarif -o report.sarif
```

| Exit | Meaning |
|---|---|
| 0 | Completed requested assessment; no finding exceeds the configured threshold |
| 1 | Completed assessment with a policy-breaking finding |
| 2 | Failed or partial assessment, including an overall deadline or a check/tool whose every probe failed |
| 3 | Invalid arguments/configuration, unsupported runtime, or missing consent |

`--fail-on never` disables finding-based failures; it does **not** turn a failed
or incomplete scan into success. Reports include `schemaVersion`, `status`,
`mode`, errors, excluded/untested tools, call counts, failed-probe counts
(`coverage.probeFailures` and per-check `probeFailures`), measured p50/p95
tool-request latency and limitations. Terminal output groups related signals;
JSON and SARIF retain individual findings and remediation. Incomplete
and metadata-only scans have `score: null`; they are not assigned a security
grade. SARIF sets `executionSuccessful: false` for incomplete assessments.

A single probe timing out or being reset is not a scan error: it is counted in
`coverage.probeFailures` (per tool name, resource URI, or prompt label) and the
assessment stays `complete` when other probes of the same check and tool
succeed. Escalation stays honest — a check reports `"<check>: all N probes
failed"` when every one of its tool probes failed, and a tool whose every probe
failed across all checks is listed in `coverage.untestedTools` with a
limitation, yielding a `partial` assessment for a genuinely untestable tool.
Server rejections of probes (unknown resource/prompt, invalid arguments) are
coverage skips, not failures.

Reports and scanner/target error output are sanitized, including secret-shaped
excerpts, supplied credentials, sensitive command flags, and URL credentials.
Inspect reports before sharing them: arbitrary application data can still be
private without resembling a credential.

## Configuration

Pass `--config mcpveil.config.json` explicitly. Precedence is **explicit CLI
flags > config file > defaults**. Unknown keys and check names are rejected.

```json
{
  "checks": { "ssrf": true, "prompt-injection": true },
  "failOn": "high",
  "timeoutMs": 10000,
  "scanTimeoutMs": 120000,
  "maxCallsPerTool": 128,
  "allowTools": ["create_*", "delete_*"],
  "output": { "format": "json" }
}
```

`maxCallsPerTool` is one shared budget across checks **including benign
baselines**. The allowed range is 1–200. Exhaustion is visible and produces a
partial result. `allowTools` / `--allow-tool` exclude active calls; static
metadata inspection and the true inventory count are retained. A trailing `*`
matches a tool-name prefix.

The default per-request timeout is 10 seconds and the overall deadline is two
minutes. Inventory pagination and content requests are bounded. Timeouts use
SDK cancellation; a target may already have performed work before cancellation.

Stdio targets receive a temporary HOME and a small runtime environment.
Credentials are not inherited implicitly. Forward required variables by name:

```bash
mcpveil scan --stdio "node test-server.js" --env TEST_SERVICE_TOKEN --yes
```

`--env` is repeatable. Use restricted test credentials. `--inventory-only` still
needs `--yes`, and CI does not bypass consent automatically. Run
`mcpveil doctor --config mcpveil.config.json --env TEST_SERVICE_TOKEN` to validate
setup and variable availability without contacting a target. Values are never
displayed. `mcpveil doctor --json` supports automation. Run `mcpveil scan --help` for all supported flags.

## Programmatic API

```js
import { writeFileSync } from "node:fs";
import { connect, runScan, defaultConfig, renderSarif } from "mcpveil-cli";

const target = { kind: "stdio", command: ["node", "path/to/test-server.js"] };
const config = defaultConfig();
const session = await connect(target, { timeoutMs: config.timeoutMs });
try {
  const report = await runScan(session, target, config);
  writeFileSync("report.sarif", renderSarif(report));
  if (report.status !== "complete") throw new Error("Assessment incomplete");
} finally {
  await session.close();
}
```

Pass the **session**, not `session.client`, to `runScan`. The entry point exports
the scanner, connection/inventory/config helpers, and JSON/SARIF/terminal
renderers. API callers authorize their own target connections and should use
the same isolation and credential restrictions as CLI users.

## Test the project

```bash
npm ci
npm run lint
npm test
npm run test:package
# Produce a production-only tarball for manual inspection:
npm run pack:release
# Run synthetic targets in the disposable sandbox described above:
npm run benchmark -- docs/benchmark.json
```

The suite includes safe and deliberately vulnerable reference servers, real
SQLite side-effect controls, independent reflection/normalization controls,
timeouts and failure status, redaction, budgets, strict CLI policy, and HTTP/SSE
transport tests. Reference-fixture coverage and determinism are CI gates; they
are not general precision/recall percentages. Test servers stay outside the npm
distribution. [Contributing](CONTRIBUTING.md) describes the fixtures and rules.

The [labeled benchmark](docs/benchmark.json) records ten independent synthetic
cases, their expected/detected checks, request counts and measured timings. These
include echo/normalization/search controls, structured credentials, nested schemas,
metadata poisoning and a real SQLite differential. CI also checks Windows/macOS
on Node 22/24; the protected Linux 18/20 jobs verify explicit rejection.

Argument planning supports bounded nested objects/arrays, local references,
nullable alternatives, enum/const siblings, and common numeric/size constraints.
Probes send the attacked argument plus required siblings only — optional
arguments are never auto-filled, because servers may reject the combination —
and required string siblings are filled with format-valid values when the
schema declares `format` (date, date-time, email, uri, uuid, IPv4/IPv6,
hostname and friends). At most two ranked injectable leaves per check are
probed. The parser is bounded
to depth 12 and 512 nodes. External/recursive references, complex alternatives and
unsupported constraints (including regular expressions) are surfaced; arbitrary
server-provided regexes are never executed. Schema support does not imply exhaustive
JSON Schema coverage or that every generated request will be accepted.

## Compatibility and migration from 0.1.x

- Node >=22.12.0 is now required, matching runtime dependencies.
- Report schema 2.0 adds completion and coverage fields; `score` may be null.
- The default shared per-tool budget is 128. Existing smaller budgets may
  intentionally produce incomplete coverage.
- Explicit config thresholds are honored, and invalid options are rejected
  before contacting a target.
- Stdio credentials need explicit `--env` forwarding or API `target.env`.
- Keep report consumers aware of assessment status before interpreting a grade.

The official SDK v2 client supports legacy MCP and the modern `2026-07-28`
revision. Legacy negotiation remains the default for predictable CLI startup:

```bash
# Explicit discovery negotiation, including legacy fallback.
mcpveil scan --stdio "node test-server.js" --protocol auto --yes
# Require a modern server; a legacy-only server fails visibly.
mcpveil scan --url http://127.0.0.1:8123/mcp --protocol 2026-07-28 --yes
```

Auto negotiation may launch a disposable sibling stdio process to identify the
era. It can start target code twice. Modern multi-round-trip sampling/elicitation
is not fulfilled automatically; interactive outcomes remain incomplete. Scanner
requests validate protocol result shapes, while arbitrary server-provided JSON
output schemas are not compiled or used to execute regexes. This is a content
security scanner, not an output-contract validator. HTTP/SSE responses and stdio
messages are bounded to 2 MiB; captured content is capped at 20,000 characters.

## Authenticated HTTP

```bash
# Set these variables securely in your shell/CI secret store; do not put values in argv.
mcpveil scan --url https://mcp.example.invalid/mcp --yes \
  --bearer-env MCP_TEST_TOKEN --header-env X-Api-Key=MCP_TEST_API_KEY \
  --auth-policy required --check-origin --protocol auto
```

`--auth-policy required` checks anonymous and invalid-credential connection attempts.
`--auth-policy public` records an intentional deployment choice; absence of an auth
flag makes no authentication claim. `--check-origin` tests one untrusted Origin.
Access probes do not invoke tools. JSON/SARIF record accepted/rejected/unverified
verdicts. These checks cover connection/discovery admission, not per-tool roles,
OAuth issuer/audience/scope compliance, mTLS or identity-provider configuration.

Credentials are resolved by environment variable name and omitted from reports.
HTTP credentials require HTTPS, with a loopback exception for local fixtures.
Redirects and cross-origin SSE endpoints are blocked. Use the final endpoint URL.
Auth denials and server errors do not trigger a permissive legacy fallback.
API callers can set `target.bearerEnv`, `target.headerEnv`, or `target.headers`;
prefer environment names to reduce accidental credential persistence.

## Reviewed baselines and tool drift

```bash
mcpveil scan --stdio "node test-server.js" --yes --format json -o report.json
# Review the evidence first. Use an explicit future ISO timestamp.
mcpveil baseline create --report report.json --target-id staging-reader \
  --reason "Reviewed temporary exception" --expires "$(node -p 'new Date(Date.now()+7*86400000).toISOString()')" -o baseline.json
mcpveil scan --stdio "node test-server.js" --yes \
  --baseline baseline.json --target-id staging-reader

# Metadata-only tool snapshot; no tool invocations.
mcpveil scan --stdio "node test-server.js" --inventory-only --yes \
  --target-id staging-reader --write-snapshot tools.snapshot.json
mcpveil scan --stdio "node test-server.js" --inventory-only --yes \
  --target-id staging-reader --snapshot tools.snapshot.json
```

Keep baseline expirations short. Use a distinct target ID per server, deployment
and authorization context. Baselines bind to that ID and the exact command/URL;
changes require review. They retain all findings and the original risk score,
mark accepted signals, and gate on new ones. Severity/confidence changes cannot
reuse acceptance. Incomplete scans still exit 2. Expired/mismatched artifacts are
rejected before target startup. Baselines are local review artifacts, not signed
attestations; protect their review and storage in your repository.

Snapshots store SHA-256 hashes of tool names, descriptions and schemas. Tool
additions/removals/changes exit 1 even with `--fail-on never`. No description text
is stored, but hashes are change detectors, not encryption for low-entropy data.
They do not attest publisher identity or prevent a server changing after the scan.
See [team CI examples](docs/team-ci.md) and the reusable [GitHub Action](action.yml).

## Ecosystem and roadmap

[Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner),
[Snyk Agent Scan](https://github.com/snyk/agent-scan), and
[MCP Safety Scanner](https://github.com/leidosinc/McpSafetyScanner) have different
analysis and integration strengths. MCPVeil focuses on local, reproducible
server regression checks. See [ROADMAP.md](ROADMAP.md) for measured accuracy,
onboarding, authenticated transports, baselines and tool-drift work.

## License and security

[MIT](LICENSE). Report vulnerabilities privately through the repository's
Security tab; see [SECURITY.md](SECURITY.md). Do not post reports containing real
credentials or private application data.

Release tarballs use a staged production-only shrinkwrap; the development lock
remains intact for contributors. `npm run test:package` checks a normal consumer
install (without `--omit=dev`) and rejects extraneous/development dependencies.
