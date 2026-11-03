#!/usr/bin/env node
import { createBaseline, applyBaseline, validateBaselineTarget, targetScope, loadBaseline, loadSnapshot, readArtifact } from "./policy.js";
import { Command, Option, InvalidArgumentError, CommanderError } from "commander";
import { writeFileSync } from "node:fs";
import { loadConfig, validateConfig, CHECK_IDS } from "./config/loader.js";
import { connect } from "./transports/factory.js";
import { runScan, failureReport } from "./engine/scanner.js";
import { renderTerminal } from "./report/terminal.js";
import { renderJson } from "./report/json.js";
import { renderSarif } from "./report/sarif.js";
import type { ScanTarget, TransportKind, Severity, ForgeConfig, ScanReport } from "./types.js";
import { log } from "./utils/logger.js";
import { redactText } from "./utils/redact.js";
import { resolveHeaders, validateEndpoint } from "./transports/http.js";
import { doctor } from "./doctor.js";
import { VERSION } from "./version.js";

export const EXIT = { CLEAN: 0, POLICY_FAIL: 1, SCAN_FAIL: 2, USAGE: 3 } as const;
const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
class UsageError extends Error {}
interface CliOpts {
  authPolicy?: "required" | "public"; checkOrigin?: boolean;
  baseline?: string; targetId?: string; snapshot?: string; writeSnapshot?: string;
  bearerEnv?: string; headerEnv?: string[]; protocol?: "legacy" | "auto" | "2026-07-28";
  stdio?: string; url?: string; transport?: TransportKind; config?: string;
  format?: "terminal" | "json" | "sarif"; output?: string; failOn?: Severity | "never";
  timeout?: number; scanTimeout?: number; maxCallsPerTool?: number;
  allowTool?: string[]; skipCheck?: string[]; env?: string[]; inventoryOnly?: boolean; yes?: boolean;
}
function integer(min: number, max: number) {
  return (input: string) => {
    if (!/^\d+$/.test(input) || !Number.isSafeInteger(Number(input)) || Number(input) < min || Number(input) > max) {
      throw new InvalidArgumentError(`must be an integer between ${min} and ${max}`);
    }
    return Number(input);
  };
}
const program = new Command().name("mcpveil")
  .description("Local security regression tests for MCP servers.").version(VERSION).exitOverride()
  .configureOutput({ writeErr: (text) => process.stderr.write(redactText(text)), writeOut: (text) => process.stdout.write(redactText(text)) });

program.command("doctor").description("Check setup without starting or contacting a target")
  .option("-c, --config <path>", "validate a configuration")
  .option("--env <name>", "check required variable presence without displaying values", (v: string, previous: string[]) => [...previous, v], [])
  .option("--json", "machine-readable diagnostics")
  .action((opts) => {
    try {
      const result = doctor(opts.config, opts.env);
      console.log(opts.json ? JSON.stringify(result, null, 2) : `MCPVeil ${result.version} · Node ${result.node} · ${result.platform}/${result.architecture}\nSetup: ${result.status} · configuration: valid\n${result.isolation}\n${result.missingEnv.length ? `Missing variables: ${result.missingEnv.join(", ")}` : result.next}`);
      process.exitCode = result.status === "ready" ? 0 : 3;
    } catch (err) { log.error(err instanceof Error ? err.message : String(err)); process.exitCode = 3; }
  });

program.command("baseline").description("Reviewable expiring finding acceptance")
  .command("create").requiredOption("--report <path>", "complete active JSON report")
  .requiredOption("--target-id <id>", "logical server and authorization context")
  .requiredOption("--reason <reason>", "review justification")
  .requiredOption("--expires <iso-date>", "ISO 8601 expiration")
  .requiredOption("-o, --output <path>", "baseline destination")
  .action((opts) => {
    try { writeFileSync(opts.output, JSON.stringify(createBaseline(readArtifact(opts.report) as ScanReport, opts.targetId, opts.reason, opts.expires), null, 2) + "\n", { mode: 0o600 }); }
    catch (err) { log.error(err instanceof Error ? err.message : String(err)); process.exitCode = EXIT.USAGE; }
  });

for (const commandName of ["scan", "inspect"] as const) program.command(commandName)
  .description(commandName === "inspect"
    ? "Inspect metadata only: zero tools/call, resources/read, or prompts/get requests"
    : "Scan an explicitly authorized MCP server")
  .option("--stdio <command>", "launch an exact command through stdio (no shell)")
  .option("--url <url>", "HTTP target, with legacy SSE fallback")
  .addOption(new Option("--transport <kind>", "force a transport").choices(["stdio", "streamable-http", "sse"]))
  .addOption(new Option("--auth-policy <policy>", "explicit HTTP deployment expectation").choices(["required", "public"]))
  .option("--check-origin", "test rejection of an untrusted HTTP Origin")
  .option("--baseline <path>", "apply an expiring target-scoped reviewed baseline")
  .option("--target-id <id>", "logical server and authorization context for policy artifacts")
  .option("--snapshot <path>", "compare hashed tool descriptions/schemas; drift exits 1")
  .option("--write-snapshot <path>", "save hashed tools from complete inventory")
  .option("--bearer-env <name>", "HTTP bearer token read from an environment variable")
  .option("--header-env <header=variable>", "HTTP header read from an environment variable (repeatable)", (v: string, previous: string[]) => [...previous, v], [])
  .addOption(new Option("--protocol <mode>", "legacy, explicit negotiation, or pinned modern protocol").choices(["legacy", "auto", "2026-07-28"]))
  .option("-c, --config <path>", "JSON configuration")
  .addOption(new Option("--format <format>", "report format").choices(["terminal", "json", "sarif"]))
  .option("-o, --output <path>", "report destination")
  .addOption(new Option("--fail-on <severity>", "policy failure threshold").choices([...SEVERITIES, "never"]))
  .option("--timeout <ms>", "per-request timeout, including inventory", integer(1000, 120000))
  .option("--scan-timeout <ms>", "overall assessment deadline", integer(1000, 3600000))
  .option("--max-calls-per-tool <count>", "shared budget across all checks, including baselines", integer(1, 200))
  .option("--allow-tool <name...>", "exclude tools from active calls (static metadata is still inspected)")
  .option("--skip-check <id...>", "disable named checks")
  .option("--env <name>", "explicitly forward one environment variable (repeatable)", (value: string, previous: string[]) => [...previous, value], [])
  .option("--inventory-only", "metadata only: zero tools/call, resources/read, or prompts/get requests")
  .option("--ci", "explicit non-interactive mode (--yes still required)")
  .option("--yes", "authorize launching/contacting this target and the selected scan mode")
  .action(async (opts: CliOpts) => {
    try { process.exitCode = await scanAction({ ...opts, inventoryOnly: commandName === "inspect" || opts.inventoryOnly }); }
    catch (err) { log.error(err instanceof Error ? err.message : String(err)); process.exitCode = err instanceof UsageError ? EXIT.USAGE : EXIT.SCAN_FAIL; }
  });

async function scanAction(opts: CliOpts): Promise<number> {
  if (Boolean(opts.stdio) === Boolean(opts.url)) throw new UsageError("provide exactly one of --stdio or --url");
  if ((opts.stdio && opts.transport && opts.transport !== "stdio") || (opts.url && opts.transport === "stdio")) {
    throw new UsageError("transport must match the selected stdio or URL target");
  }
  let baseline; let snapshot;
  try {
    baseline = opts.baseline ? loadBaseline(opts.baseline) : undefined;
    snapshot = opts.snapshot ? loadSnapshot(opts.snapshot) : undefined;
    if ((baseline || snapshot || opts.writeSnapshot) && !opts.targetId?.trim()) throw new Error("--target-id is required for baselines and tool snapshots");
  } catch (err) { throw new UsageError(err instanceof Error ? err.message : String(err)); }
  let config: ForgeConfig;
  try {
    config = loadConfig(opts.config);
    if (opts.format !== undefined) config.output.format = opts.format;
    if (opts.output !== undefined) config.output.path = opts.output;
    if (opts.failOn !== undefined) config.failOn = opts.failOn;
    if (opts.timeout !== undefined) config.timeoutMs = opts.timeout;
    if (opts.scanTimeout !== undefined) config.scanTimeoutMs = opts.scanTimeout;
    if (opts.maxCallsPerTool !== undefined) config.maxCallsPerTool = opts.maxCallsPerTool;
    config.allowTools.push(...(opts.allowTool ?? []));
    for (const id of opts.skipCheck ?? []) {
      if (!(CHECK_IDS as readonly string[]).includes(id)) throw new UsageError(`unknown check: ${id}`);
      config.checks[id as keyof typeof config.checks] = false;
    }
    config = validateConfig(config);
  } catch (err) { throw new UsageError(`invalid configuration: ${err instanceof Error ? err.message : String(err)}`); }
  const inheritEnv = opts.env ?? [];
  for (const key of inheritEnv) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || process.env[key] === undefined) throw new UsageError(`environment variable unavailable or invalid: ${key}`);
  }
  let target: ScanTarget;
  if (opts.stdio && (opts.bearerEnv || opts.headerEnv?.length || opts.authPolicy || opts.checkOrigin)) throw new UsageError("HTTP credentials require --url");
  if (opts.transport === "sse" && opts.protocol && opts.protocol !== "legacy") throw new UsageError("legacy SSE requires --protocol legacy");
  if (opts.stdio) {
    const command = shellSplit(opts.stdio);
    if (!command[0]) throw new UsageError("stdio command is empty");
    target = { kind: "stdio", command, inheritEnv };
  } else {
    let url: URL;
    try { url = new URL(opts.url!); } catch { throw new UsageError("target URL must be a valid HTTP(S) URL"); }
    if (!["https:", "http:"].includes(url.protocol) || url.username || url.password) throw new UsageError("use an HTTP(S) URL without embedded credentials");
    target = { kind: opts.transport === "sse" ? "sse" : "streamable-http", url: url.href };
  }
  target.protocolMode = opts.protocol ?? "legacy";
  if (opts.url) {
    target.authPolicy = opts.authPolicy; target.auditOrigin = opts.checkOrigin;
    target.bearerEnv = opts.bearerEnv;
    target.headerEnv = Object.fromEntries((opts.headerEnv ?? []).map((pair) => {
      const match = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+)=([A-Za-z_][A-Za-z0-9_]*)$/.exec(pair);
      if (!match) throw new UsageError("--header-env requires Header-Name=ENV_NAME");
      return [match[1]!, match[2]!];
    }));
    try { validateEndpoint(new URL(target.url!), [...resolveHeaders(target)].length > 0); }
    catch (err) { throw new UsageError(err instanceof Error ? err.message : String(err)); }
  }
  try {
    if (baseline) validateBaselineTarget(baseline, target, opts.targetId!);
    if (snapshot && snapshot.targetScope !== targetScope(target, opts.targetId!)) throw new Error("tool snapshot target scope mismatch");
  } catch (err) { throw new UsageError(err instanceof Error ? err.message : String(err)); }
  if (!opts.yes) throw new UsageError("Use --yes to authorize this target. Stdio targets execute server code even in inventory-only mode; isolate untrusted servers.");
  let report: ScanReport;
  let session;
  const signal = AbortSignal.timeout(config.scanTimeoutMs);
  try { session = await connect(target, { timeoutMs: config.timeoutMs, signal }); }
  catch (err) {
    report = failureReport(target, `connection failed: ${err instanceof Error ? err.message : String(err)}`, !opts.inventoryOnly);
    output(report, config); return EXIT.SCAN_FAIL;
  }
  try {
    report = await runScan(session, target, config, { active: !opts.inventoryOnly, signal, targetId: opts.targetId, snapshot, writeSnapshot: opts.writeSnapshot });
    if (baseline) {
      try { report = applyBaseline(report, baseline, opts.targetId!); }
      catch (err) { throw new UsageError(err instanceof Error ? err.message : String(err)); }
    }
    output(report, config);
    if (report.status !== "complete") return EXIT.SCAN_FAIL;
    if (report.policy?.drift && Object.values(report.policy.drift).some((items) => items.length)) return EXIT.POLICY_FAIL;
    if (config.failOn === "never") return EXIT.CLEAN;
    const threshold = SEVERITIES.indexOf(config.failOn);
    return report.findings.some((finding) => finding.baselineState !== "accepted" && SEVERITIES.indexOf(finding.severity) >= threshold) ? EXIT.POLICY_FAIL : EXIT.CLEAN;
  } finally { await session.close().catch(() => {}); }
}

function output(report: ScanReport, config: ForgeConfig): void {
  const rendered = config.output.format === "json" ? renderJson(report) : config.output.format === "sarif" ? renderSarif(report) : renderTerminal(report);
  if (config.output.path) {
    writeFileSync(config.output.path, rendered, "utf8"); log.info(`report written to ${config.output.path}`);
  } else console.log(rendered);
}

/** Quoted argv parsing only. No expansion or shell evaluation. */
function shellSplit(input: string): string[] {
  const out: string[] = [];
  let current = ""; let quote = ""; let started = false;
  for (let index = 0; index < input.length; index++) {
    const char = input[index]!;
    if (quote) {
      if (char === quote) { quote = ""; continue; }
      if (char === "\\" && quote === '"' && ['"', "\\"].includes(input[index + 1] ?? "")) { current += input[++index]; continue; }
      current += char;
    } else if (char === '"' || char === "'") { quote = char; started = true; }
    else if (/\s/.test(char)) { if (started) { out.push(current); current = ""; started = false; } }
    else if (char === "\\" && /[\s"'\\]/.test(input[index + 1] ?? "")) { current += input[++index]; started = true; }
    else { current += char; started = true; }
  }
  if (quote) throw new UsageError("unclosed quote in stdio command");
  if (started) out.push(current);
  return out;
}

if (process.argv.length <= 2) program.outputHelp();
else program.parseAsync(process.argv).catch((err: unknown) => {
  if (err instanceof CommanderError) process.exitCode = err.exitCode === 0 ? EXIT.CLEAN : EXIT.USAGE;
  else { log.error(err instanceof Error ? err.message : String(err)); process.exitCode = EXIT.USAGE; }
});
