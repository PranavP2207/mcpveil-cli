import { afterEach, beforeEach, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ScanReport } from "../../src/types.js";

const CLI = join(process.cwd(), "dist/cli.js");
const FIXTURE = join(process.cwd(), "test/fixtures/security-cases.mjs");
const RUNTIME = process.env.MCPVEIL_TEST_NODE || process.execPath;
let root: string;

beforeEach(() => { root = mkdtempSync(join(tmpdir(), "mcpveil-inspect-")); });
afterEach(() => { rmSync(root, { recursive: true, force: true }); });

function scan(commandName: "scan" | "inspect", mode: string, options: readonly string[] = [], consent = true) {
  const command = [RUNTIME, FIXTURE, mode, join(root, "events.jsonl")].map((value) => JSON.stringify(value)).join(" ");
  const result = spawnSync(RUNTIME, [CLI, commandName, "--stdio", command, "--format", "json",
    ...(consent ? ["--yes"] : []), ...options], { encoding: "utf8", timeout: 25000 });
  if (result.error) throw result.error;
  return result;
}

it.each([
  ["echo", []],
  ["echo", ["--inventory-only"]],
  ["surfaces", []],
  ["surfaces", ["--inventory-only"]],
] as const)("inspect matches inventory mode for %s with options %j and zero body calls", (mode, options) => {
  const reference = scan("scan", mode, ["--inventory-only"]);
  const inspect = scan("inspect", mode, options);
  expect(reference.status, reference.stderr).toBe(0);
  expect(inspect.status, inspect.stderr).toBe(reference.status);
  const report = JSON.parse(inspect.stdout) as ScanReport;
  expect(report.mode).toBe("inventory");
  expect(report.status).toBe("complete");
  expect(report.inventorySizes).toEqual(mode === "echo"
    ? { tools: 1, resources: 0, prompts: 0 } : { tools: 0, resources: 1, prompts: 1 });
  expect(report.coverage.toolCalls).toEqual(mode === "echo" ? { lookup: 0 } : {});
  expect(report.coverage.resourceReads).toBe(0);
  expect(report.score).toBeNull();
  const events: { event: string }[] = readFileSync(join(root, "events.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  expect(events.filter(({ event }) => ["call", "read-resource", "get-prompt"].includes(event))).toHaveLength(0);
  const stableReport = (body: string) => JSON.parse(body, (key: string, value: unknown) =>
    key === "startedAt" ? "<timestamp>" : key === "durationMs" ? 0 : value);
  expect(stableReport(inspect.stdout)).toEqual(stableReport(reference.stdout));
});

it("inspect still requires --yes before starting the target", () => {
  const result = scan("inspect", "echo", [], false);
  expect(result.status, result.stderr).toBe(3);
  expect(result.stderr).toContain("Use --yes to authorize this target");
  expect(existsSync(join(root, "events.jsonl"))).toBe(false);
});

it("inspect preserves static findings and the configured failure threshold", () => {
  const reference = scan("scan", "poison", ["--inventory-only", "--fail-on", "low"]);
  const inspect = scan("inspect", "poison", ["--fail-on", "low"]);
  expect(reference.status, reference.stderr).toBe(1);
  expect(inspect.status, inspect.stderr).toBe(reference.status);
  const report = JSON.parse(inspect.stdout) as ScanReport;
  expect(report.findings).toEqual((JSON.parse(reference.stdout) as ScanReport).findings);
  expect(report.findings.some((finding) => finding.checkId === "prompt-injection")).toBe(true);
  expect(report.coverage.toolCalls).toEqual({ lookup: 0 });
  expect(report.score).toBeNull();
});

it("root and inspect help list the command and its zero-invocation guarantee", () => {
  for (const args of [["--help"], ["inspect", "--help"]]) {
    const result = spawnSync(RUNTIME, [CLI, ...args], { encoding: "utf8", timeout: 5000 });
    expect(result.status, result.stderr).toBe(0);
    const help = result.stdout.replace(/\s+/g, " ");
    expect(help).toContain("inspect [options]");
    expect(help).toContain("Inspect metadata only: zero tools/call, resources/read, or prompts/get requests");
  }
});
