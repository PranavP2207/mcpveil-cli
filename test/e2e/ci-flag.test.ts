import { afterEach, beforeEach, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = join(process.cwd(), "dist/cli.js");
const FIXTURE = join(process.cwd(), "test/fixtures/security-cases.mjs");
const RUNTIME = process.env.MCPVEIL_TEST_NODE || process.execPath;
let root: string;

beforeEach(() => { root = mkdtempSync(join(tmpdir(), "mcpveil-ci-flag-")); });
afterEach(() => { rmSync(root, { recursive: true, force: true }); });

function scan(mode: string, format: "json" | "sarif", options: string[] = [], consent = true) {
  const command = [RUNTIME, FIXTURE, mode, join(root, "events.jsonl")].map((value) => JSON.stringify(value)).join(" ");
  const result = spawnSync(RUNTIME, [CLI, "scan", "--stdio", command, "--format", format,
    ...(consent ? ["--yes"] : []), ...options], { encoding: "utf8", timeout: 25000 });
  if (result.error) throw result.error;
  return result;
}

it("--ci still requires --yes before starting the target", () => {
  const result = scan("echo", "json", ["--ci"], false);
  expect(result.status, result.stderr).toBe(3);
  expect(result.stderr).toContain("Use --yes to authorize this target");
  expect(existsSync(join(root, "events.jsonl"))).toBe(false);
});

it.each([
  ["echo", "json", 0],
  ["secret", "json", 1],
  ["echo", "sarif", 0],
  ["secret", "sarif", 1],
] as const)("--ci preserves %s findings and %s reports (exit %i)", (mode, format, exitCode) => {
  const reference = scan(mode, format);
  const ci = scan(mode, format, ["--ci"]);
  expect(reference.status, reference.stderr).toBe(exitCode);
  expect(ci.status, ci.stderr).toBe(reference.status);
  // Compare complete reports; only wall-clock timestamps and measured timings vary.
  const stableReport = (body: string) => JSON.parse(body, (key: string, value: unknown) => {
    if (["startedAt", "endTimeUtc"].includes(key)) return "<timestamp>";
    if (["durationMs", "p50", "p95"].includes(key)) return 0;
    return value;
  });
  expect(stableReport(ci.stdout)).toEqual(stableReport(reference.stdout));
});

it("scan help documents the valueless --ci flag and consent requirement", () => {
  const result = spawnSync(RUNTIME, [CLI, "scan", "--help"], { encoding: "utf8", timeout: 5000 });
  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout.replace(/\s+/g, " ")).toContain("--ci explicit non-interactive mode (--yes still required)");
});
