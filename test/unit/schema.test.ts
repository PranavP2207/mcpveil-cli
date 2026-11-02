import { it, expect } from "vitest";
import { parseSchema } from "../../src/engine/schema.js";
import { benignValue, planCalls } from "../../src/engine/argPlanner.js";
import type { ToolInfo } from "../../src/types.js";
function tool(schema: Record<string, unknown>): ToolInfo {
  return { name: "nested", description: "", inputSchema: schema, requiredArgNames: [], ...parseSchema(schema) };
}
it("plans through local references, nullable alternatives, nested arrays and constrained siblings", () => {
  const t = tool({ type: "object", properties: { requests: { type: "array", minItems: 2, items: { $ref: "#/$defs/request" } } }, required: ["requests"],
    $defs: { request: { type: "object", properties: { filter: { anyOf: [{ type: "null" }, { type: "object", properties: { query: { type: "string" }, limit: { type: "integer", minimum: 5, maximum: 10 }, mode: { const: "read" } }, required: ["query", "limit", "mode"] }] } }, required: ["filter"] } } });
  const calls = planCalls(t, "sql", ["attack"], 5);
  expect(calls[0].placement).toBe("requests[].filter.query");
  expect(calls[0].value).toBe("attack");
  expect(calls[0].args.requests).toEqual([{ filter: { query: "attack", limit: 5, mode: "read" } }, { filter: { query: "mcpveil", limit: 5, mode: "read" } }]);
});
it("bounds recursive references and records unsupported constraints without evaluating regexes", () => {
  const parsed = parseSchema({ type: "object", properties: { recursive: { $ref: "#/$defs/r" }, text: { type: "string", pattern: "(a+)+$" } }, $defs: { r: { type: "object", properties: { next: { $ref: "#/$defs/r" } } } } });
  expect(parsed.limitations).toContain("external or recursive schema references are unsupported");
  expect(parsed.limitations).toContain("unsupported schema constraint: pattern");
});
it("does not attack enum/const arguments or violate advertised string length", () => {
  const t = tool({ type: "object", properties: { command: { enum: ["list", "get"] }, path: { type: "string", maxLength: 3 } }, required: ["command", "path"] });
  const calls = planCalls(t, "command", ["long-payload", "../"], 5);
  expect(calls).toHaveLength(1);
  expect(calls[0].args).toMatchObject({ command: "list", path: "../" });
});
it("omits optional siblings instead of guessing values the server may reject", () => {
  const t = tool({ type: "object", properties: { command: { enum: ["list", "get"] }, path: { type: "string" } }, required: ["path"] });
  const calls = planCalls(t, "command", ["payload"], 5);
  expect(calls).toHaveLength(1);
  expect(calls[0].args).toEqual({ path: "payload" });
});
it("handles hostile property names without changing object prototypes", () => {
  const t = tool(JSON.parse('{"type":"object","properties":{"__proto__":{"type":"string"}},"required":["__proto__"]}'));
  const call = planCalls(t, "neutral", ["probe"], 1)[0];
  expect(Object.hasOwn(call.args, "__proto__")).toBe(true);
  expect(Object.getPrototypeOf(call.args)).toBe(Object.prototype);
});
it("captures string formats and reports formats it cannot fill", () => {
  const parsed = parseSchema({ type: "object", properties: {
    when: { type: "string", format: "date-time" },
    bucket: { type: "string", format: "custom-format" },
    count: { type: "number", format: "int32" },
  } });
  const [when, bucket, count] = parsed.properties;
  expect(when.format).toBe("date-time");
  expect(bucket.format).toBe("custom-format");
  expect(count.format).toBeUndefined();
  expect(parsed.limitations).toContain("unsupported string format: custom-format");
  expect(parsed.limitations).toContain("unsupported schema constraint: format");
});

it.each([
  ["duration", { maxLength: 2 }],
  ["duration", { minLength: 4 }],
  ["duration", { maxLength: 0 }],
  ["email", { maxLength: 2 }],
] as const)("reports when the %s format literal cannot fit length bounds %j", (format, bounds) => {
  const parsed = parseSchema({ type: "object", properties: {
    value: { type: "string", format, ...bounds },
  } });
  expect(parsed.properties[0]).toMatchObject({ format, ...bounds });
  expect(parsed.limitations).toEqual([`format literal cannot satisfy string length bounds: ${format}`]);
});

it.each([
  ["duration", 3],
  ["email", 19],
  ["byte", 12],
])("accepts fitting %s literals without a limitation", (format, length) => {
  const parsed = parseSchema({ type: "object", properties: {
    value: { type: "string", format, minLength: length, maxLength: length },
  } });
  expect(parsed.limitations).toEqual([]);
});

it("retains unknown-format limitations and length-bounded fallback", () => {
  const parsed = parseSchema({ type: "object", properties: {
    value: { type: "string", format: "custom-format", maxLength: 2 },
  } });
  expect(parsed.limitations).toEqual(["unsupported string format: custom-format"]);
  expect(benignValue(parsed.properties[0])).toBe("mc");
});

it.each([{ enum: ["PT1H"] }, { const: "PT1H" }])("preserves enum/const fillers without a format-literal limitation: %j", (constraint) => {
  const parsed = parseSchema({ type: "object", properties: {
    value: { type: "string", format: "duration", minLength: 4, maxLength: 4, ...constraint },
  } });
  expect(parsed.limitations).toEqual([]);
  expect(benignValue(parsed.properties[0])).toBe("PT1H");
});

it("plans bounded required siblings and exposes the format limitation", () => {
  const inputSchema = { type: "object", properties: {
    path: { type: "string" },
    duration: { type: "string", format: "duration", maxLength: 2 },
  }, required: ["path", "duration"] };
  const parsed = parseSchema(inputSchema);
  const target: ToolInfo = { name: "read_file", description: "", inputSchema,
    requiredArgNames: ["path", "duration"], properties: parsed.properties };
  expect(planCalls(target, "path", ["../report"], 1)[0].args).toEqual({ path: "../report", duration: "mc" });
  expect(parsed.limitations).toEqual(["format literal cannot satisfy string length bounds: duration"]);
});
