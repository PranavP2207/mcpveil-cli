import { it, expect } from "vitest";
import { parseSchema } from "../../src/engine/schema.js";
import { planCalls } from "../../src/engine/argPlanner.js";
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
