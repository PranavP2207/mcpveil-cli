// test/unit/argPlanner.test.ts
import { describe, it, expect } from "vitest";
import { classifyArg, planCalls, benignValue } from "../../src/engine/argPlanner.js";
import { isExcluded } from "../../src/engine/scanner.js";
import { parseSchema } from "../../src/engine/schema.js";
import type { ToolInfo } from "../../src/types.js";

it("allow-tool excludes exact names and prefix wildcards", () => {
  expect(isExcluded("create_issue", ["create_*", "delete_repo"])).toBe(true);
  expect(isExcluded("delete_repo", ["create_*", "delete_repo"])).toBe(true);
  expect(isExcluded("list_issues", ["create_*", "delete_repo"])).toBe(false);
  expect(isExcluded("list_issues", [])).toBe(false);
});

const tool: ToolInfo = {
  name: "read_file",
  description: "Read a file",
  inputSchema: {},
  properties: [
    { name: "path", type: "string", description: "file path", required: true },
    { name: "limit", type: "number", required: false },
  ],
  requiredArgNames: ["path"],
};

it("classifies path args", () => {
  expect(classifyArg(tool.properties[0])).toBe("path");
});

it("places payloads into the attacked arg and omits optional siblings", () => {
  const calls = planCalls(tool, "path", ["../x", "/etc/x"], 12);
  expect(calls.length).toBe(2);
  // Optional `limit` is never filled: official servers reject combinations
  // like head+tail, and a rejected probe tests nothing.
  expect(calls[0].args).toEqual({ path: "../x" });
});

it("fills required siblings with format-valid benign values", () => {
  const multi: ToolInfo = {
    name: "fetch_report",
    description: "Fetch a generated report",
    inputSchema: {},
    properties: [
      { name: "path", type: "string", description: "report file", required: true },
      { name: "since", type: "string", format: "date-time", required: true },
      { name: "contact", type: "string", format: "email", required: true },
      { name: "retries", type: "integer", minimum: 2, required: true },
    ],
    requiredArgNames: ["path", "since", "contact", "retries"],
  };
  const [call] = planCalls(multi, "path", ["../x"], 3);
  expect(call.args).toEqual({
    path: "../x",
    since: "2026-01-01T00:00:00Z",
    contact: "mcpveil@example.com",
    retries: 2,
  });
});

it("benignValue satisfies known string formats", () => {
  for (const [format, value] of [
    ["date", "2026-01-01"],
    ["date-time", "2026-01-01T00:00:00Z"],
    ["time", "00:00:00Z"],
    ["email", "mcpveil@example.com"],
    ["uri", "https://mcpveil.example"],
    ["uuid", "00000000-0000-4000-8000-000000000000"],
    ["ipv4", "127.0.0.1"],
    ["ipv6", "::1"],
    ["hostname", "mcpveil.example"],
  ] as const) {
    expect(benignValue({ name: "v", type: "string", required: true, format })).toBe(value);
  }
  expect(benignValue({ name: "v", type: "string", required: true, format: "custom-format" })).toBe("mcpveil");
});

it.each([
  ["duration", "P1D"],
  ["byte", "bWNwdmVpbA=="],
  ["regex", "^mcpveil$"],
  ["json-pointer", "/a"],
  ["uri-reference", "/report"],
  ["uri-template", "/items/{id}"],
  ["idn-email", "mcpveil@example.com"],
  ["iri", "https://mcpveil.example"],
])("fills required %s siblings without schema limitations", (format, value) => {
  const inputSchema = { type: "object", properties: {
    path: { type: "string" },
    value: { type: "string", format },
  }, required: ["path", "value"] };
  const parsed = parseSchema(inputSchema);
  expect(parsed.limitations).toEqual([]);
  expect(benignValue(parsed.properties[1]!)).toBe(value);
  const formatted: ToolInfo = {
    name: "read_file", description: "Read a file", inputSchema,
    properties: parsed.properties, requiredArgNames: ["path", "value"],
  };
  const [call] = planCalls(formatted, "path", ["../report"], 1);
  expect(call?.args).toEqual({ path: "../report", value });
});

it("caps calls at maxCalls", () => {
  const many = Array.from({ length: 30 }, (_, i) => `p${i}`);
  expect(planCalls(tool, "path", many, 12).length).toBeLessThanOrEqual(12);
});

describe("nested schema planning (real-world array/object tools)", () => {
  // exactly the @modelcontextprotocol/server-memory shape
  const createEntities: ToolInfo = {
    name: "create_entities",
    description: "Create multiple new entities in the knowledge graph",
    inputSchema: {},
    properties: [
      {
        name: "entities",
        type: "array",
        required: true,
        items: {
          name: "(item)",
          type: "object",
          required: false,
          properties: [
            { name: "name", type: "string", description: "entity name", required: true },
            { name: "entityType", type: "string", description: "type of entity", required: true },
          ],
        },
      },
    ],
    requiredArgNames: ["entities"],
  };

  // array-of-strings tool (@modelcontextprotocol/server-memory open_nodes)
  const openNodes: ToolInfo = {
    name: "open_nodes",
    description: "Open specific nodes by their names",
    inputSchema: {},
    properties: [
      {
        name: "names",
        type: "array",
        required: true,
        items: { name: "(item)", type: "string", required: false },
      },
    ],
    requiredArgNames: ["names"],
  };

  it("plants payloads inside array-of-object required args (no top-level strings)", () => {
    const calls = planCalls(createEntities, "sql", ["' OR 1=1--"], 12);
    expect(calls.length).toBeGreaterThanOrEqual(1);
    const first = calls[0]!;
    expect(first.attacked).toEqual(["entities"]);
    expect(first.placement).toBe("entities[].name"); // "name" matches SQL hints
    const item = (first.args.entities as unknown[])[0] as Record<string, unknown>;
    expect(item.name).toBe("' OR 1=1--");
    expect(item.entityType).toBe("mcpveil"); // required sibling filled benignly
  });

  it("plants payloads inside array-of-string required args", () => {
    const calls = planCalls(openNodes, "path", ["../../canary.txt"], 12);
    expect(calls.length).toBe(1);
    expect(calls[0]!.placement).toBe("names[]");
    expect(calls[0]!.args.names).toEqual(["../../canary.txt"]);
  });

  it("returns [] for un-schema'd arrays rather than guessing", () => {
    const unknown: ToolInfo = {
      name: "op",
      description: "",
      inputSchema: {},
      properties: [{ name: "data", type: "array", required: true }],
      requiredArgNames: ["data"],
    };
    expect(planCalls(unknown, "path", ["../x"], 4)).toEqual([]);
  });

  it("fills required array args with one benign item (strict servers reject [])", () => {
    const mixed: ToolInfo = {
      name: "mixed",
      description: "",
      inputSchema: {},
      properties: [
        { name: "query", type: "string", required: true },
        {
          name: "tags",
          type: "array",
          required: true,
          items: { name: "(item)", type: "string", required: false },
        },
      ],
      requiredArgNames: ["query", "tags"],
    };
    const calls = planCalls(mixed, "sql", ["' OR 1=1--"], 12);
    expect(calls[0]!.args.query).toBe("' OR 1=1--");
    expect(calls[0]!.args.tags).toEqual(["mcpveil"]); // one benign item, not []
  });

  it("plants payloads inside object-typed args with nested strings", () => {
    const objTool: ToolInfo = {
      name: "create_filter",
      description: "",
      inputSchema: {},
      properties: [
        {
          name: "filter",
          type: "object",
          required: true,
          properties: [
            { name: "path", type: "string", required: true },
            { name: "label", type: "string", required: false },
          ],
        },
      ],
      requiredArgNames: ["filter"],
    };
    const calls = planCalls(objTool, "path", ["../canary.txt"], 8);
    expect(calls.length).toBeGreaterThanOrEqual(1);
    expect(calls[0]!.placement).toBe("filter.path");
    expect(calls[0]!.args.filter).toMatchObject({ path: "../canary.txt" });
  });
});
