import type { ToolInfo, ToolSchemaProperty } from "../types.js";

export type ArgIntent = "path" | "url" | "command" | "sql" | "neutral";

const PATH_HINTS = /\b(path|file|filename|filepath|dir|directory|folder|read|open|load|doc|document|template|include|import)\b/i;
const URL_HINTS = /\b(url|uri|link|endpoint|host|hostname|domain|fetch|download|target|base_?url)\b/i;
const CMD_HINTS = /\b(cmd|command|exec|execute|shell|sh\b|bash|run|script|spawn|eval|program|binary)\b/i;
const SQL_HINTS = /\b(query|sql|search|filter|where|select|find|lookup|user|username|email|name|q\b|term|keyword)\b/i;

export function classifyArg(p: ToolSchemaProperty): ArgIntent {
  const hay = `${p.name} ${p.description ?? ""}`;
  if (CMD_HINTS.test(hay)) return "command";
  if (URL_HINTS.test(hay)) return "url";
  if (PATH_HINTS.test(hay)) return "path";
  if (SQL_HINTS.test(hay)) return "sql";
  return "neutral";
}

/**
 * Valid literals for the `format` hints we can satisfy. Servers validate
 * formats (e.g. date or uri), and a padded filler would be rejected before a
 * payload is ever evaluated. Unknown formats keep the padded default and are
 * surfaced as schema limitations.
 */
export const FORMAT_VALUES: Record<string, string> = {
  "date": "2026-01-01",
  "date-time": "2026-01-01T00:00:00Z",
  "time": "00:00:00Z",
  "email": "mcpveil@example.com",
  "uri": "https://mcpveil.example",
  "url": "https://mcpveil.example",
  "uuid": "00000000-0000-4000-8000-000000000000",
  "ipv4": "127.0.0.1",
  "ipv6": "::1",
  "hostname": "mcpveil.example",
  "duration": "P1D",
  "byte": "bWNwdmVpbA==",
  "regex": "^mcpveil$",
  "json-pointer": "/a",
  "uri-reference": "/report",
  "uri-template": "/items/{id}",
  "idn-email": "mcpveil@example.com",
  "iri": "https://mcpveil.example",
};

/** Required sibling fillers are bounded; constraints outside this subset are reported. */
export function benignValue(p: ToolSchemaProperty): unknown {
  if (p.constValue !== undefined) return p.constValue;
  if (p.enum?.length) return p.enum[0];
  switch (p.type) {
    case "number": case "integer": return Math.min(p.maximum ?? Infinity, Math.max(p.minimum ?? -Infinity, 1));
    case "boolean": return false;
    case "array": return p.items ? Array.from({ length: Math.min(8, p.maxItems ?? Infinity, Math.max(1, p.minItems ?? 0)) }, () => benignValue(p.items!)) : [];
    case "object": return Object.fromEntries((p.properties ?? []).filter((n) => n.required).map((n) => [n.name, benignValue(n)]));
    case "string":
      if (p.format && FORMAT_VALUES[p.format] !== undefined) return FORMAT_VALUES[p.format]!;
      return "mcpveil".padEnd(Math.min(4096, p.minLength ?? 0), "x").slice(0, p.maxLength ?? Infinity);
    default: return null;
  }
}
export interface PlannedCall {
  tool: ToolInfo; args: Record<string, unknown>; attacked: string[]; intent: ArgIntent;
  placement: string;
  /** Exact leaf payload, including for nested arrays/objects. */
  value: string;
}
interface Placement { path: string; leaf: ToolSchemaProperty; build: (value: string) => unknown }
function placements(p: ToolSchemaProperty, depth = 0): Placement[] {
  if (depth > 12) return [];
  if (p.type === "string" && !p.enum && p.constValue === undefined)
    return [{ path: "", leaf: p, build: (value) => value }];
  if (p.type === "array" && p.items && p.maxItems !== 0)
    return placements(p.items, depth + 1).map((child) => ({ ...child, path: "[]" + child.path,
      build: (value) => [child.build(value), ...Array.from({ length: Math.min(7, Math.max(0, (p.minItems ?? 1) - 1)) }, () => benignValue(p.items!))] }));
  if (p.type === "object") return (p.properties ?? []).flatMap((field) => placements(field, depth + 1).map((child) => ({
    ...child, path: `.${field.name}${child.path}`,
    build: (value: string) => Object.fromEntries((p.properties ?? []).filter((n) => n.name === field.name || n.required)
      .map((n) => [n.name, n.name === field.name ? child.build(value) : benignValue(n)])),
  })));
  return [];
}
export function planCalls(tool: ToolInfo, intent: ArgIntent, payloadValues: string[], maxCalls: number): PlannedCall[] {
  const targets = tool.properties.flatMap((p) => placements(p).map((child) => ({ ...child, root: p, path: p.name + child.path })))
    .sort((a, b) => rank(classifyArg(b.leaf), intent) - rank(classifyArg(a.leaf), intent)).slice(0, 2);
  const calls: PlannedCall[] = [];
  for (const target of targets) for (const value of payloadValues) {
    if (calls.length >= maxCalls) return calls;
    if (value.length < (target.leaf.minLength ?? 0) || value.length > (target.leaf.maxLength ?? Infinity)) continue;
    // Optional siblings are omitted: servers reject unknown combinations
    // (e.g. head+tail), and a rejected probe tests nothing.
    const args = Object.fromEntries(tool.properties
      .filter((p) => p.name === target.root.name || p.required)
      .map((p) => [p.name, p.name === target.root.name ? target.build(value) : benignValue(p)]));
    calls.push({ tool, args, attacked: [target.root.name], intent, placement: target.path, value });
  }
  return calls;
}

function rank(actual: ArgIntent, wanted: ArgIntent): number {
  if (wanted === "neutral") return actual === "neutral" ? 2 : 1;
  return actual === wanted ? 3 : actual === "neutral" ? 1 : 0;
}
