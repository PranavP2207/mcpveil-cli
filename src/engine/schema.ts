import type { ToolSchemaProperty } from "../types.js";
import { FORMAT_VALUES, formatLiteral } from "./argPlanner.js";

type Schema = Record<string, any>;
/** Deliberately bounded subset of JSON Schema; no untrusted regular expressions. */
export function parseSchema(root: Schema): { properties: ToolSchemaProperty[]; limitations: string[] } {
  const limitations = new Set<string>();
  let nodes = 0;
  const parse = (name: string, raw: unknown, required: boolean, depth: number, refs: string[]): ToolSchemaProperty => {
    const stop = (why: string): ToolSchemaProperty => { limitations.add(why); return { name, type: "unknown", required }; };
    if (++nodes > 512 || depth > 12) return stop("schema exceeds depth 12 or node count 512");
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return stop("boolean or invalid schema is unsupported");
    let def = raw as Schema;
    if (def.$ref) {
      const ref = String(def.$ref);
      if (!ref.startsWith("#/") || refs.includes(ref)) return stop("external or recursive schema references are unsupported");
      let resolved: any = root;
      for (const key of ref.slice(2).split("/")) {
        const decoded = key.replace(/~1/g, "/").replace(/~0/g, "~");
        resolved = resolved && Object.hasOwn(resolved, decoded) ? resolved[decoded] : undefined;
      }
      if (!resolved) return stop("unresolved local schema reference");
      return parse(name, { ...resolved, ...Object.fromEntries(Object.entries(def).filter(([k]) => k !== "$ref")) }, required, depth + 1, [...refs, ref]);
    }
    if (def.anyOf || def.oneOf) {
      const variants = def.anyOf ?? def.oneOf;
      if (!Array.isArray(variants) || variants.length > 8) return stop("schema alternatives exceed bounded support");
      const branch = variants.find((v: any) => v?.type !== "null");
      if (!branch) return stop("schema has no supported non-null alternative");
      if (variants.filter((v: any) => v?.type !== "null").length > 1) limitations.add("only the first non-null schema alternative is probed");
      return parse(name, { ...Object.fromEntries(Object.entries(def).filter(([k]) => !["oneOf", "anyOf"].includes(k))), ...branch }, required, depth + 1, refs);
    }
    for (const key of ["allOf", "not", "if", "then", "else", "pattern", "patternProperties", "dependentSchemas", "prefixItems", "contains", "unevaluatedProperties", "multipleOf", "exclusiveMinimum", "exclusiveMaximum", "minProperties", "maxProperties", "uniqueItems"])
      if (def[key] !== undefined) limitations.add(`unsupported schema constraint: ${key}`);
    let type = def.type ?? (def.properties ? "object" : def.enum?.length ? typeof def.enum[0] : typeof def.const);
    if (Array.isArray(type)) {
      const supported = type.filter((t: string) => t !== "null");
      if (supported.length !== 1) limitations.add("only the first non-null type alternative is probed");
      type = supported[0] ?? "unknown";
    }
    if (!["object", "array", "string", "integer", "number", "boolean", "null"].includes(type)) limitations.add("unsupported or unspecified schema type");
    const p: ToolSchemaProperty = { name, type, required, description: typeof def.description === "string" ? def.description : undefined };
    if (def.format !== undefined) {
      if (type === "string" && typeof def.format === "string") {
        p.format = def.format;
        if (FORMAT_VALUES[def.format] === undefined) limitations.add(`unsupported string format: ${def.format}`);
      } else limitations.add("unsupported schema constraint: format");
    }
    if (Array.isArray(def.enum)) p.enum = def.enum.slice(0, 32);
    if (Object.hasOwn(def, "const")) p.constValue = def.const;
    for (const key of ["minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems"] as const)
      if (Number.isFinite(def[key])) p[key] = def[key];
    if (p.format && FORMAT_VALUES[p.format] !== undefined && p.constValue === undefined && !p.enum?.length
      && formatLiteral(p) === undefined) limitations.add(`format literal cannot satisfy string length bounds: ${p.format}`);
    if ((p.minLength ?? 0) > 4096 || (p.minItems ?? 0) > 8) limitations.add("schema filler size exceeds safety limit");
    if (type === "object") {
      const req = new Set(Array.isArray(def.required) ? def.required : []);
      const entries = Object.entries(def.properties ?? {});
      if (entries.length > 128) limitations.add("object exceeds 128 properties");
      p.properties = entries.slice(0, 128).map(([k, v]) => parse(k, v, req.has(k), depth + 1, refs));
      if (!entries.length && def.additionalProperties && typeof def.additionalProperties === "object") limitations.add("dynamic additionalProperties are unsupported");
    }
    if (type === "array" && def.items) p.items = parse("(item)", def.items, false, depth + 1, refs);
    return p;
  };
  const outer = parse("(root)", root, true, 0, []);
  return { properties: outer.properties ?? [], limitations: [...limitations] };
}

export function flattenProperties(properties: ToolSchemaProperty[]): ToolSchemaProperty[] {
  return properties.flatMap((p) => [p, ...flattenProperties(p.properties ?? []), ...(p.items ? flattenProperties([p.items]) : [])]);
}
