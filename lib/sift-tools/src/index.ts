import type { AnyToolDescriptor, ToolDescriptor, ToolResult } from "./types.js";
import { err, ok } from "./types.js";
import { logParser } from "./logParser.js";
import { iocExtractor } from "./iocExtractor.js";
import { timeline } from "./timeline.js";
import { network } from "./network.js";
import { entropy } from "./entropy.js";
import { mcpFetcher } from "./mcp.js";
import { diskImage } from "./diskImage.js";

export * from "./types.js";
export * from "./logParser.js";
export * from "./iocExtractor.js";
export * from "./timeline.js";
export * from "./network.js";
export * from "./entropy.js";
export * from "./mcp.js";
export * from "./diskImage.js";

export const TOOL_REGISTRY = {
  logParser,
  iocExtractor,
  timelineBuilder: timeline,
  networkAnalyzer: network,
  entropyScanner: entropy,
  mcpFetcher,
  diskImageAnalyzer: diskImage,
} as const;

export type ToolName = keyof typeof TOOL_REGISTRY;

export interface ToolDescriptorSummary {
  name: string;
  description: string;
  inputSchemaJson: unknown;
  outputSchemaJson: unknown;
}

export function listTools(): ToolDescriptorSummary[] {
  return Object.values(TOOL_REGISTRY).map((t) => {
    const tool = t as AnyToolDescriptor;
    return {
      name: tool.name,
      description: tool.description,
      inputSchemaJson: schemaShape(tool.inputSchema),
      outputSchemaJson: schemaShape(tool.outputSchema),
    };
  });
}

function schemaShape(schema: unknown): unknown {
  const s = schema as { _def?: { typeName?: string }; shape?: () => unknown };
  if (s?._def?.typeName === "ZodObject" && typeof s.shape === "function") {
    const shape = s.shape();
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(shape as Record<string, unknown>)) {
      const inner = v as { _def?: { typeName?: string } };
      out[k] = inner?._def?.typeName ?? "Unknown";
    }
    return out;
  }
  return s?._def?.typeName ?? "Unknown";
}

export async function invokeTool<N extends ToolName>(
  name: N,
  rawInput: unknown,
): Promise<ToolResult<unknown>> {
  const descriptor = TOOL_REGISTRY[name] as AnyToolDescriptor | undefined;
  if (!descriptor) return err(`Unknown tool '${String(name)}'`);

  const parsedInput = descriptor.inputSchema.safeParse(rawInput);
  if (!parsedInput.success) {
    return err(`Input validation failed: ${parsedInput.error.message}`);
  }
  let output: unknown;
  try {
    output = await descriptor.run(parsedInput.data);
  } catch (e) {
    return err(e instanceof Error ? e.message : String(e));
  }
  const parsedOutput = descriptor.outputSchema.safeParse(output);
  if (!parsedOutput.success) {
    return err(`Output validation failed: ${parsedOutput.error.message}`);
  }
  return ok(parsedOutput.data);
}

export type { ToolDescriptor };
