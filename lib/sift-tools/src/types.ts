import type { z } from "zod";

export type ToolOk<T> = { ok: true; data: T };
export type ToolErr = { ok: false; error: string };
export type ToolResult<T> = ToolOk<T> | ToolErr;

export interface ToolDescriptor<
  InSchema extends z.ZodTypeAny = z.ZodTypeAny,
  OutSchema extends z.ZodTypeAny = z.ZodTypeAny,
> {
  name: string;
  description: string;
  inputSchema: InSchema;
  outputSchema: OutSchema;
  run: (input: z.output<InSchema>) => Promise<z.input<OutSchema>> | z.input<OutSchema>;
}

export type AnyToolDescriptor = ToolDescriptor;

export function ok<T>(data: T): ToolOk<T> {
  return { ok: true, data };
}

export function err(message: string): ToolErr {
  return { ok: false, error: message };
}
