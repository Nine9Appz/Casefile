import { z } from "zod";
import type { ToolDescriptor } from "./types.js";

export const McpFetcherInput = z.object({
  url: z.string().url(),
  method: z.enum(["GET", "POST"]).default("GET"),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.string().optional(),
  timeoutMs: z.number().int().min(100).max(30000).default(10000),
  maxBytes: z.number().int().min(1024).max(2_000_000).default(500_000),
});
export type McpFetcherInput = z.infer<typeof McpFetcherInput>;

export const McpFetcherOutput = z.object({
  url: z.string(),
  status: z.number().int(),
  ok: z.boolean(),
  contentType: z.string().nullable(),
  byteLength: z.number().int(),
  truncated: z.boolean(),
  body: z.string(),
  fetchedAt: z.string(),
  elapsedMs: z.number(),
});
export type McpFetcherOutput = z.infer<typeof McpFetcherOutput>;

const PRIVATE_HOSTNAME_RE =
  /^(?:127\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|localhost$)/i;

function isPrivateOrInvalidHost(hostname: string): string | null {
  const lower = hostname.toLowerCase();
  // IPv6 literals — URL strips brackets so we get bare ::1 / fe80:: / fc00:: forms
  if (lower.includes(":")) {
    if (lower === "::1" || lower === "::" || lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd")) {
      return `IPv6 loopback/private/link-local '${hostname}'`;
    }
  }
  // Decimal-encoded IPv4 (e.g. 2130706433 == 127.0.0.1)
  if (/^\d+$/.test(lower)) {
    const n = Number(lower);
    if (Number.isFinite(n) && n >= 0 && n <= 0xffffffff) {
      const octets = [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join(".");
      if (PRIVATE_HOSTNAME_RE.test(octets + ".")) {
        return `decimal-encoded private/loopback IP '${hostname}' -> ${octets}`;
      }
      return `numeric-encoded IPv4 host '${hostname}' is not allowed`;
    }
  }
  // Hex-encoded IPv4 (e.g. 0x7f000001)
  if (/^0x[0-9a-f]+$/i.test(lower)) {
    return `hex-encoded IPv4 host '${hostname}' is not allowed`;
  }
  if (PRIVATE_HOSTNAME_RE.test(lower)) {
    return `private/loopback host '${hostname}'`;
  }
  return null;
}

export const mcpFetcher: ToolDescriptor<typeof McpFetcherInput, typeof McpFetcherOutput> = {
  name: "mcpFetcher",
  description:
    "Fetches an external HTTP(S) URL and returns the response body as text along with status code, content-type, and byte length. Has a hard timeout and response-size cap. Refuses requests to private/loopback hostnames or IP literals (including decimal/hex-encoded IPv4 and IPv6 loopback/ULA/link-local forms) to prevent obvious SSRF. NOTE: hostname is not DNS-resolved, so a public DNS name pointing at an internal IP will not be blocked here. This is the only tool in the suite that touches the network.",
  inputSchema: McpFetcherInput,
  outputSchema: McpFetcherOutput,
  run: async ({ url, method, headers, body, timeoutMs, maxBytes }) => {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error(`Refusing non-http(s) scheme '${parsed.protocol}'`);
    }
    const reason = isPrivateOrInvalidHost(parsed.hostname);
    if (reason) {
      throw new Error(`Refusing to fetch ${reason} — SSRF protection`);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const startedAt = Date.now();
    try {
      const res = await fetch(url, {
        method,
        headers: headers ?? {},
        body: method === "POST" ? body : undefined,
        signal: controller.signal,
      });
      const buf = new Uint8Array(await res.arrayBuffer());
      const truncated = buf.byteLength > maxBytes;
      const slice = truncated ? buf.subarray(0, maxBytes) : buf;
      const text = new TextDecoder("utf-8", { fatal: false }).decode(slice);
      return {
        url,
        status: res.status,
        ok: res.ok,
        contentType: res.headers.get("content-type"),
        byteLength: buf.byteLength,
        truncated,
        body: text,
        fetchedAt: new Date(startedAt).toISOString(),
        elapsedMs: Date.now() - startedAt,
      };
    } finally {
      clearTimeout(timer);
    }
  },
};
