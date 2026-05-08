import { z } from "zod";
import type { ToolDescriptor } from "./types.js";

export const EntropyInput = z.object({
  content: z.string().min(1),
  minStringLength: z.number().int().min(2).max(64).default(6),
  maxStrings: z.number().int().min(1).max(500).default(50),
});
export type EntropyInput = z.infer<typeof EntropyInput>;

export const EntropyOutput = z.object({
  byteLength: z.number().int(),
  shannonEntropy: z.number(),
  entropyVerdict: z.enum(["plain_text", "structured", "compressed_or_encrypted", "high_random"]),
  suspectedEncoding: z.enum(["base64", "hex", "none"]),
  printableRatio: z.number(),
  extractedStrings: z.array(z.string()),
});
export type EntropyOutput = z.infer<typeof EntropyOutput>;

function shannon(content: string): number {
  const bytes = Buffer.from(content, "utf8");
  if (bytes.length === 0) return 0;
  const freq = new Array<number>(256).fill(0);
  for (const b of bytes) freq[b]++;
  let h = 0;
  for (const f of freq) {
    if (f === 0) continue;
    const p = f / bytes.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function verdict(h: number): EntropyOutput["entropyVerdict"] {
  if (h < 3.5) return "structured";
  if (h < 5) return "plain_text";
  if (h < 7.2) return "compressed_or_encrypted";
  return "high_random";
}

const BASE64_FULL = /^[A-Za-z0-9+/=\s]+$/;
const HEX_FULL = /^[A-Fa-f0-9\s]+$/;

function detectEncoding(content: string): EntropyOutput["suspectedEncoding"] {
  const trimmed = content.trim();
  if (trimmed.length >= 16 && BASE64_FULL.test(trimmed) && trimmed.replace(/\s/g, "").length % 4 === 0) {
    return "base64";
  }
  if (trimmed.length >= 16 && HEX_FULL.test(trimmed) && trimmed.replace(/\s/g, "").length % 2 === 0) {
    return "hex";
  }
  return "none";
}

function extractStrings(content: string, minLen: number, max: number): string[] {
  const re = new RegExp(`[\\x20-\\x7e]{${minLen},}`, "g");
  const matches = content.match(re) ?? [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const m of matches) {
    if (!seen.has(m)) {
      seen.add(m);
      out.push(m);
      if (out.length >= max) break;
    }
  }
  return out;
}

export const entropy: ToolDescriptor<typeof EntropyInput, typeof EntropyOutput> = {
  name: "entropyScanner",
  description:
    "Computes Shannon entropy of a text/blob, classifies it as plain text / structured / compressed-or-encrypted / high-random, detects whether the input looks like base64 or hex encoded data, and extracts printable ASCII strings of minimum length. Useful for spotting encoded payloads embedded in logs.",
  inputSchema: EntropyInput,
  outputSchema: EntropyOutput,
  run: ({ content, minStringLength, maxStrings }) => {
    const buf = Buffer.from(content, "utf8");
    const bytes = buf.byteLength;
    const h = shannon(content);
    let printable = 0;
    for (const b of buf) {
      if (b >= 0x20 && b <= 0x7e) printable++;
    }
    return {
      byteLength: bytes,
      shannonEntropy: Number(h.toFixed(4)),
      entropyVerdict: verdict(h),
      suspectedEncoding: detectEncoding(content),
      printableRatio: bytes === 0 ? 0 : Number((printable / bytes).toFixed(4)),
      extractedStrings: extractStrings(content, minStringLength, maxStrings),
    };
  },
};
