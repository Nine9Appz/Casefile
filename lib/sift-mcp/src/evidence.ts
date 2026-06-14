import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { z } from "zod";

/**
 * Evidence-passing contract (v1) between the Casefile agent and a SIFT MCP
 * server — either the local mock (`http.ts`) or a user's remote SIFT
 * Workstation (`reference/sift-workstation-server.mjs`).
 *
 * Two shapes, chosen by the agent per artifact:
 *
 *  - **Inline** — small text/JSON evidence travels in `content` (+ `sha256`),
 *    exactly as before. The server runs the tool on the bytes it was handed.
 *  - **Reference** — large *binary* evidence (disk/memory images, pcaps) is NOT
 *    inlined. The agent sends an `evidenceRef` { path, sha256, encoding,
 *    sizeBytes } and the server resolves the pre-staged file under its evidence
 *    root and re-verifies the SHA-256 *before* the tool runs. The transfer of
 *    the bytes onto the Workstation is the operator's responsibility (out of
 *    scope); this contract is how the agent points at them and how the server
 *    proves it is operating on the exact evidence the agent verified.
 *
 * The hash is always taken over the raw bytes (sha256sum-compatible), matching
 * how Casefile computes artifact hashes in `lib/db/src/integrity.ts`. Evidence
 * never reaches a tool — inline or by reference — without its integrity hash,
 * and a reference that fails to resolve or whose hash does not match fails
 * closed (the tool does not run).
 */

export const EVIDENCE_CONTRACT_VERSION = 1;

/**
 * Artifacts at or below this size are sent inline; larger *binary* artifacts are
 * sent by reference. Keeping the boundary here (not in each caller) means the
 * agent and the docs describe one number.
 */
export const EVIDENCE_INLINE_MAX_BYTES = 256 * 1024;

/**
 * Tools whose primary input is verified evidence content. These accept either an
 * inline `content` field or an `evidenceRef`. Shared so the agent (router) and
 * the mock server (resolver) agree on the same set.
 */
export const CONTENT_CONSUMING_TOOL_NAMES = [
  "logParser",
  "iocExtractor",
  "entropyScanner",
  "diskImageAnalyzer",
  "pcapAnalyzer",
] as const;

export const evidenceRefSchema = z.object({
  path: z
    .string()
    .min(1)
    .describe(
      "Path of the pre-staged evidence file, relative to the server's evidence root.",
    ),
  sha256: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/)
    .describe("Expected SHA-256 (hex) of the raw evidence bytes."),
  encoding: z
    .enum(["base64", "text"])
    .default("base64")
    .describe("How the server should materialize the verified bytes as content."),
  sizeBytes: z
    .number()
    .int()
    .nonnegative()
    .optional()
    .describe("Size of the evidence in bytes, for the audit log."),
});

export type EvidenceRef = z.infer<typeof evidenceRefSchema>;

/**
 * The agent's decision: inline vs reference. Reference mode is for large binary
 * artifacts only — small artifacts and any text/JSON stay inline so the existing
 * (and in-process) behavior is unchanged.
 */
export function shouldReferenceEvidence(args: {
  contentEncoding: "base64" | "text";
  sizeBytes: number;
}): boolean {
  return (
    args.contentEncoding === "base64" &&
    args.sizeBytes > EVIDENCE_INLINE_MAX_BYTES
  );
}

export type EvidenceVerificationCode =
  | "no_evidence_root"
  | "path_escape"
  | "not_found"
  | "hash_mismatch";

export class EvidenceVerificationError extends Error {
  readonly code: EvidenceVerificationCode;
  constructor(code: EvidenceVerificationCode, message: string) {
    super(message);
    this.code = code;
    this.name = "EvidenceVerificationError";
  }
}

/**
 * Resolve an evidence reference under `evidenceRoot` and verify its SHA-256.
 * Fails closed: throws if no root is configured, the path escapes the root, the
 * file is missing, or the hash does not match. Returns the verified bytes so the
 * caller can feed them to the tool.
 */
export async function resolveAndVerifyEvidence(
  ref: EvidenceRef,
  evidenceRoot: string | null | undefined,
): Promise<Buffer> {
  if (!evidenceRoot) {
    throw new EvidenceVerificationError(
      "no_evidence_root",
      "server received an evidenceRef but has no evidence root configured (set SIFT_MCP_EVIDENCE_ROOT)",
    );
  }
  const root = resolve(evidenceRoot);
  const full = resolve(root, ref.path);
  if (full !== root && !full.startsWith(root + sep)) {
    throw new EvidenceVerificationError(
      "path_escape",
      `evidence path '${ref.path}' escapes the evidence root`,
    );
  }
  let bytes: Buffer;
  try {
    bytes = await readFile(full);
  } catch {
    throw new EvidenceVerificationError(
      "not_found",
      `pre-staged evidence not found at '${ref.path}'`,
    );
  }
  const computed = createHash("sha256").update(bytes).digest("hex");
  if (computed.toLowerCase() !== ref.sha256.toLowerCase()) {
    throw new EvidenceVerificationError(
      "hash_mismatch",
      `sha256 mismatch for '${ref.path}': expected ${ref.sha256}, recomputed ${computed}`,
    );
  }
  return bytes;
}
