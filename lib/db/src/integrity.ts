import { createHash } from "node:crypto";
import { eq } from "drizzle-orm";
import { db } from "./index.js";
import { caseArtifactsTable, type CaseArtifact } from "./schema/case-artifacts.js";

export class ArtifactNotFoundError extends Error {
  readonly code = "artifact_not_found";
  constructor(public artifactId: string) {
    super(`Artifact ${artifactId} not found`);
    this.name = "ArtifactNotFoundError";
  }
}

export class ArtifactIntegrityError extends Error {
  readonly code = "artifact_integrity_violation";
  constructor(
    public artifactId: string,
    public storedHash: string,
    public computedHash: string,
  ) {
    super(
      `Integrity violation on artifact ${artifactId}: stored hash ${storedHash} ` +
        `does not match recomputed hash ${computedHash}. Evidence may have been tampered with.`,
    );
    this.name = "ArtifactIntegrityError";
  }
}

export interface VerifiedArtifact {
  artifact: CaseArtifact;
  verifiedAt: Date;
  verifiedHash: string;
  /**
   * Raw artifact bytes. For text artifacts this is the UTF-8 encoding of
   * `artifact.content`; for base64 artifacts it is the decoded payload.
   * Binary-consuming tools should use this rather than `artifact.content`.
   */
  bytes: Buffer;
}

/**
 * Loads an artifact and verifies its SHA-256 matches the stored hash.
 * This is the ONLY function the rest of the codebase should use to read
 * artifact content. It is the second line of defense (after the database
 * triggers) against silent corruption or tampering.
 *
 * The stored SHA-256 is always taken over the raw artifact bytes:
 *   - text: UTF-8 encoding of `content`
 *   - base64: the decoded byte payload
 * which means the hash matches what a user would compute over the source
 * file with `sha256sum`, regardless of how the bytes ended up in the DB.
 */
export async function loadVerifiedArtifact(
  artifactId: string,
): Promise<VerifiedArtifact> {
  const [row] = await db
    .select()
    .from(caseArtifactsTable)
    .where(eq(caseArtifactsTable.id, artifactId));
  if (!row) {
    throw new ArtifactNotFoundError(artifactId);
  }
  const bytes =
    row.contentEncoding === "base64"
      ? Buffer.from(row.content, "base64")
      : Buffer.from(row.content, "utf8");
  const computed = createHash("sha256").update(bytes).digest("hex");
  if (computed !== row.sha256Hash) {
    throw new ArtifactIntegrityError(artifactId, row.sha256Hash, computed);
  }
  return { artifact: row, verifiedAt: new Date(), verifiedHash: computed, bytes };
}
