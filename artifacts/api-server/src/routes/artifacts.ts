import { caseArtifactsTable, db } from "@workspace/db";
import { eq } from "drizzle-orm";
import { Router, type IRouter } from "express";
import { NotFoundError } from "../lib/errors";

const router: IRouter = Router();

router.get("/artifacts/:artifactId", async (req, res) => {
  const { artifactId } = req.params;
  const [row] = await db
    .select()
    .from(caseArtifactsTable)
    .where(eq(caseArtifactsTable.id, artifactId));
  if (!row) {
    throw new NotFoundError(
      "artifact_not_found",
      `Artifact ${artifactId} not found`,
    );
  }
  res.json(row);
});

export default router;
