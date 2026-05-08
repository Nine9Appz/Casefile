import { analysisStepsTable, db, executionLogsTable } from "@workspace/db";
import { asc, eq } from "drizzle-orm";
import { Router, type IRouter } from "express";
import { NotFoundError } from "../lib/errors";

const router: IRouter = Router();

router.get("/steps/:stepId/logs", async (req, res) => {
  const { stepId } = req.params;
  const [parent] = await db
    .select({ id: analysisStepsTable.id })
    .from(analysisStepsTable)
    .where(eq(analysisStepsTable.id, stepId));
  if (!parent) {
    throw new NotFoundError("step_not_found", `Analysis step ${stepId} not found`);
  }

  const rows = await db
    .select()
    .from(executionLogsTable)
    .where(eq(executionLogsTable.analysisStepId, stepId))
    .orderBy(asc(executionLogsTable.startedAt));

  res.json(rows);
});

export default router;
