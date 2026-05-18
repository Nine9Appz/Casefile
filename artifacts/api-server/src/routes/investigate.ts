import { runInvestigation } from "@workspace/sift-agent";
import { db, casesTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { Router, type IRouter } from "express";

const router: IRouter = Router();

router.post("/cases/:caseId/investigate", async (req, res) => {
  const { caseId } = req.params;

  // Preflight: the OpenAPI spec advertises 404 for unknown cases, so the
  // existence check must happen BEFORE we flip the response into SSE mode.
  // Once we've sent SSE headers we can no longer return a JSON 404.
  const [caseRow] = await db
    .select({ id: casesTable.id })
    .from(casesTable)
    .where(eq(casesTable.id, caseId));
  if (!caseRow) {
    res.status(404).json({
      error: "not_found",
      message: `Case ${caseId} not found`,
    });
    return;
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();

  let cancelled = false;
  req.on("close", () => {
    cancelled = true;
  });

  const send = (event: string, data: unknown) => {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  try {
    for await (const ev of runInvestigation({
      caseId,
      isCancelled: () => cancelled,
    })) {
      send(ev.type, ev);
      if (cancelled) break;
    }
  } catch (err) {
    req.log.error({ err, caseId }, "investigation stream crashed");
    send("error", {
      type: "error",
      message: err instanceof Error ? err.message : String(err),
      fatal: true,
    });
    send("done", { type: "done", reason: "error" });
  } finally {
    res.end();
  }
});

export default router;
